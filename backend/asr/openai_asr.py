"""
OpenAI speech-to-text — POST /v1/audio/transcriptions. (M7, tier 1)

Uses the same OPENAI_API_KEY as the LLM provider, so one key covers both the
voice and the parsing. Selected by ASR_PROVIDER=openai, or by "auto" when that
key exists and Tencent credentials do not.

Why this provider changes the voice experience, not just the vendor: it
accepts webm, which is what Chrome's MediaRecorder produces by default.
Tencent SentenceRecognition does not, so on Chrome the Tencent tier always
answered 415 and dropped the user to Web Speech. With this provider, Chrome
audio is transcribed server-side as recorded — no rewrap, no fallback.

Format is declared by the upload's filename extension, and OpenAI trusts it.
`fmt` arrives from the browser, which now reports what it ACTUALLY recorded
(frontend/voice.js), and is checked against `formats` in main.py before this
runs — a mislabelled container is refused on our side, never forwarded.

Every failure is ASRUnavailable, which main.py maps to 503 + fallback: the
browser drops to Web Speech and the user can still speak. A bad key or an
outage degrades the voice tier; it never blocks the product.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

from backend.asr.errors import ASRUnavailable

# Our VoiceFormat name -> (filename extension OpenAI keys on, MIME type).
# OpenAI documents flac, mp3, mp4, mpeg, mpga, m4a, ogg, wav and webm. Not
# listed: aac, pcm, speex, silk — Tencent formats OpenAI does not take.
_CONTAINERS = {
    "mp3":      ("mp3",  "audio/mpeg"),
    "m4a":      ("m4a",  "audio/mp4"),
    "wav":      ("wav",  "audio/wav"),
    "ogg-opus": ("ogg",  "audio/ogg"),
    "webm":     ("webm", "audio/webm"),
    "flac":     ("flac", "audio/flac"),
}


class OpenAIASRProvider:
    name = "openai"
    formats = frozenset(_CONTAINERS)

    def __init__(self, settings):
        self._api_key = settings.openai_api_key
        self._base_url = settings.openai_base_url.rstrip("/")
        self._model = settings.openai_asr_model
        self._language = settings.openai_asr_language
        self._timeout = settings.asr_timeout_s

    def transcribe(self, audio: bytes, *, fmt: str) -> str:
        if not self._api_key:
            raise ASRUnavailable(
                "OPENAI_API_KEY is not set — OpenAI speech-to-text cannot "
                "authenticate. Generate a key at "
                "https://platform.openai.com/api-keys and put it in .env."
            )
        if fmt not in _CONTAINERS:
            # main.py checks `formats` first, so this is defence in depth: a
            # direct caller must not be able to mislabel a container either.
            raise ASRUnavailable(f"unsupported audio container for OpenAI: {fmt!r}")
        ext, mime = _CONTAINERS[fmt]

        fields = {"model": self._model, "response_format": "json"}
        if self._language:
            # Short command-length clips are where language auto-detection
            # guesses wrong; pinning it is the cheapest accuracy win.
            fields["language"] = self._language
        body, content_type = _multipart(fields, ("file", f"utterance.{ext}", mime, audio))

        req = urllib.request.Request(
            f"{self._base_url}/audio/transcriptions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": content_type,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # Surface the body: "HTTP 400" alone does not say whether the key,
            # the model name or the audio is the problem.
            try:
                detail = exc.read().decode("utf-8", "replace")[:500]
            except Exception:
                detail = ""
            raise ASRUnavailable(
                f"OpenAI ASR request failed: HTTP {exc.code} {exc.reason}: {detail}"
            ) from exc
        except Exception as exc:        # timeout, DNS, TLS, malformed JSON
            raise ASRUnavailable(
                f"OpenAI ASR request failed: {type(exc).__name__}: {exc}"
            ) from exc

        text = (payload.get("text") or "").strip()
        if not text:
            # Distinguish "recognised nothing" from "call failed": silence is a
            # real outcome and must not be mistaken for an empty transcript.
            raise ASRUnavailable("OpenAI ASR returned no text (silence or unrecognised audio)")
        return text


def _multipart(fields: dict[str, str], file: tuple[str, str, str, bytes]) -> tuple[bytes, str]:
    """Encode a multipart/form-data body: text fields plus one file part."""
    boundary = uuid.uuid4().hex
    parts = []
    for key, value in fields.items():
        parts.append(
            f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'
            f"{value}\r\n".encode("utf-8")
        )
    field, filename, mime, data = file
    parts.append(
        f'--{boundary}\r\nContent-Disposition: form-data; name="{field}"; '
        f'filename="{filename}"\r\nContent-Type: {mime}\r\n\r\n'.encode("utf-8")
        + data + b"\r\n"
    )
    parts.append(f"--{boundary}--\r\n".encode("utf-8"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"
