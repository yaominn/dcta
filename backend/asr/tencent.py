"""
Tencent Cloud ASR — SentenceRecognition. (M0 spike: ap-singapore, English.)

UNEXERCISED. There are no Tencent credentials yet, so not one line of this has
run against the real service. It is written to the documented API shape and the
SDK's own model definitions, which were verified locally, but treat the first
live call as a test, not a formality.

Two things to check when credentials arrive:

  1. AUDIO CONTAINER. Chrome's MediaRecorder produces `audio/webm;codecs=opus`.
     SentenceRecognition documents wav / pcm / mp3 / m4a / aac / ogg-opus /
     speex / silk. webm-opus and ogg-opus share a codec but NOT a container, so
     webm may be rejected. `VOICE_FORMAT` is configurable for exactly this
     reason, and the browser prefers a documented container where it can. If
     this is the blocker, the fix is a server-side container rewrap, not a
     redesign — the Web Speech tier keeps the demo working meanwhile.
  2. EngSerViceType must match the spoken language ("16k_en" for English at
     16 kHz; "16k_zh" for Mandarin). Configurable via ASR_ENGINE.
"""
from __future__ import annotations

import base64

from backend.asr.errors import ASRUnavailable


class TencentASRProvider:
    name = "tencent"

    def __init__(self, settings):
        self._secret_id = settings.tencent_secret_id
        self._secret_key = settings.tencent_secret_key
        self._region = settings.asr_region
        self._engine = settings.asr_engine
        self._timeout = int(settings.asr_timeout_s)

    def transcribe(self, audio: bytes, *, fmt: str) -> str:
        try:
            from tencentcloud.common import credential
            from tencentcloud.common.profile.client_profile import ClientProfile
            from tencentcloud.common.profile.http_profile import HttpProfile
            from tencentcloud.asr.v20190614 import asr_client, models
        except ImportError as exc:  # pragma: no cover - live mode only
            raise ASRUnavailable(
                "tencentcloud-sdk-python is required for the Tencent ASR provider"
            ) from exc

        http_profile = HttpProfile(reqTimeout=self._timeout)
        client = asr_client.AsrClient(
            credential.Credential(self._secret_id, self._secret_key),
            self._region,
            ClientProfile(httpProfile=http_profile),
        )
        req = models.SentenceRecognitionRequest()
        req.EngSerViceType = self._engine
        req.SourceType = 1                        # 1 = audio carried in the request body
        req.VoiceFormat = fmt
        req.Data = base64.b64encode(audio).decode("ascii")
        req.DataLen = len(audio)

        try:
            resp = client.SentenceRecognition(req)
        except Exception as exc:                  # SDK + transport errors
            raise ASRUnavailable(
                f"Tencent ASR request failed: {type(exc).__name__}: {exc}"
            ) from exc

        text = (getattr(resp, "Result", None) or "").strip()
        if not text:
            # Distinguish "recognised nothing" from "call failed": an empty
            # result is a real outcome (silence, noise) and must not be mistaken
            # for a transcript.
            raise ASRUnavailable("Tencent ASR returned no text (silence or unrecognised audio)")
        return text
