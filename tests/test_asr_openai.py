"""
OpenAI speech-to-text: selection, per-provider formats, and the upload it sends.

What is pinned here:

1. Selection. ASR_PROVIDER pins a provider; "auto" takes Tencent when its pair
   exists, else OpenAI when OPENAI_API_KEY exists — the key the LLM already
   uses — else the honest unavailable provider.

2. Formats are per provider. OpenAI accepts webm (Chrome's MediaRecorder
   default); Tencent does not. The endpoint must check the ACTIVE provider's
   list: a global Tencent list would 415 every Chrome recording that OpenAI
   could have transcribed, and a global OpenAI list would forward webm to
   Tencent, which cannot read it.

3. Every failure is ASRUnavailable -> 503 + fallback, so a bad key or an
   outage drops the user to Web Speech instead of blocking them.

No network and no key: the HTTP call is stubbed at urllib.
"""
from __future__ import annotations

import io
import json
import urllib.error
import urllib.request

import pytest
from fastapi.testclient import TestClient

import backend.main as main
from backend.asr import (SUPPORTED_VOICE_FORMATS, ASRUnavailable, UnavailableASR,
                         UnknownASRProvider, get_asr_provider)
from backend.asr.openai_asr import OpenAIASRProvider


class _Settings:
    """Minimal stand-in for backend.config.Settings."""
    def __init__(self, *, openai_key="", tencent=False, asr="auto"):
        self.tencent_secret_id = "id" if tencent else ""
        self.tencent_secret_key = "key" if tencent else ""
        self.openai_api_key = openai_key
        self.openai_base_url = "https://api.openai.com/v1"
        self.openai_asr_model = "gpt-4o-mini-transcribe"
        self.openai_asr_language = "en"
        self.asr_provider = asr
        self.asr_region = "ap-singapore"
        self.asr_engine = "16k_en"
        self.asr_timeout_s = 20.0

    @property
    def has_credentials(self):
        return bool(self.tencent_secret_id and self.tencent_secret_key)


# --------------------------------------------------------------------------- selection
def test_auto_selects_openai_when_its_key_is_the_only_credential():
    assert get_asr_provider(_Settings(openai_key="sk-o")).name == "openai"


def test_auto_keeps_tencent_first_when_both_exist():
    """Unchanged behaviour for a teammate whose .env holds the Tencent pair."""
    assert get_asr_provider(_Settings(openai_key="sk-o", tencent=True)).name == "tencent"


def test_auto_with_no_credentials_is_unavailable():
    assert isinstance(get_asr_provider(_Settings()), UnavailableASR)


@pytest.mark.parametrize("pinned", ["openai", "tencent"])
def test_explicit_provider_overrides_credentials(pinned):
    assert get_asr_provider(_Settings(openai_key="sk-o", tencent=True, asr=pinned)).name == pinned


def test_none_disables_server_asr_even_with_keys():
    assert isinstance(get_asr_provider(_Settings(openai_key="sk-o", tencent=True, asr="none")),
                      UnavailableASR)


def test_unknown_provider_name_is_rejected():
    with pytest.raises(UnknownASRProvider):
        get_asr_provider(_Settings(asr="whisper"))


# --------------------------------------------------------------------------- formats
def test_openai_accepts_webm_and_tencent_does_not():
    """The reason this provider changes the Chrome experience at all."""
    assert "webm" in OpenAIASRProvider.formats
    assert "webm" not in SUPPORTED_VOICE_FORMATS


def test_openai_does_not_claim_tencent_only_containers():
    """Claiming a container upstream cannot read turns a clean 415 into a
    paid call that fails."""
    for fmt in ("aac", "pcm", "speex", "silk"):
        assert fmt not in OpenAIASRProvider.formats


class _FakeOpenAIASR:
    """Stands in for the live provider at the endpoint: OpenAI's formats, no network."""
    name = "openai"
    formats = OpenAIASRProvider.formats

    def __init__(self):
        self.calls = []

    def transcribe(self, audio, *, fmt):
        self.calls.append(fmt)
        return "pay mom fifty dollars"


def test_endpoint_forwards_chrome_webm_when_openai_is_active(monkeypatch):
    fake = _FakeOpenAIASR()
    monkeypatch.setattr(main, "get_asr_provider", lambda settings: fake)
    r = TestClient(main.app).post(
        "/api/transcribe?fmt=webm",
        files={"audio": ("utterance", b"\x1aE\xdf\xa3webm", "audio/webm")})
    assert r.status_code == 200
    assert r.json() == {"transcript": "pay mom fifty dollars", "provider": "openai"}
    assert fake.calls == ["webm"]


def test_endpoint_refuses_what_the_active_provider_cannot_read(monkeypatch):
    """aac is fine for Tencent, not for OpenAI: refused here, never forwarded."""
    fake = _FakeOpenAIASR()
    monkeypatch.setattr(main, "get_asr_provider", lambda settings: fake)
    r = TestClient(main.app).post(
        "/api/transcribe?fmt=aac",
        files={"audio": ("utterance", b"aac-bytes", "audio/aac")})
    assert r.status_code == 415
    assert r.json()["detail"]["fallback"] == "webspeech"
    assert "openai" in r.json()["detail"]["error"]
    assert fake.calls == []


# --------------------------------------------------------------------------- failure degrades
def test_missing_key_is_unavailable_and_names_the_variable():
    with pytest.raises(ASRUnavailable) as exc:
        OpenAIASRProvider(_Settings(asr="openai")).transcribe(b"audio", fmt="webm")
    assert "OPENAI_API_KEY" in str(exc.value)


def test_unsupported_container_is_refused_even_on_direct_call():
    with pytest.raises(ASRUnavailable):
        OpenAIASRProvider(_Settings(openai_key="sk-o")).transcribe(b"audio", fmt="silk")


def test_http_error_surfaces_the_body(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 400, "Bad Request", {},
                                     io.BytesIO(b'{"error":{"message":"Invalid file format"}}'))
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ASRUnavailable) as exc:
        OpenAIASRProvider(_Settings(openai_key="sk-o")).transcribe(b"audio", fmt="webm")
    assert "400" in str(exc.value) and "Invalid file format" in str(exc.value)


def test_transport_failure_is_unavailable(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with pytest.raises(ASRUnavailable):
        OpenAIASRProvider(_Settings(openai_key="sk-o")).transcribe(b"audio", fmt="webm")


# --------------------------------------------------------------------------- the upload
class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def upload(monkeypatch):
    seen = {}

    def _install(payload):
        def fake_urlopen(req, timeout=None):
            seen["request"], seen["timeout"] = req, timeout
            return _FakeResponse(payload)
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        return seen
    return _install


def test_upload_is_multipart_with_model_language_and_a_typed_filename(upload):
    seen = upload({"text": "  pay mom fifty dollars  "})
    out = OpenAIASRProvider(_Settings(openai_key="sk-o")).transcribe(b"OGGDATA", fmt="ogg-opus")

    assert out == "pay mom fifty dollars"                 # stripped
    req = seen["request"]
    assert req.full_url == "https://api.openai.com/v1/audio/transcriptions"
    assert req.get_header("Authorization") == "Bearer sk-o"
    assert req.get_header("Content-type").startswith("multipart/form-data; boundary=")
    body = req.data
    assert b'name="model"\r\n\r\ngpt-4o-mini-transcribe\r\n' in body
    assert b'name="language"\r\n\r\nen\r\n' in body
    assert b'name="response_format"\r\n\r\njson\r\n' in body
    # OpenAI keys the format on the extension: ogg-opus must travel as .ogg.
    assert b'filename="utterance.ogg"' in body
    assert b"Content-Type: audio/ogg" in body
    assert b"OGGDATA" in body
    assert seen["timeout"] == 20.0


def test_empty_language_lets_the_model_detect(upload):
    seen = upload({"text": "hello"})
    s = _Settings(openai_key="sk-o")
    s.openai_asr_language = ""
    OpenAIASRProvider(s).transcribe(b"x", fmt="wav")
    assert b'name="language"' not in seen["request"].data


def test_silence_is_not_mistaken_for_a_transcript(upload):
    upload({"text": "   "})
    with pytest.raises(ASRUnavailable):
        OpenAIASRProvider(_Settings(openai_key="sk-o")).transcribe(b"x", fmt="wav")
