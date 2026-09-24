"""
Swappable speech-to-text provider. (brief Section 5, M7)

Three tiers, degrading gracefully. Only the first needs credentials:

  1. Server-side ASR     OpenAI transcription or Tencent Cloud ASR
  2. Web Speech API      in the browser, free, no keys, no backend
  3. Text input          always works — the demo floor

Tier 1 is selected by ASR_PROVIDER ("openai" | "tencent" | "none" | "auto").
"auto" (the default) takes Tencent when its credential pair exists, else
OpenAI when OPENAI_API_KEY exists — the same key the LLM uses — else nothing.
With no provider, /api/transcribe reports 503 + {"fallback": "webspeech"} and
the browser drops to tier 2 without the user noticing anything but a different
engine.

CRITICAL: API keys must never reach the browser, so tier 1 is necessarily
browser -> our backend -> provider. That extra hop is why tier 2 exists at all:
it is lower-latency as well as key-free.

Each provider declares the containers IT accepts. They differ in the way that
matters most: OpenAI takes webm — what Chrome's MediaRecorder produces by
default — and Tencent does not.
"""
from __future__ import annotations

from typing import Protocol

from backend.asr.errors import ASRUnavailable

# Containers Tencent SentenceRecognition documents — TencentASRProvider.formats,
# and the list UnavailableASR reports (so a no-provider box refuses the same
# containers it always has). Enforced on OUR side before a byte leaves the
# building, for the same reason the LLM's output is validated here
# rather than trusted: a caller-supplied `fmt` otherwise goes straight into a
# paid upstream request as VoiceFormat.
#
# webm is NOT on this list, and that matters: Chrome's MediaRecorder produces
# audio/webm;codecs=opus, which shares a codec but not a container with the
# documented ogg-opus. The browser asks for a documented container where it can
# and tells us what it actually recorded; when it can only give webm we say so
# and it drops to the Web Speech tier, which is the designed degradation rather
# than a failed upstream call.
SUPPORTED_VOICE_FORMATS = frozenset(
    {"wav", "pcm", "mp3", "m4a", "aac", "ogg-opus", "speex", "silk"}
)

# Tencent's SentenceRecognition limit: <=60s and <=5MB per request. Enforced
# before reading the upload into memory, so an oversized body is refused rather
# than buffered. OpenAI allows 25MB, but the cap stays provider-independent:
# 5MB is minutes of compressed speech, far beyond any voice command, and
# memory safety should not depend on which provider is configured.
MAX_AUDIO_BYTES = 5 * 1024 * 1024


class ASRProvider(Protocol):
    """One method: audio bytes in, transcript out."""
    name: str
    formats: frozenset[str]     # containers this provider accepts, checked before upload

    def transcribe(self, audio: bytes, *, fmt: str) -> str: ...


class UnknownASRProvider(ValueError):
    """ASR_PROVIDER named a provider that does not exist."""


class UnavailableASR:
    """The no-credentials provider. Says so honestly instead of pretending.

    It does NOT return an empty string or a canned transcript: a silent empty
    result would look like the user said nothing, and a canned one would look
    like recognition working while nothing ran.
    """
    name = "unavailable"
    formats = SUPPORTED_VOICE_FORMATS

    def transcribe(self, audio: bytes, *, fmt: str) -> str:
        raise ASRUnavailable(
            "no speech-to-text provider configured (set OPENAI_API_KEY or Tencent "
            "credentials); use the browser's Web Speech API or type the transcript"
        )


def get_asr_provider(settings) -> ASRProvider:
    """Explicit ASR_PROVIDER if set, else whichever provider has credentials."""
    choice = (getattr(settings, "asr_provider", "") or "auto").strip().lower()

    if choice == "none":
        return UnavailableASR()
    if choice == "openai":
        from backend.asr.openai_asr import OpenAIASRProvider
        return OpenAIASRProvider(settings)
    if choice == "tencent":
        from backend.asr.tencent import TencentASRProvider   # local: keep stub mode SDK-light
        return TencentASRProvider(settings)
    if choice != "auto":
        raise UnknownASRProvider(
            f"ASR_PROVIDER={choice!r} is not a provider "
            f"(expected 'openai', 'tencent', 'none' or 'auto')"
        )

    if getattr(settings, "has_credentials", False):
        from backend.asr.tencent import TencentASRProvider
        return TencentASRProvider(settings)
    if getattr(settings, "openai_api_key", ""):
        from backend.asr.openai_asr import OpenAIASRProvider
        return OpenAIASRProvider(settings)
    return UnavailableASR()
