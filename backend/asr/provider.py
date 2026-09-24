"""
Swappable speech-to-text provider. (brief Section 5, M7)

Three tiers, degrading gracefully. Only the first needs credentials:

  1. Tencent Cloud ASR   server-side, the judged "use of AI tools" path
  2. Web Speech API      in the browser, free, no keys, no backend
  3. Text input          always works — the demo floor

Tier 1 is selected only when Tencent credentials exist. With none configured
(the current state), /api/transcribe reports 503 + {"fallback": "webspeech"}
and the browser drops to tier 2 without the user noticing anything but a
different engine.

CRITICAL: SecretId/SecretKey must never reach the browser, so tier 1 is
necessarily browser -> our backend -> Tencent. That extra hop is why tier 2
exists at all: it is lower-latency as well as key-free.
"""
from __future__ import annotations

from typing import Protocol

from backend.asr.errors import ASRUnavailable


class ASRProvider(Protocol):
    """One method: audio bytes in, transcript out."""
    name: str

    def transcribe(self, audio: bytes, *, fmt: str) -> str: ...


class UnavailableASR:
    """The no-credentials provider. Says so honestly instead of pretending.

    It does NOT return an empty string or a canned transcript: a silent empty
    result would look like the user said nothing, and a canned one would look
    like recognition working while nothing ran.
    """
    name = "unavailable"

    def transcribe(self, audio: bytes, *, fmt: str) -> str:
        raise ASRUnavailable(
            "no Tencent credentials configured; use the browser's Web Speech API "
            "or type the transcript"
        )


def get_asr_provider(settings) -> ASRProvider:
    """Tencent when credentials exist, else the honest unavailable provider."""
    if getattr(settings, "has_credentials", False):
        from backend.asr.tencent import TencentASRProvider  # local: keep stub mode SDK-light
        return TencentASRProvider(settings)
    return UnavailableASR()
