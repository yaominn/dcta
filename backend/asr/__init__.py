"""
Speech-to-text. (M7)

Three tiers: server-side ASR (OpenAI or Tencent, needs a key), the browser's
Web Speech API (free, no keys), and text input (always works). See
backend.asr.provider for why the first tier must go through our backend.
"""
from backend.asr.errors import ASRNoSpeech, ASRUnavailable
from backend.asr.provider import (
    MAX_AUDIO_BYTES,
    SUPPORTED_VOICE_FORMATS,
    ASRProvider,
    UnavailableASR,
    UnknownASRProvider,
    get_asr_provider,
)

__all__ = ["ASRNoSpeech", "ASRUnavailable", "ASRProvider", "UnavailableASR", "UnknownASRProvider",
           "get_asr_provider",
           "MAX_AUDIO_BYTES", "SUPPORTED_VOICE_FORMATS"]
