"""
Speech-to-text. (M7)

Three tiers: Tencent Cloud ASR (server-side, needs credentials), the browser's
Web Speech API (free, no keys), and text input (always works). See
backend.asr.provider for why the first tier must go through our backend.
"""
from backend.asr.errors import ASRUnavailable
from backend.asr.provider import ASRProvider, UnavailableASR, get_asr_provider

__all__ = ["ASRUnavailable", "ASRProvider", "UnavailableASR", "get_asr_provider"]
