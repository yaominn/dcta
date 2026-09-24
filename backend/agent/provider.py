"""
Swappable LLM provider interface. (brief Section 8)

The parser talks to a LLMProvider — two methods' worth of surface — so the
model can be swapped without touching the pipeline. Hunyuan is preferred when
credentials exist; the deterministic stub is the fallback so local dev, CI and
the security test-suite never need network or keys.

Selection is config-driven ONLY (settings.has_credentials): no code edit to
swap, and credentials come from the environment via backend.config — never
hardcoded (brief Section 8 / README credentials section).
"""
from __future__ import annotations

from typing import Protocol

from backend.agent.stub import StubProvider


class LLMProvider(Protocol):
    """The whole interface: one chat completion, text in, text out."""
    name: str

    def complete(self, *, system: str, user: str) -> str: ...


def get_provider(settings) -> LLMProvider:
    """Hunyuan when real credentials are configured, else the stub."""
    if settings.has_credentials:
        from backend.agent.hunyuan import HunyuanProvider  # local import: stub mode stays SDK-light
        return HunyuanProvider(settings)
    return StubProvider()
