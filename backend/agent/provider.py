"""
Swappable LLM provider interface. (brief Section 8)

The parser talks to a LLMProvider — one method's worth of surface — so the
model can be swapped without touching the pipeline. The deterministic stub is
the fallback so local dev, CI and the security test-suite never need network
or keys.

Selection is config-driven ONLY: no code edit to swap, and credentials come
from the environment via backend.config — never hardcoded (brief Section 8 /
README credentials section).

LLM_PROVIDER pins a provider explicitly ("hunyuan" | "stub"). Unset, or
"auto", picks by whether Tencent credentials exist. Pinning "hunyuan" is
worth knowing about: it makes a missing or broken key fail LOUDLY instead of
silently falling back to the stub, which would look exactly like the model
working during a demo.
"""
from __future__ import annotations

from typing import Protocol

from backend.agent.stub import StubProvider


class LLMProvider(Protocol):
    """The whole interface: one chat completion, text in, text out."""
    name: str

    def complete(self, *, system: str, user: str) -> str: ...


class UnknownProvider(ValueError):
    """LLM_PROVIDER named a provider that does not exist."""


def get_provider(settings) -> LLMProvider:
    """Explicit LLM_PROVIDER if set, else Hunyuan when credentials exist."""
    choice = (getattr(settings, "llm_provider", "") or "auto").strip().lower()

    if choice == "stub":
        return StubProvider()
    if choice == "hunyuan":
        from backend.agent.hunyuan import HunyuanProvider  # local: stub mode stays SDK-light
        return HunyuanProvider(settings)
    if choice != "auto":
        raise UnknownProvider(
            f"LLM_PROVIDER={choice!r} is not a provider (expected 'hunyuan', 'stub' or 'auto')"
        )

    if settings.has_credentials:
        from backend.agent.hunyuan import HunyuanProvider
        return HunyuanProvider(settings)
    return StubProvider()
