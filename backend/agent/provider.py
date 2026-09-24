"""
Swappable LLM provider interface. (brief Section 8)

The parser talks to a LLMProvider — two methods' worth of surface — so the
model can be swapped without touching the pipeline. The deterministic stub is
the fallback so local dev, CI and the security test-suite never need network
or keys.

Selection is config-driven ONLY: no code edit to swap, and credentials come
from the environment via backend.config — never hardcoded (brief Section 8 /
README credentials section).

LLM_PROVIDER pins a provider explicitly ("hunyuan" | "openai" | "stub").
Unset, or "auto", picks by available credentials with Hunyuan FIRST: the
hackathon judges "use of AI tools" and the tracks are built on Tencent Cloud
services, so the Tencent path wins whenever it is available. OpenAI exists so
development is not blocked while Hunyuan access is pending.
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
    """Explicit LLM_PROVIDER if set, else credentials-driven with Hunyuan first."""
    choice = (getattr(settings, "llm_provider", "") or "auto").strip().lower()

    if choice == "stub":
        return StubProvider()
    if choice == "hunyuan":
        from backend.agent.hunyuan import HunyuanProvider  # local: stub mode stays SDK-light
        return HunyuanProvider(settings)
    if choice == "openai":
        from backend.agent.openai_provider import OpenAIProvider
        return OpenAIProvider(settings)
    if choice != "auto":
        raise UnknownProvider(
            f"LLM_PROVIDER={choice!r} is not a provider "
            "(expected 'hunyuan', 'openai', 'stub' or 'auto')"
        )

    # auto: Tencent first — it is the judged path — then OpenAI, then the stub.
    if settings.has_credentials:
        from backend.agent.hunyuan import HunyuanProvider
        return HunyuanProvider(settings)
    if settings.has_openai_credentials:
        from backend.agent.openai_provider import OpenAIProvider
        return OpenAIProvider(settings)
    return StubProvider()
