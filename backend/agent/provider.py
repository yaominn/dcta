"""
Swappable LLM provider interface. (brief Section 8)

The parser talks to a LLMProvider — one method's worth of surface — so the
model can be swapped without touching the pipeline. The deterministic stub is
the fallback so local dev, CI and the security test-suite never need network
or keys.

Selection is config-driven ONLY: no code edit to swap, and credentials come
from the environment via backend.config — never hardcoded (brief Section 8 /
README credentials section).

LLM_PROVIDER pins a provider explicitly ("tokenhub" | "openai" | "hunyuan" |
"stub").
Unset, or "auto", picks by which credentials exist. Pinning a live provider is
worth knowing about: it makes a missing or broken key fail LOUDLY instead of
silently falling back to the stub, which would look exactly like the model
working during a demo.

"hunyuan" is the LEGACY path. Tencent decommissioned the public
hunyuan.tencentcloudapi.com ChatCompletions API — every model on it answers
"该模型已下线" and the platform shuts down 2026-09-30 — so "tokenhub" is the
live provider and what "auto" prefers. The class is kept for a self-hosted or
grandfathered endpoint, and because deleting a provider is not what a swappable
provider interface is for.
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
    """Explicit LLM_PROVIDER if set, else the live provider whose key exists."""
    choice = (getattr(settings, "llm_provider", "") or "auto").strip().lower()

    if choice == "stub":
        return StubProvider()
    if choice == "tokenhub":
        from backend.agent.tokenhub import TokenHubProvider  # local: stub mode stays dependency-light
        return TokenHubProvider(settings)
    if choice == "openai":
        from backend.agent.openai_provider import OpenAIProvider
        return OpenAIProvider(settings)
    if choice == "hunyuan":
        from backend.agent.hunyuan import HunyuanProvider    # local: stub mode stays SDK-light
        return HunyuanProvider(settings)
    if choice != "auto":
        raise UnknownProvider(
            f"LLM_PROVIDER={choice!r} is not a provider "
            f"(expected 'tokenhub', 'openai', 'hunyuan', 'stub' or 'auto')"
        )

    # TokenHub first: it is the endpoint that is actually live, and its key is
    # a separate credential from the Tencent pair that still signs ASR. A box
    # with only the ASR pair must NOT select the decommissioned Hunyuan path
    # and spend the whole retry budget discovering it.
    if getattr(settings, "tokenhub_api_key", ""):
        from backend.agent.tokenhub import TokenHubProvider
        return TokenHubProvider(settings)
    if getattr(settings, "openai_api_key", ""):
        from backend.agent.openai_provider import OpenAIProvider
        return OpenAIProvider(settings)
    if settings.has_credentials:
        from backend.agent.hunyuan import HunyuanProvider
        return HunyuanProvider(settings)
    return StubProvider()
