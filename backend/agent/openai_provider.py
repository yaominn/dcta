"""
OpenAIProvider — GPT chat completions. (brief Section 8, swappable provider)

Selected by get_provider() when OpenAI credentials are configured and Hunyuan
is not, or explicitly via LLM_PROVIDER=openai. The SDK import is lazy (inside
complete()) so constructing or selecting this provider never requires the SDK
or the network — the test-suite exercises selection without either.

Hackathon note: the judged "use of AI tools" dimension favours Tencent
services, so Hunyuan wins in `auto` selection when its credentials exist. This
provider is here so development is not blocked while Hunyuan access is
pending, and so there is a working fallback if it never arrives.

Schema-constrained output is NOT delegated to the provider. response_format
json_object makes well-formed JSON much more likely, but the parser still
validates every response against the frozen Pydantic schema and retries on
rejection (brief 8: "the schema constraint is enforced on our side regardless
of provider-side enforcement"). A provider that returns perfect JSON of the
wrong shape is still rejected here.
"""
from __future__ import annotations

from backend.agent.errors import ProviderError


class OpenAIProvider:
    name = "openai"

    def __init__(self, settings):
        self._api_key = settings.openai_api_key
        self._model = settings.openai_model
        self._timeout = settings.llm_timeout_s
        self._temperature = settings.llm_temperature

    def complete(self, *, system: str, user: str) -> str:
        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover - only in live mode without deps
            raise ProviderError(
                "the `openai` package is required for the OpenAI provider "
                "(pip install -r requirements.txt), or unset OPENAI_API_KEY to use the stub."
            ) from exc

        client = OpenAI(api_key=self._api_key, timeout=self._timeout)
        try:
            resp = client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                # Structured extraction, not prose: near-zero temperature so the
                # same transcript yields the same plan and the retry budget is
                # spent on genuine ambiguity, not sampling noise.
                temperature=self._temperature,
                # Guarantees syntactically valid JSON. Says nothing about SHAPE —
                # our Pydantic validation remains the only authority on that.
                response_format={"type": "json_object"},
            )
        except Exception as exc:  # SDK raises a family of transport/API errors
            raise ProviderError(f"OpenAI request failed: {type(exc).__name__}: {exc}") from exc

        if not resp.choices:
            raise ProviderError("OpenAI returned no choices")
        content = resp.choices[0].message.content
        if not content:
            raise ProviderError("OpenAI returned an empty message")
        return content
