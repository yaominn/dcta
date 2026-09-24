"""
OpenAIProvider — OpenAI chat completions (GPT). (brief Section 8)

An alternative to TokenHub, selected with LLM_PROVIDER=openai. Same wire
protocol, so the HTTP handling is shared in openai_compat.py; this file only
names the endpoint, the key and the model.

Model choice matters here more than it looks: GPT-5-series reasoning models
reject `temperature` (HTTP 400, "Unsupported value"), and the parser sends
temperature=0 so the same transcript yields the same plan. The default,
gpt-4.1-mini, accepts it. To run a reasoning model, set LLM_TEMPERATURE=1.

What leaves the machine: the transcript, and the sanitized opaque-ID context
from context.build_context — never raw stored rows. That chokepoint is the
same whichever provider runs.
"""
from __future__ import annotations

from backend.agent.openai_compat import OpenAICompatibleProvider


class OpenAIProvider(OpenAICompatibleProvider):
    name = "openai"
    label = "OpenAI"
    missing_key = (
        "OPENAI_API_KEY is not set — the OpenAI provider cannot "
        "authenticate. Generate a key at "
        "https://platform.openai.com/api-keys and put it in .env."
    )

    def __init__(self, settings):
        super().__init__(
            api_key=settings.openai_api_key,
            base_url=settings.openai_base_url,
            model=settings.openai_model,
            timeout=settings.llm_timeout_s,
            temperature=settings.llm_temperature,
        )
