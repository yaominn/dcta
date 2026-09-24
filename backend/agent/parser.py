"""
The intent parser. (brief Section 8)

generate -> validate against the frozen Pydantic schema -> reject and retry,
bounded retries. This loop — not provider-side structured output, not prompt
politeness — is what carries the schema-constraint requirement: ANY text the
model returns either validates into an IntentPlan or is rejected with the
validator's error fed back for repair. After MAX_ATTEMPTS the parse fails
closed (ParseFailure) — a model that cannot produce a valid plan produces no
draft at all, which the architecture treats as safe by default.
"""
from __future__ import annotations

import json

from backend.agent import prompts
from backend.agent.context import PromptContext
from backend.agent.provider import LLMProvider
from backend.models.schemas import IntentPlan

MAX_ATTEMPTS = 3   # 1 initial try + 2 repairs; then fail closed


class ParseFailure(Exception):
    """The model could not produce a schema-valid IntentPlan within the retry
    budget. Carries one entry per attempt for the audit/422 surface."""

    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__(
            f"no valid IntentPlan after {len(errors)} attempt(s): {errors[-1]}"
        )


def extract_json(raw: str) -> dict:
    """Pull the first JSON object out of a model response, tolerating markdown
    fences and surrounding prose. Raises ValueError if there is none."""
    text = raw.strip()
    if text.startswith("```"):                       # ```json ... ``` fence
        lines = text.splitlines()
        lines = lines[1:] if lines and lines[0].startswith("```") else lines
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        raise ValueError("no JSON object found in model output")
    return json.loads(text[start:end + 1])           # JSONDecodeError -> ValueError


def parse_transcript(transcript: str, *, provider: LLMProvider,
                     context: PromptContext, max_attempts: int = MAX_ATTEMPTS) -> IntentPlan:
    """Turn the user's transcript into a validated IntentPlan.

    The transcript is user speech (untrusted but authorized); the context is
    the sanitized opaque-ID view. Both are prompt inputs — the OUTPUT contract
    is enforced here, by validation, never assumed from the prompt.
    """
    system = prompts.system_prompt()
    user = prompts.user_prompt(transcript, context)
    errors: list[str] = []

    for attempt in range(1, max_attempts + 1):
        raw = provider.complete(system=system, user=user)
        try:
            return IntentPlan.model_validate(extract_json(raw))
        except ValueError as exc:     # JSON errors AND pydantic ValidationError
            errors.append(f"attempt {attempt}: {exc}")
            if attempt < max_attempts:
                user = prompts.retry_prompt(
                    transcript, context, previous_output=raw, error=str(exc)
                )
    raise ParseFailure(errors)
