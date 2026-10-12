"""
Which question a request with no payment in it is asking.

The payment parser runs first; only when it finds no payment does the app ask
the model this. The model's whole output is ONE label from a fixed list,
validated as a Literal: anything else, or any failure, is "off_topic". The
answer itself is written by plain code from the ledger (backend/answers.py),
so no model text ever reaches the screen, and nothing here can move money.

The prompt carries the user's words and nothing else — no ledger data, so a
stored field (biller_07's reference text is a planted injection) never
reaches it.
"""
from __future__ import annotations

from typing import Literal, get_args

from pydantic import BaseModel, ConfigDict

from backend.agent import prompts
from backend.agent.errors import ProviderUnavailable
from backend.agent.parser import ParseFailure, _generate_validated
from backend.agent.provider import LLMProvider

Label = Literal["balance", "recent_payments", "why_stopped", "contacts",
                "what_can_you_do", "off_topic"]
LABELS: tuple[str, ...] = get_args(Label)


class QuestionLabel(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: Label


def classify_question(transcript: str, *, provider: LLMProvider, max_attempts: int = 2) -> str:
    """One of LABELS. A reply outside the list, unparseable output or a
    provider failure is "off_topic": the safe answer says only what the app
    can help with."""
    try:
        return _generate_validated(
            QuestionLabel, transcript, None, system=prompts.question_system_prompt(),
            footer=prompts.QUESTION_OUTPUT_FOOTER, provider=provider,
            max_attempts=max_attempts, user=prompts.question_user_prompt(transcript)).label
    except (ParseFailure, ProviderUnavailable):
        return "off_topic"
