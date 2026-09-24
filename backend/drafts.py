"""
Server-side draft store. (brief 4.5 — the draft_id the nonce binds to)

A draft is the state between "the user said something" and "the user signed
it": the parsed IntentPlan, the transcript, any clarification answers so far,
and — once resolution completes — the ResolvedPlan with its policy verdicts and
validation report.

WHY THIS IS SERVER-SIDE, and not round-tripped through the browser:

    The obvious shape for a clarify loop is to hand the caller the state and
    accept it back with the answer. That would let a client rewrite the plan
    between the question and the answer — approve "who did you mean?" and
    return a different IntentPlan. So the client is given a draft_id and
    nothing else: it answers with {field, choice_id}, and the server resolves
    against ITS OWN copy. The resolver already refuses an id the mention does
    not justify; keeping the state here means there is no second path around
    that check.

    The draft_id is also what the WebAuthn nonce binds to, so it must be
    server-issued and unguessable (secrets.token_urlsafe), never client-chosen.

TTL: drafts expire with the authorization window they will be signed in
(MAX_AUTH_WINDOW_S). Demo-scale in-memory storage, swept on access — a
deployment would persist this; the audit chain already records every draft that
reached validation, so nothing auditable is lost when the cache evaporates.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import Any

from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import MAX_AUTH_WINDOW_S, ResolvedPlan


@dataclass
class Draft:
    """One in-flight draft. `status` is where it stopped:

      clarify  — the resolver needs an answer; not signable
      blocked  — policy refused it; NO ResolvedPlan is retained, so there is
                 nothing to sign even by mistake
      frozen   — the validator froze it; the plan is retained for display, but
                 /api/auth/nonce refuses a nonce so it cannot be signed
      ready    — resolved, policy-cleared, validator-passed; signable
    """
    draft_id: str
    user_id: str
    transcript: str
    intent_plan: dict
    created_at: float
    kind: str = "payment"             # payment | contact_edit
    status: str = "clarify"
    answers: dict[str, str] = field(default_factory=dict)
    resolved_plan: ResolvedPlan | None = None
    resolved_change: ResolvedContactChange | None = None     # kind == contact_edit
    policy: dict | None = None
    validation: dict | None = None
    question: dict | None = None

    @property
    def payload(self):
        """Whatever this draft would have the user sign, or None."""
        return self.resolved_plan if self.kind == "payment" else self.resolved_change

    def is_expired(self, now: float, ttl: int) -> bool:
        return (now - self.created_at) > ttl


class DraftStore:
    def __init__(self, ttl_seconds: int = MAX_AUTH_WINDOW_S):
        self.ttl = ttl_seconds
        self._drafts: dict[str, Draft] = {}

    @staticmethod
    def new_id() -> str:
        """Server-issued and unguessable: the nonce binds to this."""
        return secrets.token_urlsafe(16)

    def put(self, draft: Draft) -> Draft:
        self._sweep()
        self._drafts[draft.draft_id] = draft
        return draft

    def get(self, draft_id: str) -> Draft | None:
        self._sweep()
        return self._drafts.get(draft_id)

    def _sweep(self) -> None:
        now = time.time()
        for k in [k for k, d in self._drafts.items() if d.is_expired(now, self.ttl)]:
            del self._drafts[k]

    def __len__(self) -> int:
        self._sweep()
        return len(self._drafts)
