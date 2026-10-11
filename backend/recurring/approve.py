"""
A supervised occurrence -> the ordinary, one-payment draft the user signs.

When the user opens a pending bill, this builds a fresh ResolvedPlan from the
signed mandate — exactly its biller, account and amount — under the
occurrence's own execution key, runs the policy engine and the scam rules over
it like any payment, and stores it as a `ready` draft. From there it is the
normal flow: a nonce, the passkey, Gateway.submit() with every check it makes,
and the executor (which re-checks the mandate under its write lock).

The validator is not run: it compares a MODEL's reading of the user's words
with the resolved plan, and no model was involved here — the plan is derived
from terms the user signed. Said on the draft, not skipped silently.

A payment that would need more than a signature (a hold, a phone code, the
threshold-1 questions) is not offered from here: the user is told to make it
as a one-time payment instead, where those checks run in full.
"""
from __future__ import annotations

import time

from backend.audit.canonical import payload_hash
from backend.data import billers
from backend.data.db import connect
from backend.drafts import Draft
from backend.policy import Decision, evaluate, load_context, scam
from backend.recurring import schedule, store
from backend.recurring.terms import occurrence_plan, occurrence_transcript

OFFERABLE = (scam.ALLOW, scam.WARN, scam.DELAY)


class NotApprovable(Exception):
    def __init__(self, status: int, error: str, **extra):
        super().__init__(error)
        self.status, self.detail = status, {"error": error, **extra}


def build_draft(mandate_id: str, seq: int, *, user_id: str, db_path, now: int,
                recent_change_hours: int, cooling_hours: int, executor):
    """(Draft, terms, policy verdicts, scam assessment) for a pending
    occurrence, or raises NotApprovable / returns a blocked Draft."""
    conn = connect(db_path)
    try:
        m = store.get_mandate(conn, mandate_id)
        occ = store.occurrence(conn, mandate_id, seq)
        biller_ok = None
        terms = store.load_terms(m) if m else None
        if terms is not None:
            biller_ok = billers.matches(conn, terms.biller_id, terms.biller_ref_version,
                                        terms.biller_ref_hash)
    finally:
        conn.close()
    if m is None or occ is None or m["user_id"] != user_id:
        raise NotApprovable(404, "no such recurring payment")
    prior = executor.prior_execution(occ["draft_id"])
    if prior is not None:
        raise NotApprovable(409, f"this payment was already {prior['outcome'].lower()}",
                            outcome=prior["outcome"], execution=prior["result"])
    if terms is None:
        raise NotApprovable(409, "this arrangement's record doesn't match what you signed")
    if m["status"] != "ACTIVE":
        raise NotApprovable(409, f"this arrangement is {m['status'].lower()}")
    if occ["status"] not in store.APPROVABLE:
        raise NotApprovable(409, f"this payment is {occ['status'].lower().replace('_', ' ')}")
    if not occ["due_at"] <= now <= occ["review_until"]:
        raise NotApprovable(409, "this payment isn't open for approval now")
    if not biller_ok:
        raise NotApprovable(409, f"{terms.biller_display}'s payment details changed since you "
                                 "set this up — nothing can be paid until you set it up again")

    real_now = int(time.time())
    due = schedule.parse_date(occ["due_date"])
    plan = occurrence_plan(terms, draft_id=occ["draft_id"], seq=seq, due=due, now=real_now)
    transcript = occurrence_transcript(terms, seq, due)
    draft = Draft(draft_id=occ["draft_id"], user_id=user_id, transcript=transcript,
                  intent_plan={}, created_at=time.time(), kind="payment")
    verdicts = evaluate(plan, load_context(user_id, db_path=db_path, now=real_now))
    draft.policy = {"decision": verdicts.decision.value,
                    "verdicts": [{"leg_id": v.leg_id, "decision": v.decision.value,
                                  "rule": v.rule, "reason": v.reason} for v in verdicts.verdicts]}
    draft.validation = {"verdict": "NOT_APPLICABLE", "frozen": False, "checks": [
        {"check": "recurring_mandate", "ok": True,
         "detail": "built from your signed recurring arrangement; no model output involved"}],
        "soft_signals": [], "llm_check": None}
    assessment = scam.reassess(plan, user_id, db_path=db_path, now=real_now,
                               transcript=transcript, recent_change_hours=recent_change_hours,
                               cooling_hours=cooling_hours, draft_id=occ["draft_id"])
    if verdicts.blocked or verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION:
        draft.status = "blocked"
        return draft, terms, verdicts, assessment
    if assessment.outcome not in OFFERABLE or (scam.ASK_QUESTIONS and assessment.asks):
        draft.status = "blocked"
        draft.scam = {**assessment.to_dict(), "payload_hash": None}
        return draft, terms, verdicts, assessment
    draft.scam_floor = assessment.outcome
    draft.scam = {**assessment.to_dict(), "confirm_name": None,
                  "payload_hash": payload_hash(plan), "scored": assessment.outcome}
    draft.resolved_plan = plan
    draft.status = "ready"
    return draft, terms, verdicts, assessment
