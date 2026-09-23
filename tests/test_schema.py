"""
Schema tests — freeze the frozen-v1 contract. (brief Section 7)

These are not just smoke tests: the NEGATIVE cases prove the security
properties baked into the shapes (no payee_id in the LLM schema, no
arithmetic, no invented fields).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.models.schemas import IntentPlan, ResolvedPlan


# --------------------------------------------------------------------------- the Section 7 example
SECTION_7_EXAMPLE = {
    "plan": [
        {
            "id": "t1",
            "type": "TRANSFER",
            "source_account": "acct_savings",
            "target": {"mention": "mom"},
            "amount": {"literal_cents": 50000},   # $500.00 in cents
        },
        {
            "id": "t2",
            "type": "BUY_EQUITY",
            "source_account": "acct_savings",
            "ticker": "AAPL",
            "amount": {"ref": "acct_savings.balance_after:t1", "op": "ALL"},
        },
    ],
    "unresolved": [],
}


def test_section7_example_validates():
    """The canonical multi-intent example parses into the frozen schema."""
    plan = IntentPlan.model_validate(SECTION_7_EXAMPLE)
    assert len(plan.plan) == 2
    assert plan.plan[0].type == "TRANSFER"      # Literal discriminator -> plain str
    assert plan.plan[1].type == "BUY_EQUITY"
    # the second leg's amount is symbolic, not computed — the LLM did no arithmetic
    assert not hasattr(plan.plan[1].amount, "literal_cents")  # it's a SymbolicAmount


# --------------------------------------------------------------------------- security: no payee_id field exists for the LLM
def test_llm_cannot_emit_payee_id():
    """Even if an injected LLM tries to pick a payee, the schema has no field
    for it — extra='forbid' rejects the invented key."""
    bad = {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                "target": {"mention": "mom"},
                "amount": {"literal_cents": 50000},
                "payee_id": "payee_17",  # <-- invented, must be rejected
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


def test_llm_cannot_attach_account_number():
    """Raw account numbers from conversation are not a valid field (brief 4.3)."""
    bad = {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                "target": {"mention": "mom", "account_number": "123-456"},  # invented
                "amount": {"literal_cents": 50000},
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


def test_wrong_variant_field_rejected():
    """A TRANSFER carrying a ticker, or a BUY_EQUITY with a target, is rejected
    by the discriminated union — the model can't smuggle fields across types."""
    bad = {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                "target": {"mention": "mom"},
                "amount": {"literal_cents": 50000},
                "ticker": "AAPL",  # ticker doesn't belong on a TRANSFER
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


def test_unresolved_must_not_be_guessed():
    """If the LLM cannot determine a field, it goes in `unresolved`, not made up."""
    plan = IntentPlan.model_validate({
        "plan": [],
        "unresolved": ["amount for t1"],
    })
    assert plan.unresolved == ["amount for t1"]


# --------------------------------------------------------------------------- resolved plan
def test_resolved_plan_roundtrip():
    """The signed payload carries concrete payee_id + amounts (cents), never mentions."""
    resolved = ResolvedPlan.model_validate({
        "draft_id": "d_001",
        "plan": [
            {"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
             "payee_id": "payee_17", "payee_display": "Mom", "amount_cents": 50000},
            {"id": "t2", "type": "BUY_EQUITY", "source_account": "acct_savings",
             "ticker": "AAPL", "amount_cents": 772800,
             "estimated_shares": 32, "estimated_fill_price_cents": 24150},
        ],
        "created_at": "2026-09-23T12:00:00+00:00",
    })
    assert resolved.plan[1].estimated_shares == 32  # whole shares only
