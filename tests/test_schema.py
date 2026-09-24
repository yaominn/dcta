"""
Schema tests — freeze the frozen-v1 contract. (brief Section 7)

These are not just smoke tests: the NEGATIVE cases prove the security
properties baked into the shapes (no payee_id in the LLM schema, no
arithmetic, no invented fields).
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from backend.audit.canonical import hash_transcript
from backend.models.schemas import (
    IntentPlan, ResolvedPlan, MAX_AUTH_WINDOW_S, MAX_AMOUNT_CENTS,
)

_TX = "stub: pay mom five hundred then buy aapl with the rest"
_TX_HASH = hash_transcript(_TX)


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
        "schema_version": "1",
        "draft_id": "d_001",
        "plan": [
            {"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
             "payee_id": "payee_17", "payee_display": "Mom", "amount_cents": 50000},
            {"id": "t2", "type": "BUY_EQUITY", "source_account": "acct_savings",
             "ticker": "AAPL", "amount_cents": 772800,
             "estimated_shares": 32, "estimated_fill_price_cents": 24150},
        ],
        "transcript_hash": _TX_HASH,
        "created_at": 1_700_000_000,
        "expires_at": 1_700_000_120,
    })
    assert resolved.plan[1].estimated_shares == 32  # whole shares only
    assert resolved.schema_version == "1"
    assert resolved.transcript_hash == _TX_HASH


def test_resolved_plan_requires_transcript_hash():
    """S1: a plan cannot be built without binding to a transcript. With no
    default, omitting transcript_hash is a ValidationError — the non-repudiation
    binding to the origin utterance cannot be retrofitted later."""
    with pytest.raises(ValidationError):
        ResolvedPlan.model_validate({
            "draft_id": "d_001",
            "plan": [
                {"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                 "payee_id": "payee_17", "payee_display": "Mom", "amount_cents": 50000},
            ],
            "created_at": 1_700_000_000,
            "expires_at": 1_700_000_120,
        })   # <- no transcript_hash


@pytest.mark.parametrize("bad_hash", [
    "abc",                          # wrong length
    "z" * 64,                       # right length, non-hex
    "deadbeef",                     # too short, partial hex
    "",                             # empty
])
def test_transcript_hash_must_be_valid_sha256(bad_hash):
    """S1: transcript_hash is pattern-locked to ^[0-9a-f]{64}$ . A wrong
    length or any non-hex char is rejected at validation, not at hashing time."""
    with pytest.raises(ValidationError):
        ResolvedPlan.model_validate({
            "draft_id": "d_001",
            "plan": [
                {"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                 "payee_id": "payee_17", "payee_display": "Mom", "amount_cents": 50000},
            ],
            "transcript_hash": bad_hash,
            "created_at": 1_700_000_000,
            "expires_at": 1_700_000_120,
        })


# --------------------------------------------------------------------------- N1/N2: the authorization window is bounded by construction
def _resolved_dict(**overrides):
    """A minimal valid ResolvedPlan dict. Tests override created_at/expires_at
    to exercise the window validator (N1 inverted, N2 over-long)."""
    base = {
        "draft_id": "d_001",
        "plan": [
            {"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
             "payee_id": "payee_17", "payee_display": "Mom", "amount_cents": 50000},
        ],
        "transcript_hash": _TX_HASH,
        "created_at": 1_700_000_000,
        "expires_at": 1_700_000_120,
    }
    base.update(overrides)
    return base


def test_inverted_window_rejected():
    """N1: expires_at must be strictly after created_at. An approval that ends
    before or exactly when it began is not an authorization; rejected at
    construction so it can never be signed."""
    with pytest.raises(ValidationError):
        ResolvedPlan.model_validate(_resolved_dict(
            created_at=1_700_000_000, expires_at=1_700_000_000,
        ))


def test_overlong_window_rejected():
    """N2: the authorization window is capped (MAX_AUTH_WINDOW_S). A ten-year
    approval is not a time-bounded authorization. Enforced at construction, so
    a bad timestamp can never be signed regardless of what the server wrote."""
    c = 1_700_000_000
    with pytest.raises(ValidationError):
        ResolvedPlan.model_validate(_resolved_dict(
            created_at=c, expires_at=c + MAX_AUTH_WINDOW_S + 1,
        ))


def test_window_at_cap_is_valid():
    """Boundary: a window of exactly MAX_AUTH_WINDOW_S is acceptable (the cap is
    inclusive). Pins the edge so a future off-by-one is caught."""
    c = 1_700_000_000
    plan = ResolvedPlan.model_validate(_resolved_dict(
        created_at=c, expires_at=c + MAX_AUTH_WINDOW_S,
    ))
    assert plan.expires_at - plan.created_at == MAX_AUTH_WINDOW_S


# --------------------------------------------------------------------------- N1: amount_cents is bounded (cross-language hash safety)
def test_amount_cents_above_2to53_rejected():
    """N1: JS numbers are doubles; integers above 2^53 lose precision in JS but
    not Python, so the two canonicalizers would produce different bytes -> a
    payload_hash mismatch in the exact field the binding-constraint test proves
    matches. The bound makes that guarantee unconditional, not incidental. A
    value one above the ceiling is rejected at validation, so it can never be
    signed."""
    with pytest.raises(ValidationError):
        ResolvedPlan.model_validate(_resolved_dict(
            plan=[{"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
                   "payee_id": "payee_17", "payee_display": "Mom",
                   "amount_cents": MAX_AMOUNT_CENTS + 1}],
        ))


def test_amount_cents_at_2to53_is_valid():
    """Boundary: the ceiling itself is acceptable (inclusive). The bound is a
    hard ceiling on the signed payload, not an off-by-one below it."""
    plan = ResolvedPlan.model_validate(_resolved_dict(
        plan=[{"id": "t1", "type": "TRANSFER", "source_account": "acct_savings",
               "payee_id": "payee_17", "payee_display": "Mom",
               "amount_cents": MAX_AMOUNT_CENTS}],
    ))
    assert plan.plan[0].amount_cents == MAX_AMOUNT_CENTS
