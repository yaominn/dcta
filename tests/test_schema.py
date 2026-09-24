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
    AmountOp, IntentPlan, ResolvedPlan, SymbolicAmount,
    MAX_AUTH_WINDOW_S, MAX_AMOUNT_CENTS,
)

_TX = "stub: pay mom five hundred then buy aapl with the rest"
_TX_HASH = hash_transcript(_TX)


# --------------------------------------------------------------------------- the Section 7 example
# L3: source_account and ticker are MENTIONS ({mention:"..."}), not the bare
# account-alias / ticker-string the brief's literal Section 7 shows. The LLM
# cannot name which account to debit or which equity directly; only the
# resolver maps the mention. Symbolic amounts name an earlier LEG (after_leg),
# never an account — the account is derived from the referenced leg's own
# source_account at resolution time, so no account alias is representable
# anywhere in the LLM output. (Supersedes the brief's "ref" grammar.)
SECTION_7_EXAMPLE = {
    "plan": [
        {
            "id": "t1",
            "type": "TRANSFER",
            "source_account": {"mention": "savings"},
            "target": {"mention": "mom"},
            "amount": {"literal_cents": 50000},   # $500.00 in cents
        },
        {
            "id": "t2",
            "type": "BUY_EQUITY",
            "source_account": {"mention": "savings"},
            "ticker": {"mention": "AAPL"},
            "amount": {"after_leg": "t1", "op": "ALL"},
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
    # L3: source_account + ticker are mentions, not bare identifiers.
    assert plan.plan[0].source_account.mention == "savings"
    assert plan.plan[1].ticker.mention == "AAPL"
    # the second leg's amount is symbolic, not computed — the LLM did no arithmetic
    amt = plan.plan[1].amount
    assert isinstance(amt, SymbolicAmount)
    assert amt.after_leg == "t1"          # names a leg, never an account
    assert amt.op is AmountOp.ALL


# --------------------------------------------------------------------------- security: no payee_id field exists for the LLM
def test_llm_cannot_emit_payee_id():
    """Even if an injected LLM tries to pick a payee, the schema has no field
    for it — extra='forbid' rejects the invented key."""
    bad = {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER",
                "source_account": {"mention": "savings"},
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
                "id": "t1", "type": "TRANSFER",
                "source_account": {"mention": "savings"},
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
                "id": "t1", "type": "TRANSFER",
                "source_account": {"mention": "savings"},
                "target": {"mention": "mom"},
                "amount": {"literal_cents": 50000},
                "ticker": {"mention": "AAPL"},  # ticker doesn't belong on a TRANSFER
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


# --------------------------------------------------------------------------- L3: source_account + ticker are mentions, not identifiers
def test_source_account_must_be_mention_not_identifier():
    """L3: the LLM emits a MENTION for the source account ({mention:'savings'}),
    not the account alias/id. A bare alias string like 'acct_savings' is
    rejected — the LLM cannot name which account to debit directly; only the
    resolver maps the mention. Mirrors 'no payee_id'."""
    bad = {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER",
                "source_account": "acct_savings",   # bare identifier -> rejected
                "target": {"mention": "mom"},
                "amount": {"literal_cents": 50000},
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


def test_ticker_must_be_mention_not_identifier():
    """L3: the LLM emits a MENTION for the equity ({mention:'AAPL'}), not a
    bare ticker string. The resolver validates it maps to a known equity."""
    bad = {
        "plan": [
            {
                "id": "t2", "type": "BUY_EQUITY",
                "source_account": {"mention": "savings"},
                "ticker": "AAPL",   # bare identifier -> rejected
                "amount": {"after_leg": "t1", "op": "ALL"},
            }
        ],
        "unresolved": [],
    }
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(bad)


# --------------------------------------------------------------------------- L3 residual: symbolic amounts name legs, never accounts
def _symbolic_plan(amount):
    """A two-leg plan: t1 is a literal transfer; t2 carries the given amount."""
    return {
        "plan": [
            {
                "id": "t1", "type": "TRANSFER",
                "source_account": {"mention": "savings"},
                "target": {"mention": "mom"},
                "amount": {"literal_cents": 50000},
            },
            {
                "id": "t2", "type": "BUY_EQUITY",
                "source_account": {"mention": "savings"},
                "ticker": {"mention": "AAPL"},
                "amount": amount,
            },
        ],
        "unresolved": [],
    }


def test_symbolic_amount_after_leg_constructs():
    """The grammar: a symbolic amount names an earlier leg + op. There is no
    account field — the account is derived from the referenced leg's own
    source_account at resolution time."""
    plan = IntentPlan.model_validate(_symbolic_plan({"after_leg": "t1", "op": "ALL"}))
    amt = plan.plan[1].amount
    assert isinstance(amt, SymbolicAmount)
    assert amt.after_leg == "t1"
    assert amt.op is AmountOp.ALL


def test_symbolic_amount_old_ref_form_rejected():
    """Regression pin: the brief's old grammar embedded an account alias
    ({"ref": "acct_savings.balance_after:t1", ...}). That shape must not
    validate at all — extra="forbid" rejects the `ref` key, so an account
    alias is unrepresentable in an amount, not merely discouraged."""
    with pytest.raises(ValidationError):
        IntentPlan.model_validate(
            _symbolic_plan({"ref": "acct_savings.balance_after:t1", "op": "ALL"})
        )


def test_symbolic_amount_forward_reference_rejected():
    """A leg may only depend on an EARLIER leg — t1 referencing t2 is a
    forward (circular) reference, rejected at construction."""
    bad = _symbolic_plan({"literal_cents": 100})
    bad["plan"][0]["amount"] = {"after_leg": "t2", "op": "ALL"}
    with pytest.raises(ValidationError, match="earlier leg"):
        IntentPlan.model_validate(bad)


def test_symbolic_amount_self_reference_rejected():
    """A leg referencing itself is degenerate circularity — rejected."""
    with pytest.raises(ValidationError, match="earlier leg"):
        IntentPlan.model_validate({
            "plan": [
                {
                    "id": "t1", "type": "TRANSFER",
                    "source_account": {"mention": "savings"},
                    "target": {"mention": "mom"},
                    "amount": {"after_leg": "t1", "op": "ALL"},
                }
            ],
            "unresolved": [],
        })


def test_symbolic_amount_unknown_leg_rejected():
    """A ref to a leg id that does not exist in the plan is rejected at
    construction — the resolver can never be handed a dangling reference."""
    with pytest.raises(ValidationError, match="not a leg"):
        IntentPlan.model_validate(_symbolic_plan({"after_leg": "t9", "op": "ALL"}))


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
