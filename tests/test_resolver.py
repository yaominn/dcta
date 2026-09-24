"""
M4 acceptance tests — Deterministic Resolver + clarify loop. (brief Section 6)

One test per acceptance case in the brief, plus a clarify-loop resume round-trip
that proves the 2+ disambiguation path can be resumed with an answer. The
resolver is exercised directly (no HTTP, no LLM): the IntentPlan is constructed
in-test, which is exactly the shape M3's parser produces and M5+ will call with.

Headline arithmetic locked in the seed (brief Section 13), all integer cents:
  acct_savings 842050 - 50000 (t1) = 792050 -> at AAPL 24150:
  792050 // 24150 = 32 whole shares = 772800, remainder 19250. No floats.
"""
from __future__ import annotations

import pytest

from backend.audit.canonical import hash_transcript, payload_hash
from backend.data.seed import seed
from backend.models.schemas import (
    AmountOp,
    BuyEquityIntent,
    IntentPlan,
    LiteralAmount,
    MentionTarget,
    PayBillIntent,
    SymbolicAmount,
    TransferIntent,
)
from backend.resolver import Clarify, Resolved, resolve

seed()  # clean mock ledger before the run (matches the other suites)


# --------------------------------------------------------------------------- builders
def _mention(s: str) -> MentionTarget:
    return MentionTarget(mention=s)


def _lit(cents: int) -> LiteralAmount:
    return LiteralAmount(literal_cents=cents)


def _sym(ref: str, op: AmountOp) -> SymbolicAmount:
    return SymbolicAmount(after_leg=ref, op=op)


# --------------------------------------------------------------------------- 1. headline
def test_1_headline_two_leg_plan():
    """Transfer 500 from savings to mom, invest the rest in Apple -> 2-leg
    ResolvedPlan; leg 2 = 32 shares, 772800 cents, remainder 19250."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(50000),
        ),
        BuyEquityIntent(
            id="t2", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("Apple"),
            amount=_sym("t1", AmountOp.ALL),
        ),
    ])
    res = resolve(
        plan,
        transcript="transfer 500 from savings to mom and invest the rest in apple",
        user_id="u_alice",
    )
    assert isinstance(res, Resolved)
    assert len(res.plan.plan) == 2

    t1, t2 = res.plan.plan
    assert t1.type == "TRANSFER"
    assert t1.source_account == "acct_savings"
    assert t1.payee_id == "payee_17"
    assert t1.payee_display == "Mom ··3310"          # DB-sourced, not LLM-derived
    assert t1.amount_cents == 50000

    assert t2.type == "BUY_EQUITY"
    assert t2.source_account == "acct_savings"       # derived from t1 (symbolic)
    assert t2.ticker == "AAPL"
    assert t2.estimated_shares == 32
    assert t2.amount_cents == 772800                  # the SPEND, not the allocated 792050
    assert t2.estimated_fill_price_cents == 24150

    # remainder stays in the source account: 792050 - 772800 = 19250
    assert 842050 - 50000 - 772800 == 19250

    # the signed payload binds the origin utterance
    assert res.plan.transcript_hash == hash_transcript(
        "transfer 500 from savings to mom and invest the rest in apple"
    )


# --------------------------------------------------------------------------- 2. two johns
def test_2_two_johns_disambiguate():
    """'Send fifty to John' -> a disambiguation question naming BOTH last-4s,
    never a guess. The seed has payee_21 ··4521 and payee_22 ··8892."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("John"),
            amount=_lit(5000),
        ),
    ])
    res = resolve(plan, transcript="send fifty to john", user_id="u_alice")
    assert isinstance(res, Clarify)
    assert "4521" in res.question and "8892" in res.question
    assert len(res.choices) == 2
    assert {c["id"] for c in res.choices} == {"payee_21", "payee_22"}
    # never a fabricated id
    assert not isinstance(res, Resolved)


# --------------------------------------------------------------------------- 3. unknown payee
def test_3_unknown_payee_clarifies():
    """A mention matching nothing -> a question, never a made-up payee_id."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("Dave"),
            amount=_lit(5000),
        ),
    ])
    res = resolve(plan, transcript="send fifty to dave", user_id="u_alice")
    assert isinstance(res, Clarify)
    assert "Dave" in res.question
    assert res.choices == []                          # open question -> re-pipeline, not resume
    assert res.kind == "payee"


# --------------------------------------------------------------------------- 4. company name
def test_4_company_name_apple_to_aapl():
    """{"mention":"Apple"} -> AAPL at 24150 (ticker match fails, name table maps it)."""
    plan = IntentPlan(plan=[
        BuyEquityIntent(
            id="t1", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("Apple"),
            amount=_lit(100000),
        ),
    ])
    res = resolve(plan, transcript="buy apple with a thousand", user_id="u_alice")
    assert isinstance(res, Resolved)
    leg = res.plan.plan[0]
    assert leg.ticker == "AAPL"
    assert leg.estimated_fill_price_cents == 24150
    # 100000 // 24150 = 4 shares, spend 96600, remainder 3400
    assert leg.estimated_shares == 4
    assert leg.amount_cents == 96600


def test_4b_ticker_mention_resolves_directly():
    """{"mention":"AAPL"} (a bare ticker) resolves directly via the ticker column."""
    plan = IntentPlan(plan=[
        BuyEquityIntent(
            id="t1", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("aapl"),
            amount=_lit(50000),
        ),
    ])
    res = resolve(plan, transcript="buy aapl", user_id="u_alice")
    assert isinstance(res, Resolved)
    assert res.plan.plan[0].ticker == "AAPL"


# --------------------------------------------------------------------------- 5. unresolved is a hint
def test_5_unresolved_is_a_hint_not_a_gate():
    """A plan with a genuinely missing field but an EMPTY unresolved list still
    triggers clarification. The resolver independently verifies every field; the
    LLM's unresolved list is a hint, not authority to skip clarification."""
    plan = IntentPlan(
        plan=[
            TransferIntent(
                id="t1", type="TRANSFER",
                source_account=_mention("savings"), target=_mention("Dave"),
                amount=_lit(5000),
            )
        ],
        unresolved=[],                               # explicitly empty — but Dave matches nothing
    )
    res = resolve(plan, transcript="send fifty to dave", user_id="u_alice")
    assert isinstance(res, Clarify)                  # verified independently, not gated


# --------------------------------------------------------------------------- 6. empty intent plan
def test_6_empty_intent_plan_clarifies_and_builds_no_resolved_plan():
    """An empty IntentPlan (nothing understood) -> a question, and NO ResolvedPlan
    is constructed (a signature over an empty authorization is meaningless)."""
    plan = IntentPlan(plan=[], unresolved=["could not understand: 'uh never mind'"])
    res = resolve(plan, transcript="uh never mind", user_id="u_alice")
    assert isinstance(res, Clarify)
    assert res.kind == "empty"
    # there is no .plan attribute to hash — the clarify path never builds one
    assert not isinstance(res, Resolved)


# --------------------------------------------------------------------------- 7. no floats
def test_7_resolved_plan_canonicalizes_without_raising():
    """Every resolved plan canonicalizes without raising (no float anywhere) —
    i.e. payload_hash(resolved) succeeds and returns a 64-char hex digest."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(50000),
        ),
        BuyEquityIntent(
            id="t2", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("AAPL"),
            amount=_sym("t1", AmountOp.ALL),
        ),
    ])
    res = resolve(plan, transcript="pay mom five hundred then buy aapl with the rest",
                 user_id="u_alice")
    assert isinstance(res, Resolved)
    h = payload_hash(res.plan)                       # must not raise TypeError on a float
    assert len(h) == 64
    assert all(c in "0123456789abcdef" for c in h)


# --------------------------------------------------------------------------- 8. insufficient / drained
def test_8a_symbolic_all_on_drained_account_clarifies_not_zero():
    """A symbolic ALL on a drained account does NOT produce a zero-amount leg
    (amount_cents is gt=0) — it is a clarify case. Here t1 drains savings
    (842050c), so t2's ALL-after-t1 would be 0 -> clarify, not a constructed leg."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(842050),                      # drains savings to 0
        ),
        BuyEquityIntent(
            id="t2", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("AAPL"),
            amount=_sym("t1", AmountOp.ALL),          # 0 left -> can't buy a share
        ),
    ])
    res = resolve(plan, transcript="empty savings to mom then buy aapl with the rest",
                 user_id="u_alice")
    assert isinstance(res, Clarify)                  # never a zero-amount leg
    assert res.kind in ("zero", "equity_too_small")
    assert not isinstance(res, Resolved)


def test_8b_literal_exceeds_balance_clarifies():
    """A literal amount the account can't cover -> clarify (we never sign a plan
    the executor would reject). Decided: clarify, not a hard failure, so the
    voice-first loop can offer a smaller amount / different account."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(99999999),
        ),
    ])
    res = resolve(plan, transcript="send a million to mom", user_id="u_alice")
    assert isinstance(res, Clarify)
    assert res.kind == "insufficient"


# --------------------------------------------------------------------------- resume round-trip
def test_clarify_resume_with_answer_picks_the_chosen_john():
    """The 2+ disambiguation path resumes via answers: the caller passes the
    chosen id back under the Clarify's field, and the resolver validates it is
    among the candidates the mention justifies (a caller can't inject another id)."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("John"),
            amount=_lit(5000),
        ),
    ])
    first = resolve(plan, transcript="send fifty to john", user_id="u_alice")
    assert isinstance(first, Clarify)
    assert first.field == "t1.target"

    # user answers "John Doe ··4521" -> payee_21
    second = resolve(
        plan, transcript="send fifty to john", user_id="u_alice",
        draft_id=first.resume_state["draft_id"],     # keep the nonce-binding id stable
        answers={first.field: "payee_21"},
    )
    assert isinstance(second, Resolved)
    assert second.plan.plan[0].payee_id == "payee_21"
    assert second.plan.plan[0].payee_display == "John ··4521"
    assert second.plan.draft_id == first.resume_state["draft_id"]


def test_clarify_resume_rejects_an_id_the_mention_does_not_justify():
    """Security: an answer whose id is NOT among the candidates is ignored, and
    the resolver re-clarifies rather than trusting the caller-supplied id."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("John"),
            amount=_lit(5000),
        ),
    ])
    # payee_17 is "Mom" — not among the two Johns. The resolver must re-clarify.
    res = resolve(
        plan, transcript="send fifty to john", user_id="u_alice",
        answers={"t1.target": "payee_17"},
    )
    assert isinstance(res, Clarify)
    assert {c["id"] for c in res.choices} == {"payee_21", "payee_22"}


# --------------------------------------------------------------------------- provenance
def test_payee_display_never_carries_legal_name_or_injection():
    """payee_display is built from nickname + last4 only — never legal_name (a
    stored third-party field) and never biller reference_text (the injection
    carrier biller_07.reference_text). This is the one surface the user trusts."""
    plan = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(5000),
        ),
    ])
    res = resolve(plan, transcript="pay mom fifty", user_id="u_alice")
    assert isinstance(res, Resolved)
    display = res.plan.plan[0].payee_display
    # the last4 ("3310") is intentionally part of the safe display (nickname + last4).
    # forbidden: the legal_name, and any biller reference_text injection payload.
    for forbidden in ("Jane Tan", "ignore previous instructions", "123-456", "Acct 88231"):
        assert forbidden not in display
    assert display == "Mom ··3310"


def test_pay_bill_resolves_biller_without_reference_text():
    """PAY_BILL matches billers.name; biller_display is the name only, never the
    injection-carrying reference_text (biller_07)."""
    plan = IntentPlan(plan=[
        PayBillIntent(
            id="t1", type="PAY_BILL",
            source_account=_mention("savings"), target=_mention("CityGas"),
            amount=_lit(8000),
        ),
    ])
    res = resolve(plan, transcript="pay the citygas bill eighty dollars", user_id="u_alice")
    assert isinstance(res, Resolved)
    leg = res.plan.plan[0]
    assert leg.type == "PAY_BILL"
    assert leg.biller_id == "biller_07"
    assert leg.biller_display == "CityGas"           # name only; reference_text absent
    for forbidden in ("ignore previous instructions", "123-456", "Acct 88231"):
        assert forbidden not in leg.biller_display
