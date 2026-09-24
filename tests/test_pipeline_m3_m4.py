"""
M3 -> M4 seam test: the real parser's output, fed to the real resolver.

Every case in tests/test_resolver.py builds its IntentPlan BY HAND. That is
useful (it isolates the resolver) but it left the seam between the two
milestones completely untested — and that is exactly where the bug was.
backend/agent/prompts.py instructs the model to emit
`source_account: {"mention": "default"}` when the user names no account, the
resolver had no rule for "default", and so every README demo sentence
dead-ended in a clarification while 153 tests stayed green.

These tests run the actual parser (stub provider — no credentials, no network)
into the actual resolver, for the transcripts the demo script uses. They are
deliberately end-to-end-ish: if either side changes its half of the contract,
this file goes red.
"""
from __future__ import annotations

import pytest

from backend.agent import build_context, get_provider, parse_transcript
from backend.config import settings
from backend.data.db import connect
from backend.data.seed import seed
from backend.resolver import Clarify, Resolved, resolve


@pytest.fixture(scope="module")
def ledger(tmp_path_factory):
    """An isolated seeded ledger, so the suite never touches the dev's DB."""
    db = tmp_path_factory.mktemp("pipeline") / "ledger.db"
    seed(db)
    return db


@pytest.fixture(scope="module")
def context(ledger):
    """The sanitized prompt context, built exactly as main.py builds it."""
    conn = connect(ledger)
    try:
        return build_context(
            payees=[dict(r) for r in conn.execute(
                "SELECT * FROM payees WHERE user_id='u_alice'")],
            billers=[dict(r) for r in conn.execute("SELECT * FROM billers")],
            accounts=[dict(r) for r in conn.execute(
                "SELECT * FROM accounts WHERE user_id='u_alice'")],
            equities=[dict(r) for r in conn.execute("SELECT * FROM equities")],
        )
    finally:
        conn.close()


def _run(transcript: str, context, ledger):
    plan = parse_transcript(transcript, provider=get_provider(settings), context=context)
    return plan, resolve(plan, transcript=transcript, user_id="u_alice", db_path=ledger)


def test_headline_transcript_resolves_end_to_end(context, ledger):
    """The README's own demo sentence, start to finish: parser -> resolver ->
    a signable two-leg plan with the Section 13 arithmetic."""
    plan, res = _run("pay mom five hundred then buy aapl with the rest", context, ledger)
    # the parser really does emit the "default" account mention — pin that, so
    # this test documents WHY the resolver needs a default rule
    assert plan.plan[0].source_account.mention == "default"

    assert isinstance(res, Resolved), getattr(res, "question", res)
    t1, t2 = res.plan.plan
    assert (t1.type, t1.payee_id, t1.amount_cents) == ("TRANSFER", "payee_17", 50000)
    assert t1.source_account == "acct_savings"          # the documented default
    assert (t2.type, t2.ticker, t2.estimated_shares) == ("BUY_EQUITY", "AAPL", 32)
    assert t2.amount_cents == 772800                    # the spend
    assert 842050 - 50000 - 772800 == 19250             # remainder stays put


@pytest.mark.parametrize("transcript", [
    "pay mom five hundred then buy aapl with the rest",
    "transfer five hundred to mom then buy apple with the rest",
    "pay the citygas bill eighty dollars",
    "move two hundred from my savings account to mom",
    "send five hundred to mom",
])
def test_demo_transcripts_do_not_dead_end(transcript, context, ledger):
    """No demo sentence may come back as an account question. Before the default
    rule every one of these did."""
    _, res = _run(transcript, context, ledger)
    assert isinstance(res, Resolved), (
        f"{transcript!r} did not resolve: {getattr(res, 'question', res)}"
    )


def test_ambiguous_transcript_asks_an_answerable_question(context, ledger):
    """Demo scenario 2. The two seeded Johns must produce a question the user can
    answer in one round-trip — a question with no choices is an infinite loop."""
    plan, res = _run("send fifty to john", context, ledger)
    assert isinstance(res, Clarify)
    assert res.kind == "payee"
    assert {c["id"] for c in res.choices} == {"payee_21", "payee_22"}
    assert "4521" in res.question and "8892" in res.question

    resumed = resolve(plan, transcript="send fifty to john", user_id="u_alice",
                      db_path=ledger, answers={res.field: "payee_21"})
    assert isinstance(resumed, Resolved)
    assert resumed.plan.plan[0].payee_id == "payee_21"


def test_pipeline_never_leaks_the_seeded_injection(context, ledger):
    """biller_07.reference_text carries a live injection. It must not reach the
    prompt (M3) nor any displayed/signed field (M4)."""
    plan, res = _run("pay the citygas bill eighty dollars", context, ledger)
    assert isinstance(res, Resolved)
    leg = res.plan.plan[0]
    assert leg.biller_display == "CityGas"
    for forbidden in ("ignore previous instructions", "123-456", "Acct 88231"):
        assert forbidden not in res.plan.model_dump_json()
