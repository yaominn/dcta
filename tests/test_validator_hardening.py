"""
WorkPlan "Improve review and refusal", group A — the validator and resolver
stop letting a wrong amount or account through.

Reproduced before this change:
  - "pay mom five hundred to account 123-456": the validator read $500, $123
    and $456, so a draft paying $123 PASSED.
  - "pay mom 50 no wait 500": both $50 and $500 passed; nothing asked.
  - "send mom 20 from my spending account" debiting SAVINGS passed, with a
    soft warning nobody saw.
  - "pay mom 50 from my savings" became a bill payment (prompt gap).

Pinned here:
  1. Numbers that are not money are not amounts: account references, long
     digit runs, times, dates, share counts, percentages, a pronoun "one".
  2. Competing amounts are ASKED, and the answer must be one the user said.
  3. A NAMED account that the draft doesn't debit is a hard failure; an
     unnamed one stays the soft default.
  4. The parser is told the recipient, not the verb, decides the type.
"""
from __future__ import annotations

import contextlib
import io
import tempfile
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import hash_transcript
from backend.audit.log import AuditLog
from backend.data.seed import seed
from backend.models.schemas import (IntentPlan, LiteralAmount, MentionTarget, ResolvedPlan,
                                    ResolvedTransfer, TransferIntent)
from backend.resolver import Clarify, Resolved, resolve
from backend.validator import competing_amounts, validate
from backend.validator.amounts import extract_literal_cents

ACCT = {"savings": "acct_savings", "spending": "acct_joint"}
PAYEE = {"mom": ("payee_17", "Mom ··3310"), "john": ("payee_21", "John ··4521"),
         "landlord": ("payee_30", "Landlord ··7001")}


@pytest.fixture(autouse=True)
def _ledger():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    yield
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _intent(*legs):
    """legs: (payee, cents, source mention)."""
    return IntentPlan(plan=[
        TransferIntent(id=f"t{i}", type="TRANSFER",
                       source_account=MentionTarget(mention=src),
                       target=MentionTarget(mention=payee),
                       amount=LiteralAmount(literal_cents=cents))
        for i, (payee, cents, src) in enumerate(legs, 1)])


def _validate(transcript, *legs, intent_cents=None, answers=None):
    """legs: (payee, cents, source account id). `intent_cents` overrides the
    parser's literal per leg (the parser picked one of two amounts)."""
    now = int(time.time())
    cents = intent_cents or [c for _, c, _ in legs]
    intent = _intent(*[(p, ic, "default") for (p, _, _), ic in zip(legs, cents)])
    plan = ResolvedPlan(
        draft_id=f"h{time.time_ns()}", transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
        plan=[ResolvedTransfer(id=f"t{i}", type="TRANSFER", source_account=acct,
                               payee_id=PAYEE[p][0], payee_display=PAYEE[p][1],
                               amount_cents=c)
              for i, (p, c, acct) in enumerate(legs, 1)])
    return validate(intent, plan, transcript, audit=AuditLog(Path(tempfile.mkdtemp()) / "a.db"),
                    answers=answers)


def _failed(report, check):
    return [c for c in report.checks if c["check"] == check and c["outcome"] == "fail"]


# --------------------------------------------------------------------------- 1. not money
@pytest.mark.parametrize("text,amounts", [
    ("pay mom five hundred to account 123-456", {50000}),
    ("pay mom 500 acct no 55512345", {50000}),
    ("send 50 to account number one two three four", {5000}),
    ("pay mom 50 at 3 pm", {5000}),
    ("pay mom fifty at five pm", {5000}),
    ("buy 10 shares of apple with 500", {50000}),
    ("pay mom 50 on 25 september", {5000}),
    ("pay mom 50 in 5 days", {5000}),
    ("pay mom 50 with 5% off", {5000}),
    ("send mom 20 from the blue one", {2000}),
    ("send 2500000", set()),                         # 7+ bare digits: a reference
    ("$1234567", {123456700}),                        # ...unless it's marked as money
    ("pay mom one dollar", {100}),                    # "one" WITH a money word is money
])
def test_numbers_that_are_not_money_are_not_amounts(text, amounts):
    assert extract_literal_cents(text) == amounts


def test_the_workplan_reproduction_now_freezes():
    """$123 from "123-456" no longer passes; the $500 the user said still does."""
    t = "pay mom five hundred to account 123-456"
    assert _failed(_validate(t, ("mom", 12300, "acct_savings")), "amount")
    assert not _failed(_validate(t, ("mom", 50000, "acct_savings")), "amount")


# --------------------------------------------------------------------------- 2. competing amounts
def test_two_amounts_for_one_payment_are_competing():
    assert competing_amounts(_intent(("mom", 5000, "default")).plan,
                             "pay mom 50 no wait 500") == {"t1": [5000, 50000]}


@pytest.mark.parametrize("transcript,legs", [
    ("pay mom 50 and john 20", [("mom", 5000, "default"), ("john", 2000, "default")]),
    ("pay mom 50 then pay john 20", [("mom", 5000, "default"), ("john", 2000, "default")]),
    ("pay mom 50 at 3 pm", [("mom", 5000, "default")]),
])
def test_as_many_amounts_as_payments_is_not_competing(transcript, legs):
    assert competing_amounts(_intent(*legs).plan, transcript) == {}


def test_the_resolver_asks_which_amount():
    out = resolve(_intent(("mom", 5000, "default")), transcript="pay mom 50 no wait 500",
                  user_id="u_alice")
    assert isinstance(out, Clarify) and out.kind == "amount" and out.field == "t1.amount"
    assert out.question == "Did you mean $50.00 or $500.00?"
    assert [c["id"] for c in out.choices] == ["5000", "50000"]


def test_the_answer_becomes_the_amount_paid():
    out = resolve(_intent(("mom", 5000, "default")), transcript="pay mom 50 no wait 500",
                  user_id="u_alice", answers={"t1.amount": "50000"})
    assert isinstance(out, Resolved)
    assert out.plan.plan[0].amount_cents == 50000


def test_the_validator_decides_competing_amounts_itself():
    """Handed the PARSER's intent ($50) and a draft paying $500: it passes only
    with the user's recorded answer — the validator reads it itself, instead of
    trusting a resolver-rewritten intent."""
    t = "pay mom 50 no wait 500"
    confirmed = _validate(t, ("mom", 50000, "acct_savings"), intent_cents=[5000],
                          answers={"t1.amount": "50000"})
    unconfirmed = _validate(t, ("mom", 5000, "acct_savings"))
    assert not _failed(confirmed, "amount"), confirmed.checks
    fail = _failed(unconfirmed, "amount")
    assert fail and "no choice between them was confirmed" in fail[0]["detail"]


@pytest.mark.parametrize("answer", ["12300", "999999", "fifty", "", "²", "050000"])
def test_an_answer_the_user_never_said_is_refused(answer):
    """An answer narrows the choice; it can never introduce a new amount."""
    out = resolve(_intent(("mom", 5000, "default")), transcript="pay mom 50 no wait 500",
                  user_id="u_alice", answers={"t1.amount": answer})
    assert isinstance(out, Clarify) and out.kind == "amount"


def test_the_whole_round_trip_over_http():
    """The pipeline asks, the user picks $500, and the draft that comes back is
    $500 and passes the validator — the answered amount is what gets checked."""
    from backend.main import app
    c = TestClient(app)
    # Phrased for the offline stub parser, which the suite runs on. The live
    # model (GPT) also asks for "no wait" / "actually" / "sorry" corrections.
    d = c.post("/api/drafts", json={"transcript": "transfer 500 to mom not 50"}).json()
    assert d["status"] == "clarify" and d["field"] == "t1.amount", d
    d = c.post(f"/api/drafts/{d['draft_id']}/clarify",
               json={"field": "t1.amount", "choice_id": "50000"}).json()
    assert d["status"] == "ready", d
    assert d["resolved_plan"]["plan"][0]["amount_cents"] == 50000
    assert d["validation"]["verdict"] == "pass"


# --------------------------------------------------------------------------- 3. named account
def test_a_named_account_the_draft_does_not_use_freezes():
    r = _validate("send mom 20 from my spending account", ("mom", 2000, "acct_savings"))
    fails = _failed(r, "source_account")
    assert r.frozen and fails
    assert "you said 'spending'" in fails[0]["detail"]


def test_the_named_account_passes_when_used():
    r = _validate("send mom 20 from my spending account", ("mom", 2000, "acct_joint"))
    assert not _failed(r, "source_account")


def test_no_named_account_keeps_the_soft_default():
    """Savings as the default is legitimate: not a hard failure."""
    for t in ("send mom 20", "pay mom 20 for her savings"):     # "her savings" names nothing
        assert not _failed(_validate(t, ("mom", 2000, "acct_savings")), "source_account"), t


def test_each_payment_is_held_to_its_own_named_account():
    t = "pay mom 50 from savings then pay john 20 from my spending account"
    ok = _validate(t, ("mom", 5000, "acct_savings"), ("john", 2000, "acct_joint"))
    wrong = _validate(t, ("mom", 5000, "acct_savings"), ("john", 2000, "acct_savings"))
    assert not _failed(ok, "source_account")
    assert [c["leg"] for c in _failed(wrong, "source_account")] == ["t2"]


# --------------------------------------------------------------------------- 4. action
def test_the_parser_is_told_the_recipient_decides_the_type():
    from backend.agent import prompts
    system = prompts._SYSTEM
    assert "the VERB does not decide it, the RECIPIENT does" in system
    assert '"pay mom 50"' in system and "PAYEES" in system and "BILLERS" in system


# --------------------------------------------------------------------------- review findings
def test_a_number_after_account_that_is_not_account_shaped_stays_money():
    """Blanking "account five" left "hundred" = $100 — a tampered $100 passed."""
    t = "pay mom from my savings account five hundred"
    assert extract_literal_cents(t) == {50000}
    assert _failed(_validate(t, ("mom", 10000, "acct_savings")), "amount")
    assert extract_literal_cents("from my spending account 500 to mom") == {50000}


@pytest.mark.parametrize("text,cents", [
    ("send 20 jan", 2000), ("pay john 30 marbles", 3000), ("pay mom 20 may i add", 2000)])
def test_only_real_dates_are_masked(text, cents):
    assert cents in extract_literal_cents(text)


@pytest.mark.parametrize("transcript,legs", [
    ("pay mom 50 and john 20 then pay landlord 100",
     [("mom", 5000, "default"), ("john", 2000, "default"), ("landlord", 10000, "default")]),
    ("pay mom 50 and john 20 ", [("mom", 5000, "default"), ("john", 2000, "default")]),
    ("pay mom 50 for 2 tickets", [("mom", 5000, "default")]),
    ("pay mom 50 dollars and 25 cents", [("mom", 5025, "default")]),
])
def test_ordinary_requests_get_no_amount_question(transcript, legs):
    assert competing_amounts(_intent(*legs).plan, transcript) == {}


def test_a_single_payments_account_can_be_named_in_its_own_clause():
    t = "pay mom 50 then take it from my spending account"
    assert _failed(_validate(t, ("mom", 5000, "acct_savings")), "source_account")
    assert not _failed(_validate(t, ("mom", 5000, "acct_joint")), "source_account")


def test_the_recipients_account_is_not_the_source():
    """"into her savings account" is where the money goes."""
    assert not _failed(_validate("send mom 50 into her savings account",
                                 ("mom", 5000, "acct_joint")), "source_account")
    t = "send mom 50 from my spending account to mom's savings account"
    assert not _failed(_validate(t, ("mom", 5000, "acct_joint")), "source_account")
    assert _failed(_validate(t, ("mom", 5000, "acct_savings")), "source_account")


# --------------------------------------------------------------------------- review findings, round 2
@pytest.mark.parametrize("transcript", [
    "pay mom 50 because I owe her, no wait 500",
    "pay mom 50 tomorrow, hmm, 500",
    "send mom 50 at noon, actually 500",
    "pay mom fifty, uh, five hundred",
])
def test_a_correction_with_words_in_between_is_still_caught(transcript):
    assert competing_amounts(_intent(("mom", 5000, "default")).plan, transcript) == \
        {"t1": [5000, 50000]}


def test_the_same_figure_said_twice_then_corrected_is_caught():
    """20, 20, then 30: three figures for two payments. Shared clause, so the
    user is asked to say it again rather than offered amounts."""
    got = competing_amounts(_intent(("mom", 2000, "default"), ("john", 2000, "default")).plan,
                            "pay mom 20 and john 20 wait no 30")
    assert got == {"t1": [], "t2": []}


def test_a_question_never_offers_another_payments_amount():
    """mom's correction must not become john's menu: with several payments in
    one clause the answer would WIDEN the choice, so it asks to say it again."""
    legs = _intent(("mom", 5000, "default"), ("john", 2000, "default"))
    got = competing_amounts(legs.plan, "pay mom 50 no wait 500 and john 20")
    assert all(offered == [] for offered in got.values())
    out = resolve(legs, transcript="pay mom 50 no wait 500 and john 20", user_id="u_alice")
    assert isinstance(out, Clarify) and out.kind == "restate" and out.choices == []


def test_say_it_again_can_never_pass_the_validator():
    r = _validate("pay mom 50 no wait 500 and john 20",
                  ("mom", 5000, "acct_savings"), ("john", 2000, "acct_savings"))
    assert r.frozen and _failed(r, "amount")


@pytest.mark.parametrize("transcript,cents", [
    ("pay mom fifty dollars and twenty five cents", 5025),
    ("pay mom 50 dollars and twenty five cents", 5025),
    ("pay mom 50 dollars 25 cents", 5025),
])
def test_dollars_and_cents_is_one_amount_and_payable(transcript, cents):
    assert extract_literal_cents(transcript) == {cents}
    assert competing_amounts(_intent(("mom", cents, "default")).plan, transcript) == {}
    assert not _failed(_validate(transcript, ("mom", cents, "acct_savings")), "amount")


@pytest.mark.parametrize("transcript", [
    "pay landlord 500, he has a savings account",
    "pay mom 50, she wants it for a savings account",
    "send mom 50 into her savings account",
])
def test_mentioning_an_account_is_not_naming_the_source(transcript):
    """A hard freeze needs unmistakable source phrasing; these are not."""
    payee = "landlord" if "landlord" in transcript else "mom"
    r = _validate(transcript, (payee, 50000 if payee == "landlord" else 5000, "acct_joint"))
    assert not _failed(r, "source_account"), r.checks


def test_use_my_account_names_the_source():
    t = "I want to use my savings account to pay mom 50"
    assert _failed(_validate(t, ("mom", 5000, "acct_joint")), "source_account")
    assert not _failed(_validate(t, ("mom", 5000, "acct_savings")), "source_account")


def test_a_bill_named_after_an_account_does_not_hide_the_real_source():
    t = "pay mom 50 from my spending account for the savings account fees"
    assert _failed(_validate(t, ("mom", 5000, "acct_savings")), "source_account")


@pytest.mark.parametrize("transcript", ["transfer 100 to mom for room 204",
                                        "pay landlord 1500 for unit 12"])
def test_reference_numbers_are_not_amounts(transcript):
    assert len(extract_literal_cents(transcript)) == 1


def test_a_large_amount_with_a_money_word_is_not_an_account_number():
    assert extract_literal_cents("pay mom 1000000 dollars") == {100000000}


@pytest.mark.parametrize("transcript", ["send john one", "pay mom one, please"])
def test_a_bare_one_is_one_dollar_when_nothing_else_is(transcript):
    assert extract_literal_cents(transcript) == {100}


# --------------------------------------------------------------------------- review findings, round 3
def test_a_label_mask_never_cuts_a_spoken_amount_in_half():
    """"unit 5" was blanked and the leftover "hundred" read as $100."""
    t = "pay the landlord for unit 5 hundred dollars"
    assert extract_literal_cents(t) == {50000}
    assert _failed(_validate(t, ("landlord", 10000, "acct_savings")), "amount")
    assert not _failed(_validate(t, ("landlord", 50000, "acct_savings")), "amount")


@pytest.mark.parametrize("text,cents", [
    ("pay the invoice 250 dollars to john", 25000), ("ticket 20 dollars to mom", 2000),
    ("#5 hundred to john", 50000), ("order 5 thousand to mom", 500000)])
def test_a_labelled_number_with_a_money_word_stays_money(text, cents):
    assert cents in extract_literal_cents(text)


def test_a_correction_in_its_own_clause_is_asked_and_honoured():
    t = "pay mom 50 then actually make it 500"
    assert competing_amounts(_intent(("mom", 5000, "default")).plan, t) == {"t1": [5000, 50000]}
    confirmed = _validate(t, ("mom", 50000, "acct_savings"), intent_cents=[5000],
                          answers={"t1.amount": "50000"})
    assert not _failed(confirmed, "amount"), confirmed.checks
    assert _failed(_validate(t, ("mom", 5000, "acct_savings")), "amount")


def test_no_rush_is_not_a_correction():
    assert competing_amounts(_intent(("mom", 5000, "default")).plan,
                             "pay mom 50 for 2 tickets, no rush") == {}


@pytest.mark.parametrize("transcript", ["pay mom 50 to help with savings",
                                        "pay mom 50 from the investment club"])
def test_loose_account_words_do_not_hard_freeze(transcript):
    assert not _failed(_validate(transcript, ("mom", 5000, "acct_joint")), "source_account")


def test_from_the_savings_account_names_the_source():
    t = "pay mom 50 from the savings account"
    assert _failed(_validate(t, ("mom", 5000, "acct_joint")), "source_account")


def test_one_dollar_joined_by_and_is_kept():
    t = "pay john 50 and one to mom"
    assert extract_literal_cents(t) == {5000, 100}
    assert not _failed(_validate(t, ("john", 5000, "acct_savings"), ("mom", 100, "acct_savings")),
                       "amount")


def test_api_validate_uses_the_servers_record_of_the_answers():
    """The pipeline and /api/validate must agree — and /api/validate must not
    take answers from its caller."""
    from backend.main import _drafts, app
    c = TestClient(app)
    d = c.post("/api/drafts", json={"transcript": "transfer 500 to mom not 50"}).json()
    d = c.post(f"/api/drafts/{d['draft_id']}/clarify",
               json={"field": "t1.amount", "choice_id": "50000"}).json()
    assert d["status"] == "ready", d
    stored = _drafts.get(d["draft_id"])
    body = {"intent_plan": stored.intent_plan, "resolved_plan": d["resolved_plan"],
            "transcript": stored.transcript}
    assert c.post("/api/validate", json=body).json()["verdict"] == "pass"

    forged = dict(body, resolved_plan=dict(d["resolved_plan"], draft_id="not-a-real-draft"))
    assert c.post("/api/validate", json=forged).json()["frozen"] is True


# --------------------------------------------------------------------------- review findings, round 4
def test_one_after_a_name_is_a_dollar():
    t = "pay mom 50 and john one"
    assert extract_literal_cents(t) == {5000, 100}
    assert extract_literal_cents("send mom 20 from the blue one") == {2000}   # still a pronoun


def test_a_fare_after_bus_is_money():
    assert extract_literal_cents("pay john for the bus 20") == {2000}


def test_repeating_the_same_figure_is_not_a_choice():
    for t in ("pay mom 50 dollars, yes 50", "pay mom 50, I said 50"):
        assert competing_amounts(_intent(("mom", 5000, "default")).plan, t) == {}, t
    assert competing_amounts(_intent(("mom", 2000, "default"), ("john", 2000, "default")).plan,
                             "pay mom 20 and john 20 wait no 30")      # 20, 20, 30: still asked
