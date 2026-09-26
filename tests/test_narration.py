"""
The assistant's reply and the review card's evidence (backend/narrate.py).

The reply is what makes the draft read like an assistant rather than a form:
what it worked out that the user did not say — the usual amount for this
person, what's left afterwards, a defaulted account, a calculated amount, why
an extra check is needed. The evidence shows where each field came from.

Pinned here:
  - every figure in the reply is the plan's or the ledger's (it can never
    disagree with the card) and it is NOT model text;
  - quotes are cut from the TRANSCRIPT, not the parser's mention — a field
    whose words are not in the transcript is reported, never papered over;
  - the notes: first payment / in line / more / less / Nx usual, the default
    account, a calculated amount, a chosen amount, balances after, the check;
  - the API returns it for a READY draft only, with the server's transcript;
  - the page's evidence line (run under Node).
"""
from __future__ import annotations

import contextlib
import io
import json
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import hash_transcript
from backend.data.seed import seed
from backend.models.schemas import (AmountOp, BuyEquityIntent, IntentPlan, LiteralAmount,
                                    MentionTarget, ResolvedBuyEquity, ResolvedPlan,
                                    ResolvedTransfer, SymbolicAmount, TransferIntent)
from backend.narrate import narrate

REPO = Path(__file__).resolve().parents[1]
ACCOUNTS = {"acct_savings": {"type": "savings", "balance": 842050},
            "acct_joint": {"type": "joint", "balance": 120000},
            "acct_invest": {"type": "settlement", "balance": 0}}
MOM_HISTORY = [{"payee_id": "payee_17", "amount": 50000}] * 6
ACCT = {"savings": "acct_savings", "spending": "acct_joint"}


def _transfer(transcript, cents, *, mention="mom", source_mention="default",
              acct="acct_savings", payee=("payee_17", "Mom ··3310"), history=MOM_HISTORY,
              answers=None, extra_check=False, draft_id="d-narrate"):
    intent = IntentPlan(plan=[TransferIntent(
        id="t1", type="TRANSFER", source_account=MentionTarget(mention=source_mention),
        target=MentionTarget(mention=mention), amount=LiteralAmount(literal_cents=cents))])
    now = int(time.time())
    plan = ResolvedPlan(
        draft_id=draft_id, transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account=acct,
                               payee_id=payee[0], payee_display=payee[1],
                               amount_cents=cents if not answers else int(answers["t1.amount"]))])
    return narrate(intent, plan, transcript, accounts=ACCOUNTS, history=history,
                   answers=answers, extra_check=extra_check)


# --------------------------------------------------------------------------- the reply
def test_a_simple_payment_reads_like_an_assistant():
    out = _transfer("pay mom 50 dollars", 5000)
    reply = out["reply"]
    assert "$50.00 to Mom from your Savings account" in reply
    assert "less than you usually send Mom ($500.00)" in reply          # worked out
    assert "You didn't say which account, so I've used Savings" in reply  # filled in
    assert "cancel and ask again with the account" in reply              # a real way to change it
    assert "You'll have $8,370.50 in Savings left afterwards" in reply     # worked out


@pytest.mark.parametrize("cents,phrase", [
    (50000, "in line with what you usually send Mom"),
    (120000, "more than you usually send Mom ($500.00)"),
    (10000, "less than you usually send Mom ($500.00)"),
    (500000, "about 10× what you usually send Mom ($500.00)"),
])
def test_the_comparison_with_what_you_usually_send(cents, phrase):
    assert phrase in _transfer("pay mom some money", cents)["reply"]


def test_a_first_payment_says_so():
    out = _transfer("pay landlord 800", 80000, mention="landlord",
                    payee=("payee_30", "Landlord ··7001"), history=[])
    assert "It's your first payment to Landlord." in out["reply"]


def test_a_named_account_is_not_called_a_default():
    out = _transfer("send mom 20 from my spending account", 2000,
                    source_mention="spending", acct="acct_joint")
    assert "from your Spending account" in out["reply"]
    assert "didn't say which account" not in out["reply"]
    assert "$1,180.00 in Spending" in out["reply"]
    assert out["evidence"]["t1"]["from"] == {"kind": "said", "quote": "spending"}


def test_the_extra_check_gives_the_real_reason():
    far = _transfer("pay mom 5000", 500000, extra_check=True)
    assert "Because that's far more than you usually send Mom, I've texted a code" in far["reply"]
    first = _transfer("pay landlord 800", 80000, mention="landlord", extra_check=True,
                      payee=("payee_30", "Landlord ··7001"), history=[])
    assert "Because it's your first payment to Landlord, I've texted a code" in first["reply"]


def test_a_chosen_amount_says_what_was_chosen():
    out = _transfer("pay mom 50 no wait 500", 5000, answers={"t1.amount": "50000"})
    assert "You mentioned $50.00 and $500.00, and chose $500.00." in out["reply"]
    assert out["evidence"]["t1"]["amount"]["kind"] == "chosen"
    assert out["evidence"]["t1"]["amount"]["quote"] == "500"


def test_a_calculated_amount_and_two_payments():
    transcript = "pay mom five hundred then buy apple with the rest"
    intent = IntentPlan(plan=[
        TransferIntent(id="t1", type="TRANSFER", source_account=MentionTarget(mention="default"),
                       target=MentionTarget(mention="mom"), amount=LiteralAmount(literal_cents=50000)),
        BuyEquityIntent(id="t2", type="BUY_EQUITY", source_account=MentionTarget(mention="default"),
                        ticker=MentionTarget(mention="apple"),
                        amount=SymbolicAmount(after_leg="t1", op=AmountOp.ALL))])
    now = int(time.time())
    plan = ResolvedPlan(
        draft_id="d-two", transcript_hash=hash_transcript(transcript), created_at=now,
        expires_at=now + 300,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_savings",
                               payee_id="payee_17", payee_display="Mom ··3310", amount_cents=50000),
              ResolvedBuyEquity(id="t2", type="BUY_EQUITY", source_account="acct_savings",
                                ticker="AAPL", amount_cents=772800, estimated_shares=32,
                                estimated_fill_price_cents=24150)])
    out = narrate(intent, plan, transcript, accounts=ACCOUNTS, history=MOM_HISTORY)
    assert "two payments: $500.00 to Mom" in out["reply"]
    assert "about 32 AAPL shares at $241.50 — $7,728.00" in out["reply"]
    assert "$7,728.00 is the rest of what's left in Savings" in out["reply"]
    assert "$192.50 in Savings left afterwards" in out["reply"]
    assert out["evidence"]["t2"]["amount"]["kind"] == "calculated"
    assert out["evidence"]["t2"]["from"]["kind"] == "derived"


def test_every_figure_in_the_reply_comes_from_the_plan_or_the_ledger():
    """The reply can never disagree with the card: its payment amount is the
    RESOLVED amount, even if the parser's literal said something else."""
    out = _transfer("pay mom 50 no wait 500", 5000, answers={"t1.amount": "50000"})
    first_sentence = out["reply"].split(" account.")[0]
    assert first_sentence.endswith("$500.00 to Mom from your Savings")


def test_narration_uses_no_model():
    """Deterministic: the same draft always gets the same reply — and the
    module reaches nothing under backend.agent."""
    import backend.narrate as mod
    source = Path(mod.__file__).read_text()
    assert "backend.agent" not in source and "get_provider" not in source
    assert _transfer("pay mom 50 dollars", 5000) == _transfer("pay mom 50 dollars", 5000)


# --------------------------------------------------------------------------- quotes come from the transcript
def test_quotes_are_the_users_words_in_their_own_casing():
    ev = _transfer("Pay MOM 50 Dollars", 5000)["evidence"]["t1"]
    assert ev["amount"]["quote"] == "50 Dollars"
    assert ev["to"]["quote"] == "MOM"


def test_a_recipient_not_in_the_transcript_is_reported_not_papered_over():
    """The parser said "mom"; the user said "mum". Never quote words they didn't say."""
    ev = _transfer("send mum 50", 5000, mention="mom")["evidence"]["t1"]
    assert ev["to"] == {"kind": "not_found"}


# --------------------------------------------------------------------------- the API
@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    yield TestClient(__import__("backend.main", fromlist=["app"]).app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def test_a_ready_draft_carries_the_reply_and_the_servers_transcript(client):
    d = client.post("/api/drafts", json={"transcript": "pay mom 50 dollars"}).json()
    assert d["status"] == "ready"
    assert d["transcript"] == "pay mom 50 dollars"
    assert "$50.00 to Mom" in d["narration"]["reply"]
    assert d["narration"]["evidence"]["t1"]["to"]["quote"] == "mom"


def test_a_question_carries_no_reply(client):
    d = client.post("/api/drafts", json={"transcript": "pay john 50 dollars"}).json()
    assert d["status"] == "clarify" and "narration" not in d


# --------------------------------------------------------------------------- the card's evidence line
@pytest.fixture(scope="module")
def page():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    out = subprocess.run(["node", str(REPO / "tests" / "js" / "app_runner.js")],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def test_the_card_evidence_line(page):
    assert page["evidence"] == [
        "“50 dollars” · “mom” · Savings by default",
        "you chose “500” · “mom” · “spending”",
        "calculated: the rest of what's left in Savings · “apple” · same account",
        "⚠ amount not in your words · ⚠ recipient not in your words · Savings by default",
        "\u201c50\u201d · \u201cmom\u201d · \u26a0 account not in your words",
        "",
    ]


# --------------------------------------------------------------------------- review findings
def test_an_account_named_in_other_words_is_not_called_a_default():
    """"using spending": the resolver used the named account, so the reply
    must not say it was a default."""
    out = _transfer("send mom 50 using spending", 5000, source_mention="spending", acct="acct_joint")
    assert "didn't say which account" not in out["reply"]
    assert out["evidence"]["t1"]["from"] == {"kind": "said", "quote": "spending"}


def test_the_quoted_account_is_the_one_debited():
    """"from savings, no wait, from spending" — debiting Spending, the card
    must quote "spending", not the first account named."""
    out = _transfer("send mom 50 from savings, no wait, from spending", 5000,
                    source_mention="spending", acct="acct_joint")
    assert out["evidence"]["t1"]["from"] == {"kind": "said", "quote": "spending"}


def test_a_zero_in_the_history_does_not_crash():
    out = _transfer("pay mom 50", 5000, history=[{"payee_id": "payee_17", "amount": 0}])
    assert "$50.00 to Mom" in out["reply"]


def test_the_threshold_is_the_policy_engines(monkeypatch):
    """"N× usual" must follow the rule that triggers the check, not a copy."""
    import backend.narrate as mod
    monkeypatch.setattr(mod, "ANOMALY_MULTIPLE", 5)
    assert "about 6× what you usually send Mom" in _transfer("pay mom 3000", 300000)["reply"]


def test_a_narration_failure_never_breaks_a_draft(client, monkeypatch):
    """Cosmetic: the draft stays ready and signable, with the plain card."""
    import backend.main as main
    def boom(*a, **k):
        raise ZeroDivisionError("simulated")
    monkeypatch.setattr(main, "narrate", boom)
    d = client.post("/api/drafts", json={"transcript": "pay mom 50 dollars"}).json()
    assert d["status"] == "ready" and d["narration"] is None
