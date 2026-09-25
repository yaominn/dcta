"""
Demo balances, the "Spending" account, and the drop-down notification.

The demo presents the joint account as the everyday "Spending" account, so the
words on screen must work when spoken: "from my spending account" must debit
it — in the resolver, in the offline stub parser, and without a spurious
validator warning. The page shows balances read from the ledger and, after a
payment, a notification listing only the legs that actually ran.

The full visible flow — panel, notification, balance change, and the spending
sentence — is proven in a real browser by tests/test_e2e_webauthn.py.
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

from backend.agent.stub import _find_source_account
from backend.audit.canonical import hash_transcript
from backend.audit.log import AuditLog
from backend.data.seed import seed
from backend.models.schemas import (IntentPlan, LiteralAmount, MentionTarget,
                                    ResolvedPlan, ResolvedTransfer, TransferIntent)
from backend.resolver import Resolved, resolve
from backend.validator import validate

REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def _ledger():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    yield
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _intent(source_mention: str, cents=2000):
    return IntentPlan(plan=[TransferIntent(
        id="t1", type="TRANSFER", source_account=MentionTarget(mention=source_mention),
        target=MentionTarget(mention="mom"), amount=LiteralAmount(literal_cents=cents))])


# --------------------------------------------------------------------------- the Spending account
@pytest.mark.parametrize("mention", ["spending", "my spending account", "everyday", "joint"])
def test_spending_resolves_to_the_joint_account(mention):
    res = resolve(_intent(mention), transcript=f"send mom 20 from {mention}", user_id="u_alice")
    assert isinstance(res, Resolved), res
    assert res.plan.plan[0].source_account == "acct_joint"


def test_saying_nothing_still_means_savings():
    res = resolve(_intent("default"), transcript="send mom 20", user_id="u_alice")
    assert res.plan.plan[0].source_account == "acct_savings"


@pytest.mark.parametrize("clause,expected", [
    ("send mom 20 from my spending account", "my spending account"),
    ("transfer five hundred from my savings to mom", "savings"),
    ("pay mom 50 from joint", "joint"),
    ("pay mom 50", "default"),
    ("pay mom 50 from the moon", "default"),     # not an account: unchanged
])
def test_the_offline_stub_passes_a_named_account_through(clause, expected):
    assert _find_source_account(clause, ["savings", "joint", "settlement"]) == expected


def test_the_validator_does_not_warn_about_spending(tmp_path):
    transcript = "send mom 20 from my spending account"
    now = int(time.time())
    plan = ResolvedPlan(
        draft_id="spend", transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_joint",
                               payee_id="payee_17", payee_display="Mom ··3310",
                               amount_cents=2000)])
    report = validate(_intent("spending"), plan, transcript, audit=AuditLog(tmp_path / "a.db"))
    source = [c for c in report.soft_signals if c["check"] == "source_account"]
    assert source and source[0]["outcome"] == "pass", source


# --------------------------------------------------------------------------- the page's pure helpers
@pytest.fixture(scope="module")
def page():
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    out = subprocess.run(["node", str(REPO / "tests" / "js" / "app_runner.js")],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def test_account_labels(page):
    assert page["labels"] == ["Savings", "Spending", "Investments", "Other", "weird"]


def test_the_notification_lists_only_legs_that_ran(page):
    """A failed leg never appears as sent."""
    assert page["lines"] == [
        "$50.00 to Mom ··3310 · from Spending",
        "$123.45 to SP Group · from Savings",
    ]


# --------------------------------------------------------------------------- review fixes
def test_a_partly_run_payment_is_announced_as_partial(page):
    """Money moved on 2 of 3 legs (overall status FAILED): the notification
    must still appear, say it was partial, and list only what ran."""
    assert page["partial"]["title"] == "2 of 3 payments sent"
    assert len(page["partial"]["lines"]) == 2


def test_nothing_ran_means_no_notification(page):
    assert page["noneRan"] == {"title": "", "lines": []}


def test_single_payment_and_contact_titles(page):
    assert page["single"]["title"] == "Transfer successful"
    assert page["contact"] == {"title": "Contact updated",
                               "lines": ["John ··8892 · name → Johnny"]}


@pytest.mark.parametrize("clause,expected", [
    ("pay mom 50 from my account", "default"),          # names nothing: still savings
    ("buy AAPL 100 from invest", "invest"),             # a resolver synonym passes through
    ("pay mom 50 from my saving account", "my saving account"),
])
def test_the_stub_uses_the_resolvers_own_account_words(clause, expected):
    assert _find_source_account(clause, ["savings", "joint", "settlement"]) == expected


def test_saving_resolves_to_savings():
    res = resolve(_intent("my saving account"), transcript="x", user_id="u_alice")
    assert res.plan.plan[0].source_account == "acct_savings"


def test_account_questions_use_the_names_the_page_shows():
    """The clarify choices must call the joint account "Spending", like the
    balance panel — not the raw type."""
    from backend.resolver import Clarify
    res = resolve(_intent("the blue one"), transcript="send mom 20 from the blue one",
                  user_id="u_alice")
    assert isinstance(res, Clarify), res
    labels = " ".join(c["display"] for c in res.choices)
    assert "Spending (" in labels and "Savings (" in labels, labels
    assert "joint (" not in labels


def test_invest_as_a_verb_does_not_satisfy_the_source_account_tripwire(tmp_path):
    """"invest $100 in apple" names no account; if the model debits the
    investment account anyway, the soft check must still warn."""
    transcript = "invest 100 in apple"
    now = int(time.time())
    plan = ResolvedPlan(
        draft_id="tripwire", transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_invest",
                               payee_id="payee_17", payee_display="Mom ··3310",
                               amount_cents=10000)])
    report = validate(_intent("default", 10000), plan, transcript,
                      audit=AuditLog(tmp_path / "a.db"))
    source = [c for c in report.soft_signals if c["check"] == "source_account"]
    assert source and source[0]["outcome"] == "warn", source


# --------------------------------------------------------------------------- second review
@pytest.mark.parametrize("mention,account", [
    ("my everyday spending account", "acct_joint"),     # both words -> the same account
    ("my saving savings account", "acct_savings"),
])
def test_several_words_for_the_same_account_resolve(mention, account):
    res = resolve(_intent(mention), transcript="x", user_id="u_alice")
    assert isinstance(res, Resolved), res
    assert res.plan.plan[0].source_account == account


def test_words_naming_different_accounts_ask_rather_than_guess():
    from backend.resolver import Clarify
    res = resolve(_intent("joint savings"), transcript="x", user_id="u_alice")
    assert isinstance(res, Clarify)


def test_the_phone_message_uses_the_same_account_names():
    """The out-of-band confirmation describes the payment from the server's
    copy — it must say Spending, as the card and the panel do."""
    from backend.display import account_label, plan_summary
    assert account_label("acct_joint") == "Spending"
    assert account_label("acct_invest") == "Investments"
    now = int(time.time())
    plan = ResolvedPlan(
        draft_id="phone", transcript_hash=hash_transcript("x"), created_at=now,
        expires_at=now + 300,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_joint",
                               payee_id="payee_17", payee_display="Mom ··3310",
                               amount_cents=2000)])
    assert "from Spending" in plan_summary(plan)
