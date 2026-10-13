"""
Edge cases found by a sweep of the live app (13 Oct 2026), one section per fix.
Each test names what a user said and what the app must do with it. The stub
provider stands in for the model, as everywhere in the suite.
"""
from __future__ import annotations

import contextlib
import io
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.data.db import get_conn
from backend.data.seed import seed


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _phone, _stopped
    _phone.clear()
    _stopped.clear()
    yield TestClient(__import__("backend.main", fromlist=["app"]).app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _ask(client, text, **extra):
    return client.post("/api/drafts", json={"transcript": text, **extra}).json()


# --------------------------------------------------------------------------- the seed
def test_no_seeded_payment_counts_as_recent(client):
    """A reset stamped a $50 to John and a $500 to Mom at "now": two of the five
    transfers allowed in 10 minutes were used before the demo began, and the
    script's anomaly scene hit the rate limit. Seeded history starts yesterday."""
    conn = get_conn()
    try:
        stamps = [r[0] for r in conn.execute("SELECT ts FROM transaction_history")]
    finally:
        conn.close()
    newest = max(datetime.fromisoformat(s) for s in stamps)
    assert newest <= datetime.now(timezone.utc) - timedelta(hours=23)


def test_after_a_reset_five_payments_fit_in_the_window(client):
    from backend.policy import evaluate, load_context
    from backend.resolver import Resolved, resolve
    from backend.models.schemas import IntentPlan
    plan = IntentPlan.model_validate({"plan": [
        {"id": f"t{i}", "type": "TRANSFER", "source_account": {"mention": "savings"},
         "target": {"mention": "mom"}, "amount": {"literal_cents": 1000}} for i in range(1, 6)]})
    res = resolve(plan, transcript="send mom 10 " * 5, user_id="u_alice")
    assert isinstance(res, Resolved)
    verdicts = evaluate(res.plan, load_context("u_alice"))
    assert [v.rule for v in verdicts.verdicts if v.decision.value == "BLOCK"] == []


def test_an_unverified_customer_reaches_the_kyc_block(client):
    """Bob's KYC is PENDING. He had no account or contact, so the pipeline asked
    "which account?" and never reached the KYC rule. Now it refuses, saying why."""
    r = _ask(client, "send 50 to mom", user_id="u_bob")
    assert r["status"] == "blocked"
    assert [v["rule"] for v in r["policy"]["verdicts"]] == ["kyc"]


# --------------------------------------------------------------------------- names
def _transfer_plan(mention, cents=5000):
    from backend.models.schemas import IntentPlan
    return IntentPlan.model_validate({"plan": [
        {"id": "t1", "type": "TRANSFER", "source_account": {"mention": "default"},
         "target": {"mention": mention}, "amount": {"literal_cents": cents}}]})


@pytest.mark.parametrize("said,payee", [("John Doe", "payee_21"), ("john smith", "payee_22"),
                                        ("Jane Tan", "payee_17")])
def test_a_contact_can_be_named_in_full(client, said, payee):
    """"send 50 to John Doe" said John Doe wasn't a contact and offered to add
    him. The full name picks the contact; the card still shows the nickname."""
    from backend.resolver import Resolved, resolve
    res = resolve(_transfer_plan(said), transcript=f"send 50 to {said}", user_id="u_alice")
    assert isinstance(res, Resolved) and res.plan.plan[0].payee_id == payee
    assert said.lower() not in res.plan.plan[0].payee_display.lower()


def test_the_validator_accepts_the_full_name_the_user_said(client):
    from backend.resolver import resolve
    from backend.validator import validate
    plan = _transfer_plan("John Doe")
    res = resolve(plan, transcript="send 50 to John Doe", user_id="u_alice")
    report = validate(plan, res.plan, "send 50 to John Doe", provider=None)
    assert not report.frozen, report.checks


def test_two_johns_are_told_apart_by_surname(client):
    r = _ask(client, "Send fifty to John")
    assert r["status"] == "clarify"
    assert [c["display"] for c in r["choices"]] == ["John Doe ··4521", "John Smith ··8892"]
    assert r["question"] == "Did you mean John Doe ··4521 or John Smith ··8892?"


def test_a_contact_list_question_still_shows_nicknames(client):
    """Surnames only break a tie between contacts with the same nickname: an
    unknown name's question lists the contacts as the user saved them."""
    r = _ask(client, "send 50 to uncle bob")
    assert "Mom ··3310" in [c["display"] for c in r["choices"]]
    assert "Jane Tan" not in str(r)


def test_my_sister_is_offered_as_sister(client):
    r = _ask(client, "send 50 to my sister")
    assert r["new_contact"]["name"] == "Sister"
    assert r["question"].startswith("Sister isn't in your contacts")


@pytest.mark.parametrize("said", ["send 800 to this new account", "send 800 to an account",
                                  "send 800 to the new bank account"])
def test_an_account_is_not_offered_as_a_new_contact(client, said):
    """"transfer $8,000 to this new account" offered to add "This New Account"
    as a contact. It names no one: ask who, from the saved contacts."""
    r = _ask(client, said)
    assert r["status"] == "clarify" and "new_contact" not in r
    assert r["question"] == ("I can only send money to people saved in your contacts. "
                             "Who is it for?")
    assert r["choices"]
