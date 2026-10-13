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
