"""
M3 API tests — POST /api/plan, the text-input surface of the parser.

Pins: the endpoint returns a schema-valid IntentPlan (mentions only) plus the
transcript hash M4 will bind into the ResolvedPlan; the response carries no
stored third-party data; and a provider that cannot produce a valid plan gets
a closed 422 with the per-attempt errors — never a guessed draft.
"""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from backend.data.seed import seed
from backend.audit.canonical import hash_transcript

seed()  # the endpoint reads payees/billers/accounts/equities from the ledger

from backend.main import app  # noqa: E402  (import after seed for a fresh ledger)


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


def test_post_plan_returns_valid_intent_plan(client):
    tx = "pay mom five hundred then buy aapl with the rest"
    resp = client.post("/api/plan", json={"transcript": tx})
    assert resp.status_code == 200
    body = resp.json()

    from backend.models.schemas import IntentPlan
    plan = IntentPlan.model_validate(body["intent_plan"])   # re-validated, not trusted
    assert len(plan.plan) == 2
    assert plan.plan[0].target.mention == "mom"
    assert plan.plan[1].ticker.mention == "aapl"

    assert body["provider"] == "stub"                       # no creds in the test env
    assert body["transcript_hash"] == hash_transcript(tx)   # the M4 binding input


def test_post_plan_response_carries_no_stored_third_party_data(client):
    """The API-level echo of the opaque-IDs property: even if a prompt leaked,
    the RESPONSE never contains legal names, last4s or reference text."""
    resp = client.post("/api/plan", json={"transcript": "pay the citygas bill, eighty dollars"})
    assert resp.status_code == 200
    blob = json.dumps(resp.json())
    for forbidden in ("Jane Tan", "John Doe", "John Smith", "Property Mgmt",
                      "3310", "4521", "8892", "7001",
                      "ignore previous instructions", "123-456", "Acct 88231"):
        assert forbidden not in blob


def test_post_plan_unresolved_is_a_valid_200(client):
    """A transcript with no determinable amount is NOT an error — unresolved
    entries feed the clarify loop (M4). Guessing is the only failure mode."""
    resp = client.post("/api/plan", json={"transcript": "pay the citygas bill"})
    assert resp.status_code == 200
    plan = resp.json()["intent_plan"]
    assert plan["plan"] == []
    assert plan["unresolved"]


class _AlwaysGarbage:
    name = "garbage"

    def complete(self, *, system, user):
        return "definitely not a plan"


def test_post_plan_fails_closed_422(client, monkeypatch):
    """A model that can't produce a valid plan within the retry budget ->
    422 with the per-attempt errors. No draft is ever fabricated."""
    monkeypatch.setattr("backend.main.get_provider", lambda settings: _AlwaysGarbage())
    resp = client.post("/api/plan", json={"transcript": "pay mom five hundred"})
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "schema-valid" in detail["error"]
    assert len(detail["attempts"]) == 3                   # the bounded budget, surfaced
