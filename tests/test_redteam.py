"""
M8 acceptance — the red-team demo runs in CI, not just on stage.

A demo narrated from slides proves nothing. Every scenario in backend/redteam/
asserts a security property against live output from the real pipeline, so this
file is what makes "the LLM cannot move money" a claim that FAILS THE BUILD
when it stops being true.

Also covers the M8 wiring the scenarios depend on: POST /api/drafts joins
parse -> resolve -> policy -> validate, and the clarify loop keeps its state
server-side.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.data.seed import seed
from backend.main import app
from backend.redteam import SCENARIOS, run_all


@pytest.fixture(scope="module")
def results():
    """Run the whole demo once; assert on it per-scenario below."""
    out = run_all()
    yield out
    seed()          # leave the repo ledger clean


@pytest.mark.parametrize("index", range(len(SCENARIOS)))
def test_every_red_team_property_holds(results, index):
    """One test per scenario, so a failure names the property that broke."""
    r = results[index]
    assert r.passed, (
        f"RED-TEAM FAILURE — scenario {r.number} ({r.name}): the property "
        f"'{r.property_}' did not hold.\nEvidence:\n  "
        + "\n  ".join(r.evidence)
    )


def test_every_scenario_runs(results):
    """A demo that silently skips a scenario is worse than one that fails."""
    assert len(results) == len(SCENARIOS) == 12
    assert all(r.evidence for r in results), "a scenario produced no evidence"


# --------------------------------------------------------------------------- the M8 wiring
@pytest.fixture
def client():
    seed()
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    yield TestClient(app)
    seed()


def test_draft_endpoint_joins_every_milestone(client):
    """One POST runs parse -> resolve -> policy -> validate and returns a
    signable plan. Before M8 the resolver and policy engine were unreachable
    over HTTP and the overlay signed a hard-coded draft."""
    r = client.post("/api/drafts",
                    json={"transcript": "pay mom five hundred then buy aapl with the rest"})
    body = r.json()
    assert r.status_code == 200 and body["status"] == "ready"
    assert body["policy"]["decision"] == "ALLOW"          # M5 ran
    assert body["validation"]["verdict"] == "pass"        # M6 ran
    assert len(body["resolved_plan"]["plan"]) == 2        # M4 ran
    assert body["resolved_plan"]["plan"][1]["estimated_shares"] == 32
    assert len(body["payload_hash"]) == 64


def test_clarify_state_is_server_side(client):
    """The client answers with {field, choice_id} and nothing else. It is never
    handed the IntentPlan to send back, so it cannot rewrite the plan between
    the question and the answer."""
    first = client.post("/api/drafts", json={"transcript": "send fifty to john"}).json()
    assert first["status"] == "clarify"
    assert "intent_plan" not in first and "resume_state" not in first

    answered = client.post(f"/api/drafts/{first['draft_id']}/clarify",
                           json={"field": first["field"], "choice_id": "payee_21"}).json()
    assert answered["status"] == "ready"
    assert answered["resolved_plan"]["plan"][0]["payee_id"] == "payee_21"
    # the draft_id is stable, so the WebAuthn nonce binding survives the loop
    assert answered["draft_id"] == first["draft_id"]


def test_draft_id_is_server_issued_and_unguessable(client):
    """The nonce binds to the draft_id, so a client must not choose it."""
    a = client.post("/api/drafts", json={"transcript": "pay mom five hundred"}).json()
    b = client.post("/api/drafts", json={"transcript": "pay mom five hundred"}).json()
    assert a["draft_id"] != b["draft_id"]
    assert len(a["draft_id"]) >= 16


def test_a_policy_blocked_draft_retains_no_signable_plan(client):
    """Fail closed: there must be nothing to sign, not merely a flag saying
    'blocked'.

    Getting a policy BLOCK through the honest path takes some doing, and the
    reason is worth recording: acct_savings holds $8,420.50, which is BELOW the
    $20,000 per-transaction limit, so the resolver's insufficient-funds check
    always fires before policy can refuse an over-limit amount. The reachable
    block through this endpoint is velocity — and driving it also proves the M5
    change that makes executed transfers write transaction_history, without
    which the counter could never move."""
    blocked = None
    for _ in range(8):
        draft = client.post("/api/drafts", json={"transcript": "send fifty to mom"}).json()
        if draft["status"] == "blocked":
            blocked = draft
            break
        assert draft["status"] == "ready", draft
        nonce = client.get("/api/auth/nonce",
                           params={"draft_id": draft["draft_id"]}).json()["nonce"]
        signed = client.post("/api/auth/mock-sign", json={
            "resolved_plan": draft["resolved_plan"], "nonce": nonce}).json()
        out = client.post("/api/gateway/execute", json={
            "resolved_plan": draft["resolved_plan"], "signature": signed["signature"],
            "nonce": nonce, "credential_id": signed["credential_id"]}).json()
        assert out["accepted"] is True

    assert blocked is not None, "velocity never fired after 8 rapid transfers"
    assert blocked["policy"]["decision"] == "BLOCK"
    assert any(v["rule"] == "velocity" for v in blocked["policy"]["verdicts"])
    assert "resolved_plan" not in blocked
    stored = client.get(f"/api/drafts/{blocked['draft_id']}").json()
    assert stored["resolved_plan"] is None


def test_unknown_draft_is_404_not_a_crash(client):
    assert client.get("/api/drafts/does-not-exist").status_code == 404
    assert client.post("/api/drafts/does-not-exist/clarify",
                       json={"field": "t1.target", "choice_id": "payee_17"}
                       ).status_code == 404
