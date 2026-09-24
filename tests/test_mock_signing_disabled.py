"""
The mock signer is OFF unless something explicitly opts in.

WorkPlan: "Disable mock-signing shortcuts in the protected demo; they currently
allow payment without biometric interaction."

Before this, /api/auth/mock-sign handed a valid signature to ANY caller, the
nonce endpoint issues a nonce for any draft_id, and the gateway executes the
plan in the request. So three HTTP calls — nonce, mock-sign, gateway/execute —
moved money from a fabricated plan with no passkey and no human. The red-team
runner did exactly that for its happy path; so could anyone who reached the
demo server. /api/contacts/apply did the same for contact edits.

Pinned here:
  1. The default: a freshly started app, with MOCK_SIGNING unset, has no mock
     routes — checked in a clean subprocess, not by flipping a flag in-process.
  2. Off means 404 on all three, identical to a route that never existed, and
     BEFORE the body is parsed.
  3. Off means the attack fails end to end: a real, signable draft cannot be
     executed or a contact edited through the mock path, nothing changes, and
     the blocked probe does not burn the user's nonce.
  4. The real WebAuthn routes are untouched.
  5. Only an explicit on-value enables it; a typo fails closed.
"""
from __future__ import annotations

import contextlib
import io
import json
import logging
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import challenge_hash, payload_hash
from backend.config import env_flag, settings
from backend.data.db import connect
from backend.data.seed import seed
from backend.main import app
from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import ResolvedPlan

REPO = Path(__file__).resolve().parents[1]
MOCK_ROUTES = ["/api/auth/mock-sign", "/api/gateway/execute", "/api/contacts/apply"]


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _phone
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()
    yield TestClient(app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


@pytest.fixture
def mock_off(monkeypatch):
    """What every real server runs with. The suite opts in (conftest.py), so
    this switches it back off for the test's duration."""
    monkeypatch.setattr(settings, "mock_signing", False)


def _balance(account_id: str) -> int:
    conn = connect()
    try:
        return conn.execute("SELECT balance FROM accounts WHERE id=?",
                            (account_id,)).fetchone()["balance"]
    finally:
        conn.close()


def _payee(payee_id: str) -> dict:
    conn = connect()
    try:
        return dict(conn.execute("SELECT * FROM payees WHERE id=?", (payee_id,)).fetchone())
    finally:
        conn.close()


# --------------------------------------------------------------------------- 1. the default
def test_a_fresh_server_has_no_mock_routes():
    """The property that matters for the demo, tested the way the demo runs: a
    new process, MOCK_SIGNING never set. (A developer whose .env sets
    MOCK_SIGNING=1 will see this fail — correctly: their server is exposed.)"""
    env = {k: v for k, v in os.environ.items() if k != "MOCK_SIGNING"}
    probe = textwrap.dedent("""
        import json
        from fastapi.testclient import TestClient
        from backend.config import settings
        from backend.main import app
        c = TestClient(app)
        documented = c.get("/openapi.json").json()["paths"]
        print(json.dumps({
            "flag": settings.mock_signing,
            "documented": sorted(p for p in %r if p in documented),
            "status": {p: c.post(p, json={}).status_code for p in %r},
        }))
    """ % (MOCK_ROUTES, MOCK_ROUTES))
    out = subprocess.run([sys.executable, "-c", probe], cwd=REPO, env=env,
                         capture_output=True, text=True, timeout=120, check=True)
    result = json.loads(out.stdout.strip().splitlines()[-1])

    assert result["flag"] is False
    assert result["documented"] == [], "mock routes must not appear in /docs"
    assert result["status"] == {p: 404 for p in MOCK_ROUTES}


# --------------------------------------------------------------------------- 2. off = does not exist
@pytest.mark.parametrize("path", MOCK_ROUTES)
def test_off_is_indistinguishable_from_a_route_that_never_existed(client, mock_off, path):
    """Same status, same body as a genuinely undefined path. And the body here
    is not a valid request: a 404 rather than a 422 proves the gate runs before
    parsing, so a probe learns nothing about the schema either."""
    r = client.post(path, json={"not": "a valid body"})
    never_existed = client.post("/api/this-route-was-never-defined", json={})
    assert r.status_code == 404
    assert r.json() == never_existed.json()


def test_a_blocked_call_is_logged(client, mock_off, caplog):
    """Probing the mock path on a protected server is itself a signal."""
    with caplog.at_level(logging.WARNING):
        client.post("/api/auth/mock-sign", json={})
    assert any("blocked call to disabled mock-signing route" in r.getMessage()
               and "/api/auth/mock-sign" in r.getMessage() for r in caplog.records)


# --------------------------------------------------------------------------- 3. the attack, end to end
def test_the_three_call_attack_cannot_move_money(client, mock_off):
    """The exact sequence the red-team runner used, against a real, signable
    draft — the strongest input an attacker could bring."""
    draft = client.post("/api/drafts", json={"transcript": "pay mom fifty dollars"}).json()
    assert draft["status"] == "ready", draft
    plan = draft["resolved_plan"]
    source = plan["plan"][0]["source_account"]
    before = _balance(source)

    nonce = client.get("/api/auth/nonce", params={"draft_id": draft["draft_id"]}).json()["nonce"]

    # Call 2: the signing oracle is gone.
    r = client.post("/api/auth/mock-sign", json={"resolved_plan": plan, "nonce": nonce})
    assert r.status_code == 404

    # Call 3: even an attacker who ALREADY holds a valid mock signature — say,
    # captured while the flag was briefly on — cannot use it.
    from backend.main import _signer
    signature = _signer.sign(challenge_hash(payload_hash(ResolvedPlan.model_validate(plan)), nonce))
    r = client.post("/api/gateway/execute", json={
        "resolved_plan": plan, "signature": signature,
        "nonce": nonce, "credential_id": "cred_alice"})
    assert r.status_code == 404

    assert _balance(source) == before, "money moved without a biometric"

    # The probe was refused before the gateway ran, so it did not burn the
    # user's nonce: the real passkey path can still use it.
    from backend.main import _nonce_store
    _nonce_store.consume(nonce, draft["draft_id"])        # raises if it was burned


def test_a_contact_edit_cannot_be_applied_through_the_mock_path(client, mock_off):
    """The scam demo depends on this one: changing where Mom's money goes must
    need a biometric, not three HTTP calls."""
    d = client.post("/api/drafts", json={"transcript": "rename John to Johnny"}).json()
    if d.get("status") == "clarify":
        d = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                        json={"field": d["field"], "choice_id": "payee_22"}).json()
    change = d["contact_change"]
    before = _payee("payee_22")

    ch = ResolvedContactChange.model_validate(change)
    nonce = client.get("/api/auth/nonce", params={"draft_id": ch.draft_id}).json()["nonce"]
    from backend.main import _signer
    signature = _signer.sign(challenge_hash(payload_hash(ch), nonce))
    r = client.post("/api/contacts/apply", json={
        "contact_change": change, "signature": signature,
        "nonce": nonce, "credential_id": "cred_alice"})

    assert r.status_code == 404
    assert _payee("payee_22") == before


# --------------------------------------------------------------------------- 4. the real path is untouched
@pytest.mark.parametrize("path", ["/api/gateway/execute-webauthn",
                                  "/api/contacts/apply-webauthn"])
def test_the_webauthn_routes_still_exist_with_mock_off(client, mock_off, path):
    """A malformed body reaching validation (422) proves the route is there.
    Disabling the shortcut must not disable the real thing."""
    assert client.post(path, json={}).status_code == 422


def test_positive_control_the_mock_path_works_when_opted_in(client):
    """Without this, every 404 above could be passing for a reason unrelated to
    the flag. The suite runs with it on (conftest.py)."""
    assert settings.mock_signing is True
    draft = client.post("/api/drafts", json={"transcript": "pay mom fifty dollars"}).json()
    nonce = client.get("/api/auth/nonce", params={"draft_id": draft["draft_id"]}).json()["nonce"]
    r = client.post("/api/auth/mock-sign",
                    json={"resolved_plan": draft["resolved_plan"], "nonce": nonce})
    assert r.status_code == 200 and r.json()["signature"]


# --------------------------------------------------------------------------- 5. fails closed
@pytest.mark.parametrize("value", ["1", "true", "TRUE", " on ", "yes"])
def test_explicit_on_values_enable_it(monkeypatch, value):
    monkeypatch.setenv("MOCK_SIGNING", value)
    assert env_flag("MOCK_SIGNING") is True


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off", "ture", "enabled", "2"])
def test_anything_else_leaves_it_off(monkeypatch, value):
    """A flag that weakens security must fail CLOSED on a typo."""
    monkeypatch.setenv("MOCK_SIGNING", value)
    assert env_flag("MOCK_SIGNING") is False


def test_unset_leaves_it_off(monkeypatch):
    monkeypatch.delenv("MOCK_SIGNING", raising=False)
    assert env_flag("MOCK_SIGNING") is False


# --------------------------------------------------------------------------- 6. a real server process
def test_a_live_uvicorn_server_refuses_the_mock_path(server_url):
    """Everything above uses the in-process app. This is a real uvicorn
    process started the way the demo is — the same one the WebAuthn e2e test
    signs against, so that test proves the real path works with the shortcut
    gone."""
    import requests
    for path in MOCK_ROUTES:
        assert requests.post(server_url + path, json={}, timeout=10).status_code == 404, path
    assert requests.post(server_url + "/api/gateway/execute-webauthn",
                         json={}, timeout=10).status_code == 422
