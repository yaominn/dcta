"""
Out-of-band step-up confirmation. (backend/gateway/stepup.py, demo scenario 3)

The anomaly rule escalates rather than blocks. These tests pin that the
escalation is ENFORCED at the gateway — a signed but unconfirmed plan is
refused — and that a confirmation cannot be guessed, moved onto a different
payload, or reused.
"""
from __future__ import annotations

import re
import time

import pytest
from fastapi.testclient import TestClient

from backend.audit import AuditLog
from backend.audit.canonical import challenge_hash, hash_transcript, payload_hash
from backend.auth import MockCredentialStore
from backend.data.seed import seed
from backend.gateway import (Gateway, MockExecutor, MockSigner, NonceStore,
                             StepUpError, StepUpStore)
from backend.models.schemas import ResolvedPlan, ResolvedTransfer

_NOW = int(time.time())


def _anomalous_plan(cents=500000, draft_id="d-stepup"):
    """$5,000 to John ··4521, whose seeded median is $50 -> anomaly escalates."""
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_savings",
                               payee_id="payee_21", payee_display="John ··4521",
                               amount_cents=cents)],
        transcript_hash=hash_transcript("send five thousand to john"),
        created_at=_NOW, expires_at=_NOW + 300)


def _gateway(tmp_path, step_up):
    db = tmp_path / "ledger.db"
    seed(db)
    signer = MockSigner()
    creds = MockCredentialStore()
    creds.register("cred_alice", signer.public_key)
    gw = Gateway(signer=signer, nonce_store=NonceStore(), audit=AuditLog(db),
                 executor=MockExecutor(db), credentials=creds,
                 policy_db_path=db, step_up=step_up)
    return gw, signer


def _submit(gw, signer, plan):
    nonce = gw.nonce_store.issue(plan.draft_id)
    sig = signer.sign(challenge_hash(payload_hash(plan), nonce))
    return gw.submit(plan, sig, nonce, "cred_alice")


# --------------------------------------------------------------------------- gateway enforcement
def test_gateway_refuses_a_signed_but_unconfirmed_escalated_plan(tmp_path):
    """THE enforcement test: escalation is a control, not a warning."""
    gw, signer = _gateway(tmp_path, StepUpStore())
    out = _submit(gw, signer, _anomalous_plan())
    assert out["accepted"] is False
    assert out["rejection"] == "CONFIRMATION"


def test_gateway_without_a_step_up_store_fails_closed(tmp_path):
    gw, signer = _gateway(tmp_path, None)
    assert _submit(gw, signer, _anomalous_plan())["rejection"] == "CONFIRMATION"


def test_gateway_executes_a_confirmed_escalated_plan_exactly_once(tmp_path):
    store = StepUpStore()
    gw, signer = _gateway(tmp_path, store)
    plan = _anomalous_plan()
    store.confirm(plan.draft_id, store.issue(plan.draft_id, payload_hash(plan)))
    assert _submit(gw, signer, plan)["accepted"] is True
    # One confirmation authorizes one execution: a second signed submission of
    # the same draft needs a fresh confirmation.
    assert _submit(gw, signer, plan)["rejection"] == "CONFIRMATION"


def test_a_confirmation_cannot_be_moved_onto_a_different_payload(tmp_path):
    """Confirm $5,000, then submit $9,000 under the same draft_id: refused,
    because the confirmation is bound to the payload hash."""
    store = StepUpStore()
    gw, signer = _gateway(tmp_path, store)
    confirmed = _anomalous_plan(500000)
    store.confirm(confirmed.draft_id,
                  store.issue(confirmed.draft_id, payload_hash(confirmed)))
    swapped = _anomalous_plan(800000)
    assert _submit(gw, signer, swapped)["rejection"] == "CONFIRMATION"


def test_an_unescalated_plan_needs_no_confirmation(tmp_path):
    gw, signer = _gateway(tmp_path, StepUpStore())
    normal = _anomalous_plan(5000)          # $50 to John: his usual amount
    assert _submit(gw, signer, normal)["accepted"] is True


# --------------------------------------------------------------------------- the store
def test_three_wrong_codes_burn_the_challenge():
    store = StepUpStore()
    code = store.issue("d", "h")
    wrong = "000000" if code != "000000" else "111111"
    for left in (2, 1, 0):
        with pytest.raises(StepUpError) as exc:
            store.confirm("d", wrong)
        assert exc.value.attempts_left == left
    with pytest.raises(StepUpError):
        store.confirm("d", code)            # even the right code, once burned
    assert not store.is_confirmed("d", "h")


def test_an_expired_code_is_refused(monkeypatch):
    store = StepUpStore(ttl_seconds=300)
    code = store.issue("d", "h")
    real = time.time
    monkeypatch.setattr(time, "time", lambda: real() + 301)
    with pytest.raises(StepUpError):
        store.confirm("d", code)


def test_reissuing_replaces_the_previous_code():
    store = StepUpStore()
    old = store.issue("d", "h1")
    new = store.issue("d", "h2")
    if old != new:
        with pytest.raises(StepUpError):
            store.confirm("d", old)
    store.confirm("d", new)
    assert store.is_confirmed("d", "h2") and not store.is_confirmed("d", "h1")


# --------------------------------------------------------------------------- over HTTP
@pytest.fixture
def client():
    seed()
    from backend.main import _phone
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()
    from backend.main import app
    yield TestClient(app)
    seed()


def _escalated_draft(client):
    r = client.post("/api/drafts", json={"transcript": "send five thousand to john"}).json()
    return client.post(f"/api/drafts/{r['draft_id']}/clarify",
                       json={"field": r["field"], "choice_id": "payee_21"}).json()


def test_the_code_goes_to_the_phone_and_never_to_the_overlay(client):
    draft = _escalated_draft(client)
    assert draft["requires_extra_confirmation"] is True
    sms = client.get("/api/phone/messages").json()["messages"][0]["text"]
    code = re.search(r"code (\d{6})", sms).group(1)
    assert code not in str(draft)
    # The message describes the payment from the server's copy of the plan.
    assert "$5,000.00" in sms and "John ··4521" in sms


def test_confirm_endpoint_accepts_the_right_code_and_logs_both_outcomes(client):
    draft = _escalated_draft(client)
    sms = client.get("/api/phone/messages").json()["messages"][0]["text"]
    code = re.search(r"code (\d{6})", sms).group(1)
    wrong = "000000" if code != "000000" else "111111"
    bad = client.post(f"/api/drafts/{draft['draft_id']}/confirm", json={"code": wrong})
    assert bad.status_code == 400 and bad.json()["detail"]["attempts_left"] == 2
    ok = client.post(f"/api/drafts/{draft['draft_id']}/confirm", json={"code": code})
    assert ok.status_code == 200
    entries = [e for e in client.get("/api/audit/chain").json()["entries"]
               if e["entry_type"] == "CONFIRMATION"
               and draft["draft_id"] in str(e["payload"])]
    assert len(entries) == 2
    assert client.get("/api/audit/verify").json()["ok"] is True


def test_a_normal_draft_sends_nothing_to_the_phone(client):
    r = client.post("/api/drafts", json={"transcript": "pay mom five hundred"}).json()
    assert r["status"] == "ready" and r["requires_extra_confirmation"] is False
    assert client.get("/api/phone/messages").json()["messages"] == []
