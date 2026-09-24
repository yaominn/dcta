"""
The signer must own what they sign for.

WorkPlan: "Check that the signer owns the account/contact."

The signature proves a registered passkey approved exactly this payload. Before
this check nothing asked WHOSE passkey it was relative to the money: any valid
credential could debit any account, pay into another customer's payee, or edit
another customer's contact. The seed data hid it — every account and payee is
Alice's — so this suite gives Bob an account, a payee and a credential of his
own, and signs across the line in every direction.

Also pinned: the check runs AFTER the signature (it is not an ownership oracle
for unsigned callers), rejections never name the true owner, it fails closed on
unknown signers/accounts/payees, and a successful payment CARRIES the evidence
— whose passkey signed and what they own — because that is what the demo shows.

The mock signer stands in for the biometric (MOCK_SIGNING is on in the suite).
Both gateways run the same Gateway.submit(), so what is proven here holds for
the WebAuthn path; the passkey store's user lookup is tested directly.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import challenge_hash, payload_hash
from backend.data.db import connect
from backend.data.seed import seed
from backend.main import app
from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import ResolvedPlan


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _credentials, _phone, _signer
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()

    # Bob gets the things the seed never gave him.
    conn = connect()
    try:
        conn.execute("INSERT INTO accounts VALUES (?,?,?,?,?)",
                     ("acct_bob", "u_bob", "acct_bob", 50000, "savings"))
        conn.execute("INSERT INTO payees VALUES (?,?,?,?,?,?)",
                     ("payee_bob", "u_bob", "Sis", "Bee Lim", "4040", "+65 9000 4040"))
        conn.commit()
    finally:
        conn.close()
    _credentials.register("cred_bob", _signer.public_key, user_id="u_bob")
    _credentials.register("cred_ghost", _signer.public_key, user_id="u_nobody")

    yield TestClient(app)

    for cred in ("cred_bob", "cred_ghost"):
        _credentials._creds.pop(cred, None)
        _credentials._users.pop(cred, None)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


# --------------------------------------------------------------------------- helpers
def _alice_draft(client) -> dict:
    d = client.post("/api/drafts", json={"transcript": "pay mom fifty dollars"}).json()
    assert d["status"] == "ready", d
    return d


def _execute(client, plan: dict, credential_id: str, *, tamper_signature=False) -> dict:
    """Sign `plan` with the mock signer and submit it as `credential_id`."""
    from backend.main import _signer
    nonce = client.get("/api/auth/nonce", params={"draft_id": plan["draft_id"]}).json()["nonce"]
    sig = _signer.sign(challenge_hash(payload_hash(ResolvedPlan.model_validate(plan)), nonce))
    if tamper_signature:
        sig = "0" * len(sig)
    return client.post("/api/gateway/execute", json={
        "resolved_plan": plan, "signature": sig, "nonce": nonce,
        "credential_id": credential_id}).json()


def _apply_contact(client, change: dict, credential_id: str) -> dict:
    from backend.main import _signer
    ch = ResolvedContactChange.model_validate(change)
    nonce = client.get("/api/auth/nonce", params={"draft_id": ch.draft_id}).json()["nonce"]
    sig = _signer.sign(challenge_hash(payload_hash(ch), nonce))
    return client.post("/api/contacts/apply", json={
        "contact_change": change, "signature": sig, "nonce": nonce,
        "credential_id": credential_id}).json()


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


def _last_audit() -> tuple[str, dict]:
    conn = connect()
    try:
        row = conn.execute("SELECT entry_type, payload FROM audit_log "
                           "ORDER BY id DESC LIMIT 1").fetchone()
        return row["entry_type"], json.loads(row["payload"])
    finally:
        conn.close()


# --------------------------------------------------------------------------- the positive case, with evidence
def test_alice_paying_from_her_account_to_her_payee_executes_with_evidence(client):
    """The demo path. The gateway does not merely fail to object: it says whose
    passkey signed and that this person owns everything the payment touched."""
    d = _alice_draft(client)
    before = _balance("acct_savings")
    out = _execute(client, d["resolved_plan"], "cred_alice")

    assert out["accepted"] is True, out
    assert out["ownership"] == {
        "verified": True, "signer": "u_alice", "signer_name": "Alice",
        "accounts": [{"id": "acct_savings", "label": "savings"}],
        "payees": [{"id": "payee_17", "label": "Mom"}],
    }
    assert _balance("acct_savings") == before - 5000
    kind, payload = _last_audit()
    assert kind == "EXECUTION" and payload["signer"] == "u_alice"


def test_the_evidence_reaches_the_data_page_trace(client):
    d = _alice_draft(client)
    _execute(client, d["resolved_plan"], "cred_alice")
    traces = client.get("/api/data").json()["traces"]
    gw = [e for t in traces if t["id"] == d["draft_id"]
          for e in t["events"] if e["step"] == "gateway"]
    assert gw and gw[-1]["ownership"]["signer"] == "u_alice"


# --------------------------------------------------------------------------- across the line, every direction
def test_bobs_passkey_cannot_debit_alices_account(client):
    """The core case. Without this check it EXECUTED: policy is evaluated
    against the account's owner — Alice, KYC-verified — so nothing else
    objected to Bob's signature moving Alice's money."""
    d = _alice_draft(client)
    before = _balance("acct_savings")
    out = _execute(client, d["resolved_plan"], "cred_bob")

    assert out["accepted"] is False
    assert out["rejection"] == "OWNERSHIP"
    assert "acct_savings" in out["reason"]
    assert _balance("acct_savings") == before
    kind, payload = _last_audit()
    assert kind == "SIGNATURE" and payload["rejection"] == "OWNERSHIP"


def test_alice_cannot_pay_into_another_customers_payee(client):
    """Her own account, someone else's payee record: still refused. A payee is
    a customer's stored instruction, not a public address book."""
    plan = copy.deepcopy(_alice_draft(client)["resolved_plan"])
    plan["plan"][0]["payee_id"] = "payee_bob"
    out = _execute(client, plan, "cred_alice")
    assert out["rejection"] == "OWNERSHIP"
    assert "payee_bob" in out["reason"]


def test_a_plan_spanning_two_owners_is_refused(client):
    plan = copy.deepcopy(_alice_draft(client)["resolved_plan"])
    second = copy.deepcopy(plan["plan"][0])
    second.update(id="t2", source_account="acct_bob")
    plan["plan"].append(second)
    before = (_balance("acct_savings"), _balance("acct_bob"))
    out = _execute(client, plan, "cred_alice")
    assert out["rejection"] == "OWNERSHIP"
    assert (_balance("acct_savings"), _balance("acct_bob")) == before, "no leg may run"


def test_alice_cannot_edit_another_customers_contact(client):
    """What the scam demo rests on: where a payee's money goes can only be
    changed by that payee's owner."""
    d = client.post("/api/drafts", json={"transcript": "rename John to Johnny"}).json()
    if d.get("status") == "clarify":
        d = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                        json={"field": d["field"], "choice_id": "payee_22"}).json()
    change = copy.deepcopy(d["contact_change"])
    for edit in change["edits"]:
        edit["payee_id"] = "payee_bob"
    before = _payee("payee_bob")

    out = _apply_contact(client, change, "cred_alice")
    assert out["rejection"] == "OWNERSHIP"
    assert _payee("payee_bob") == before


def test_alice_editing_her_own_contact_still_works_with_evidence(client):
    d = client.post("/api/drafts", json={"transcript": "rename John to Johnny"}).json()
    if d.get("status") == "clarify":
        d = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                        json={"field": d["field"], "choice_id": "payee_22"}).json()
    out = _apply_contact(client, d["contact_change"], "cred_alice")
    assert out["accepted"] is True, out
    assert out["ownership"]["signer"] == "u_alice"
    assert out["ownership"]["payees"] == [{"id": "payee_22", "label": "John"}]


# --------------------------------------------------------------------------- fails closed, leaks nothing
def test_a_rejection_never_names_the_true_owner(client):
    """Naming the owner would turn the check into a who-owns-what oracle."""
    plan = copy.deepcopy(_alice_draft(client)["resolved_plan"])
    plan["plan"][0]["payee_id"] = "payee_bob"
    reason = _execute(client, plan, "cred_alice")["reason"]
    assert "u_bob" not in reason and "Bob" not in reason


def test_an_unknown_account_is_refused(client):
    plan = copy.deepcopy(_alice_draft(client)["resolved_plan"])
    plan["plan"][0]["source_account"] = "acct_does_not_exist"
    out = _execute(client, plan, "cred_alice")
    assert out["rejection"] == "OWNERSHIP"
    assert "unknown account" in out["reason"]


def test_a_credential_whose_user_does_not_exist_is_refused(client):
    out = _execute(client, _alice_draft(client)["resolved_plan"], "cred_ghost")
    assert out["rejection"] == "OWNERSHIP"


def test_ownership_is_checked_only_after_a_valid_signature(client):
    """A badly signed request for Bob's money is refused for its SIGNATURE:
    an unsigned caller learns nothing about who owns what."""
    plan = copy.deepcopy(_alice_draft(client)["resolved_plan"])
    plan["plan"][0]["source_account"] = "acct_bob"
    out = _execute(client, plan, "cred_alice", tamper_signature=True)
    assert out["rejection"] == "SIGNATURE"


def test_a_mock_credential_cannot_be_registered_without_an_owner():
    from backend.auth.credentials import MockCredentialStore
    with pytest.raises(TypeError):
        MockCredentialStore().register("cred_x", "mock-pubkey")      # no user_id


# --------------------------------------------------------------------------- the passkey store
def test_the_passkey_store_reports_the_user_it_was_registered_to(client):
    """What the WebAuthn gateway's ownership check reads. The submit() path
    that consumes it is the one exercised above — both gateways share it."""
    from backend.main import _webauthn_credentials
    _webauthn_credentials.store("cred_passkey_bob", "u_bob", b"\x01cose", 0)
    assert _webauthn_credentials.user_of("cred_passkey_bob") == "u_bob"
    assert _webauthn_credentials.user_of("cred_never_registered") is None
