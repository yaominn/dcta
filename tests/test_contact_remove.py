"""
Removing a contact from the contacts card — a confirm tap, no passkey.

Removing someone can only narrow who the user can pay, so it is not signed.
These pin what keeps that safe:
  - the contact is named as the card shows it (name + last 4); no match, or
    more than one, removes nothing
  - the row stays (payment history and the scam rules point at it) but the
    contact is gone from the list, from payments and from edits
  - anything drafted to them before the removal is refused when it's signed
  - saving the number again makes a brand-new contact, with the new-contact
    checks; and removing doesn't hide recent additions from those checks
  - removing Mom first doesn't make "add Mom, new number" look harmless
  - every removal is audited by id, without the name or the number
"""
from __future__ import annotations

import contextlib
import io
import json
import re
import shutil
import subprocess
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import challenge_hash, payload_hash
from backend.data.db import connect
from backend.data.seed import seed
from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import ResolvedPlan


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _phone, app
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()
    yield TestClient(app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _remove(client, nickname="Landlord", last4="7001"):
    return client.post("/api/contacts/remove", json={"nickname": nickname, "last4": last4})


def _listed(client):
    return [c["display"] for c in client.get("/api/contacts").json()["contacts"]]


def _execute(client, d):
    from backend.main import _nonce_store, _signer
    plan = d["resolved_plan"]
    n = _nonce_store.issue(d["draft_id"])
    sig = _signer.sign(challenge_hash(payload_hash(ResolvedPlan.model_validate(plan)), n))
    return client.post("/api/gateway/execute", json={"resolved_plan": plan, "signature": sig,
                                                     "nonce": n, "credential_id": "cred_alice"}).json()


def test_a_removed_contact_leaves_the_list(client):
    r = _remove(client)
    assert r.status_code == 200 and r.json() == {"removed": "Landlord ··7001"}
    assert "Landlord ··7001" not in _listed(client)
    assert "Mom ··3310" in _listed(client)


def test_the_row_stays_for_the_history(client):
    _remove(client)
    conn = connect()
    try:
        row = conn.execute("SELECT removed_at FROM payees WHERE id='payee_30'").fetchone()
    finally:
        conn.close()
    assert row is not None and row["removed_at"] is not None


def test_a_removed_contact_cannot_be_paid(client):
    _remove(client)
    d = client.post("/api/drafts", json={"transcript": "pay landlord 50 dollars"}).json()
    assert d["status"] != "ready" and "resolved_plan" not in d


def test_a_payment_drafted_before_the_removal_is_refused_as_removed(client):
    """Refused for the right reason: "removed", never "their number changed"
    (on a scam-protection app that reads like a hijack)."""
    d = client.post("/api/drafts", json={"transcript": "pay landlord 50 dollars"}).json()
    assert d["status"] == "ready"
    _remove(client)
    nonce = client.get("/api/auth/nonce", params={"draft_id": d["draft_id"]})
    assert nonce.status_code == 409 and nonce.json()["detail"]["rejection"] == "REMOVED"
    assert "removed from your contacts" in nonce.json()["detail"]["error"]
    out = _execute(client, d)
    assert out["rejection"] == "REMOVED" and "removed from your contacts" in out["reason"]


def test_a_waiting_payment_to_a_removed_contact_is_cancelled_as_removed(client, monkeypatch):
    from backend.main import _gateway
    from backend.policy import scam
    from tests.test_scam_protection import _scheduled
    monkeypatch.setattr(scam, "RELEASE_DELAY_SECONDS", 60)
    d = _scheduled(client)                                   # $1,500 to Landlord, waiting
    _remove(client)
    done = [x for x in _gateway.release_due(now=int(time.time()) + 61)
            if x["draft_id"] == d["draft_id"]]
    assert done == [{"draft_id": d["draft_id"], "status": "CANCELLED",
                     "reason": "the payee was removed from your contacts"}]


def test_a_removed_contact_cannot_be_renamed(client):
    _remove(client)
    d = client.post("/api/drafts", json={"transcript": "rename landlord to Mr Lee"}).json()
    assert d["status"] != "ready" and "contact_change" not in d


def test_an_edit_drafted_before_the_removal_writes_nothing(client):
    from backend.main import _signer
    from backend.main import _nonce_store
    d = client.post("/api/drafts", json={"transcript": "rename landlord to Mr Lee"}).json()
    assert d["status"] == "ready"
    _remove(client)
    change = ResolvedContactChange.model_validate(d["contact_change"])
    # No fingerprint asked for an edit that can only fail ...
    asked = client.get("/api/auth/nonce", params={"draft_id": change.draft_id})
    assert asked.status_code == 409 and asked.json()["detail"]["rejection"] == "REMOVED"
    # ... and straight at the gateway, nothing is written.
    nonce = _nonce_store.issue(change.draft_id)
    r = client.post("/api/contacts/apply", json={
        "contact_change": d["contact_change"], "nonce": nonce, "credential_id": "cred_alice",
        "signature": _signer.sign(challenge_hash(payload_hash(change), nonce))}).json()
    assert r["execution"]["status"] == "FAILED"
    assert "was removed from your contacts" in r["execution"]["error"]
    conn = connect()
    try:
        assert conn.execute("SELECT nickname FROM payees WHERE id='payee_30'").fetchone()[0] == "Landlord"
    finally:
        conn.close()


def test_the_number_can_be_saved_again_as_a_new_contact(client):
    from backend.main import _signer
    from backend.models.contacts import ResolvedContactAdd
    _remove(client)
    d = client.post("/api/drafts", json={"transcript": "add Landlord as a contact, 6123 7001"}).json()
    assert d["status"] == "ready", d
    if "PHONE_CODE" in d["contact_add"]["safeguards"]:
        text = client.get("/api/phone/messages").json()["messages"][0]["text"]
        code = re.search(r"code (\d{6})", text).group(1)
        assert client.post(f"/api/drafts/{d['draft_id']}/confirm",
                           json={"code": code}).status_code == 200
    add = ResolvedContactAdd.model_validate(d["contact_add"])
    nonce = client.get("/api/auth/nonce", params={"draft_id": add.draft_id}).json()["nonce"]
    r = client.post("/api/contacts/add", json={
        "contact_add": d["contact_add"], "nonce": nonce, "credential_id": "cred_alice",
        "signature": _signer.sign(challenge_hash(payload_hash(add), nonce))}).json()
    assert r["accepted"], r
    conn = connect()
    try:
        rows = conn.execute("SELECT id, added_at FROM payees WHERE nickname='Landlord' "
                            "AND removed_at IS NULL").fetchall()
    finally:
        conn.close()
    assert len(rows) == 1 and rows[0]["id"] != "payee_30" and rows[0]["added_at"]


def test_removing_a_new_contact_still_counts_as_a_recent_addition(client):
    from backend import main
    conn = connect()
    try:
        conn.execute("INSERT INTO payees (id, user_id, nickname, legal_name, last4, phone, added_at) "
                     "VALUES ('payee_new', 'u_alice', 'Bob', '', '4567', '+65 9123 4567', "
                     "strftime('%s','now'))")
        conn.commit()
    finally:
        conn.close()
    assert _remove(client, "Bob", "4567").status_code == 200
    seen = {}
    real = main.NewContactFacts

    def spy(**kw):
        seen.update(kw)
        return real(**kw)

    main.NewContactFacts = spy
    try:
        client.post("/api/drafts", json={"transcript": "add Jim as a contact, 8123 0000"})
    finally:
        main.NewContactFacts = real
    assert seen["added_last_24h"] == 1


def test_an_unknown_contact_is_not_found(client):
    assert _remove(client, "Nobody", "0000").status_code == 404
    assert _remove(client, "Landlord", "0000").status_code == 404


def test_removing_twice_finds_nothing_the_second_time(client):
    assert _remove(client).status_code == 200
    assert _remove(client).status_code == 404


def test_two_contacts_with_the_same_name_and_digits_remove_neither(client):
    conn = connect()
    try:
        conn.execute("INSERT INTO payees (id, user_id, nickname, legal_name, last4, phone) "
                     "VALUES ('payee_dup', 'u_alice', 'Landlord', '', '7001', '+65 8000 7001')")
        conn.commit()
    finally:
        conn.close()
    assert _remove(client).status_code == 409
    assert _listed(client).count("Landlord ··7001") == 2


def test_another_users_contact_cannot_be_removed(client):
    r = client.post("/api/contacts/remove",
                    json={"nickname": "Landlord", "last4": "7001", "user_id": "u_bob"})
    assert r.status_code == 404
    assert "Landlord ··7001" in _listed(client)


def test_removing_mom_first_still_holds_her_new_number(client):
    """The scam the hold exists for, with a removal in front of it: a removed
    contact still counts when a new one takes the same name."""
    assert _remove(client, "Mom", "3310").status_code == 200
    d = client.post("/api/drafts", json={"transcript": "add Mom as a contact, 8765 4321"}).json()
    assert d["status"] == "ready"
    assert "name_clash" in [w["code"] for w in d["risk"]["warnings"]]
    assert "HOLD" in d["contact_add"]["safeguards"]


def test_a_removal_is_audited_without_the_name_or_number(client):
    """Like CONTACT_ADD: the chain is append-only, so no name and no number."""
    from backend.main import _audit
    _remove(client)
    entry = [e for e in _audit.all_entries() if e["entry_type"] == "CONTACT_REMOVE"][-1]
    assert '"outcome":"REMOVED"' in entry["payload"] and "payee_30" in entry["payload"]
    assert "Landlord" not in entry["payload"] and "7001" not in entry["payload"]


# --------------------------------------------------------------------------- the page
@pytest.fixture(scope="module")
def page():
    """frontend/app.js under Node: the greeting and the contacts card
    (tests/js/contacts_runner.js)."""
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    runner = Path(__file__).resolve().parent / "js" / "contacts_runner.js"
    return json.loads(subprocess.run(["node", str(runner)], capture_output=True, text=True,
                                     timeout=60, check=True).stdout)


def test_the_greeting_offers_only_the_contacts_button(page):
    assert page["greetingButtons"] == ["Show my contacts"]


def test_the_button_reads_the_list_without_the_model(page):
    assert page["showCalls"] == ["GET /api/contacts?user_id=u_alice"]
    assert page["cardRows"] == 2 and page["rowButtons"] == ["Remove"]


def test_remove_asks_first_and_cancel_sends_nothing(page):
    assert page["confirmButtons"] == ["Yes, remove", "Cancel"]
    assert page["confirmAsk"] == "Remove Landlord ··7001?"
    assert page["afterCancel"] == ["Remove"] and page["removeCallsAfterCancel"] == 0


def test_a_refused_or_failed_removal_keeps_the_contact(page):
    assert page["refused"]["stillListed"] and page["refused"]["buttons"] == ["Remove"]
    assert page["refused"]["error"].startswith("Two contacts have that name")
    assert page["offline"]["stillListed"]
    assert page["offline"]["error"] == "Couldn't remove Landlord ··7001 (no connection). Nothing changed."


def test_a_removed_contact_leaves_the_card(page):
    assert page["removed"]["body"] == {"nickname": "Landlord", "last4": "7001", "user_id": "u_alice"}
    assert not page["removed"]["stillListed"] and page["removed"]["momListed"]
    assert not page["removed"]["olderCardStillListed"]      # no stale Remove further up
    assert page["removed"]["said"] == "Landlord ··7001 is no longer in your contacts."


def test_a_list_that_cannot_be_read_is_never_shown_empty(page):
    for case in ("load_serverError", "load_offline"):
        assert page[case] == {"newCard": False,
                              "error": "Couldn't load your contacts. Try again."}


def test_the_add_form_drafts_a_new_contact(page):
    assert page["formShown"] and page["emptySent"] == 0 and page["emptyFocus"]
    added = page["added"]
    assert added["url"] == "/api/drafts"           # a fresh request, not a purpose answer
    assert added["transcript"] == "add Uncle Bob as a contact, 9123 4567"
    assert added["formHidden"] and added["pending"] == {"purpose": None, "number": None}
