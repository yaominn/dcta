"""
Only a ready draft's exact payload executes; the user can say no.

WorkPlan: "Enforce draft states on the server: declined, cancelled, frozen,
expired or outdated drafts cannot execute."

The gateway executed whatever payload it was sent. Reproduced before this:
the validator passed "$50 to Mom", and the gateway ran $800 signed under the
same draft id — a payment nothing had checked — and ran a payment for a draft
this app never created. A frozen draft was stopped only because no nonce was
issued for it; nothing at the gateway looked. And there was no way to say no:
a card you did not want stayed signable for its whole window.

Pinned here:
  1. Outdated: a payload that is not the draft's current one is refused.
  2. Unknown / expired: no draft, no nonce — and no execution even with one.
  3. Frozen: refused AT THE GATEWAY, not only at the nonce.
  4. Decline / cancel: final, audited, block the nonce AND the gateway, can't
     be revived by answering a question, and survive a restart.
  5. A decline racing a signature: exactly one wins, and the user is never
     told "nothing was sent" about money that was.
  6. Contact edits: the same binding and the same decline.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import threading
import time

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
    from backend.main import _phone
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()
    yield TestClient(app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


# --------------------------------------------------------------------------- helpers
def _draft(client, transcript="pay mom fifty dollars"):
    d = client.post("/api/drafts", json={"transcript": transcript}).json()
    assert d["status"] == "ready", d
    return d


def _nonce(client, draft_id):
    return client.get("/api/auth/nonce", params={"draft_id": draft_id})


def _submit(plan: dict, nonce: str, client) -> dict:
    """Sign `plan` with the mock signer and send it to the gateway."""
    from backend.main import _signer
    sig = _signer.sign(challenge_hash(payload_hash(ResolvedPlan.model_validate(plan)), nonce))
    return client.post("/api/gateway/execute", json={
        "resolved_plan": plan, "signature": sig, "nonce": nonce,
        "credential_id": "cred_alice"}).json()


def _balance(account="acct_savings"):
    conn = connect()
    try:
        return conn.execute("SELECT balance FROM accounts WHERE id=?", (account,)).fetchone()[0]
    finally:
        conn.close()


def _audit_types():
    conn = connect()
    try:
        return [r[0] for r in conn.execute("SELECT entry_type FROM audit_log ORDER BY id")]
    finally:
        conn.close()


# --------------------------------------------------------------------------- the positive path
def test_the_drafted_payment_still_executes(client):
    d = _draft(client)
    before = _balance()
    out = _submit(d["resolved_plan"], _nonce(client, d["draft_id"]).json()["nonce"], client)
    assert out["accepted"] is True
    assert _balance() == before - 5000


# --------------------------------------------------------------------------- 1. outdated
def test_a_swapped_payload_under_a_real_draft_is_refused(client):
    """The reproduction: $800 signed under the id of a validated $50 draft."""
    d = _draft(client)
    swapped = copy.deepcopy(d["resolved_plan"])
    swapped["plan"][0]["amount_cents"] = 80000
    before = _balance()

    out = _submit(swapped, _nonce(client, d["draft_id"]).json()["nonce"], client)

    assert out["accepted"] is False and out["rejection"] == "OUTDATED"
    assert "nothing was sent" in out["reason"]
    assert _balance() == before


def test_the_draft_is_still_signable_after_a_refused_swap(client):
    """Refusing a forgery must not spend the genuine draft."""
    d = _draft(client)
    swapped = copy.deepcopy(d["resolved_plan"])
    swapped["plan"][0]["amount_cents"] = 80000
    _submit(swapped, _nonce(client, d["draft_id"]).json()["nonce"], client)
    out = _submit(d["resolved_plan"], _nonce(client, d["draft_id"]).json()["nonce"], client)
    assert out["accepted"] is True


# --------------------------------------------------------------------------- 2. unknown / expired
def test_a_draft_the_app_never_created_gets_no_nonce_and_cannot_execute(client):
    d = _draft(client)
    made_up = copy.deepcopy(d["resolved_plan"])
    made_up["draft_id"] = "never-drafted-by-this-app"
    assert _nonce(client, made_up["draft_id"]).status_code == 404

    # Even with a nonce minted around the endpoint, the gateway refuses it.
    from backend.main import _nonce_store
    before = _balance()
    out = _submit(made_up, _nonce_store.issue(made_up["draft_id"]), client)
    assert out["rejection"] == "STATE" and "never created" in out["reason"]
    assert _balance() == before


def test_an_expired_draft_cannot_execute(client):
    """Past the draft's window it is swept; its payload no longer binds."""
    from backend.main import _drafts
    d = _draft(client)
    nonce = _nonce(client, d["draft_id"]).json()["nonce"]
    _drafts.get(d["draft_id"]).created_at -= 3600              # an hour old
    out = _submit(d["resolved_plan"], nonce, client)
    assert out["rejection"] == "STATE"
    assert _drafts.get(d["draft_id"]) is None


# --------------------------------------------------------------------------- 3. frozen, at the gateway
def test_a_frozen_draft_is_refused_at_the_gateway_not_only_at_the_nonce(client):
    """Freeze AFTER a nonce was issued: only the gateway can catch it now."""
    from backend.main import _drafts
    d = _draft(client)
    nonce = _nonce(client, d["draft_id"]).json()["nonce"]
    _drafts.get(d["draft_id"]).status = "frozen"
    before = _balance()
    out = _submit(d["resolved_plan"], nonce, client)
    assert out["rejection"] == "STATE" and "frozen" in out["reason"]
    assert _balance() == before


# --------------------------------------------------------------------------- 4. decline / cancel
@pytest.mark.parametrize("action,outcome,entry", [
    ("decline", "declined", "DRAFT_DECLINED"),
    ("cancel", "cancelled", "DRAFT_CANCELLED"),
])
def test_saying_no_blocks_the_nonce_and_the_gateway(client, action, outcome, entry):
    d = _draft(client)
    held_nonce = _nonce(client, d["draft_id"]).json()["nonce"]   # taken BEFORE saying no

    r = client.post(f"/api/drafts/{d['draft_id']}/{action}")
    assert r.status_code == 200
    assert r.json() == {"draft_id": d["draft_id"], "status": outcome, "sent": False}
    assert _audit_types()[-1] == entry

    later = _nonce(client, d["draft_id"])
    assert later.status_code == 409 and later.json()["detail"]["status"] == outcome

    before = _balance()
    out = _submit(d["resolved_plan"], held_nonce, client)
    assert out["rejection"] == "STATE" and outcome in out["reason"]
    assert _balance() == before


def test_declining_twice_is_harmless(client):
    d = _draft(client)
    first = client.post(f"/api/drafts/{d['draft_id']}/decline").json()
    second = client.post(f"/api/drafts/{d['draft_id']}/decline")
    assert second.status_code == 200 and second.json() == first
    conn = connect()
    try:
        logged = [json.loads(r[0]) for r in conn.execute(
            "SELECT payload FROM audit_log WHERE entry_type='DRAFT_DECLINED'")]
    finally:
        conn.close()
    # The audit log is append-only across tests: count THIS draft's entries.
    assert sum(e["draft_id"] == d["draft_id"] for e in logged) == 1


def test_a_sent_payment_cannot_be_declined_and_says_so(client):
    """Never 'cancelled' about money that moved."""
    d = _draft(client)
    _submit(d["resolved_plan"], _nonce(client, d["draft_id"]).json()["nonce"], client)
    r = client.post(f"/api/drafts/{d['draft_id']}/decline")
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["already_executed"] is True
    assert detail["execution"]["status"] == "EXECUTED"


def test_a_declined_draft_cannot_be_revived_by_answering_a_question(client):
    from backend.main import _drafts
    d = _draft(client)
    client.post(f"/api/drafts/{d['draft_id']}/decline")
    r = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                    json={"field": "target", "choice_id": "payee_17"})
    assert r.status_code == 409
    assert _drafts.get(d["draft_id"]).status == "declined"


def test_a_decline_survives_a_restart(client):
    """The draft store is memory; the decline is in the ledger. With the draft
    forgotten, the gateway still says why — declined, not merely unknown."""
    from backend.main import _drafts, _nonce_store
    d = _draft(client)
    client.post(f"/api/drafts/{d['draft_id']}/decline")
    _drafts._drafts.clear()                                   # "restart"
    out = _submit(d["resolved_plan"], _nonce_store.issue(d["draft_id"]), client)
    assert out["rejection"] == "STATE" and "declined" in out["reason"]


def test_an_unknown_draft_cannot_be_declined(client):
    assert client.post("/api/drafts/no-such-draft/decline").status_code == 404


# --------------------------------------------------------------------------- 5. the race
def test_a_decline_racing_a_signature_has_exactly_one_winner(client):
    """Released together, many times. Whichever reaches the ledger first wins,
    and the two answers always agree with the balance."""
    for _ in range(10):
        d = _draft(client)
        nonce = _nonce(client, d["draft_id"]).json()["nonce"]
        before = _balance()
        barrier = threading.Barrier(2)
        got = {}

        def sign():
            barrier.wait()
            got["pay"] = _submit(d["resolved_plan"], nonce, client)

        def decline():
            barrier.wait()
            got["no"] = client.post(f"/api/drafts/{d['draft_id']}/decline")

        threads = [threading.Thread(target=sign), threading.Thread(target=decline)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        paid, declined = got["pay"]["accepted"], got["no"].status_code == 200
        assert paid != declined, "exactly one must win"
        if paid:
            assert got["no"].json()["detail"]["already_executed"] is True
            assert _balance() == before - 5000
        else:
            assert got["pay"]["rejection"] == "STATE"
            assert _balance() == before


# --------------------------------------------------------------------------- 6. contact edits
def _rename(client):
    d = client.post("/api/drafts", json={"transcript": "rename John to Johnny"}).json()
    if d.get("status") == "clarify":
        d = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                        json={"field": d["field"], "choice_id": "payee_22"}).json()
    return d


def _apply(client, change: dict) -> dict:
    from backend.main import _signer
    ch = ResolvedContactChange.model_validate(change)
    nonce = _nonce(client, ch.draft_id).json()["nonce"]
    return client.post("/api/contacts/apply", json={
        "contact_change": change, "nonce": nonce, "credential_id": "cred_alice",
        "signature": _signer.sign(challenge_hash(payload_hash(ch), nonce))}).json()


def test_a_swapped_contact_edit_is_refused(client):
    d = _rename(client)
    swapped = copy.deepcopy(d["contact_change"])
    swapped["edits"][0]["new_value"] = "Scammer"
    out = _apply(client, swapped)
    assert out["rejection"] == "OUTDATED"


def test_a_contact_edit_can_be_declined(client):
    d = _rename(client)
    assert client.post(f"/api/drafts/{d['draft_id']}/decline").status_code == 200
    assert _nonce(client, d["draft_id"]).status_code == 409
