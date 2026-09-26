"""
A draft executes at most once.

WorkPlan: "Prevent duplicate execution: the same draft currently executes twice
with fresh nonces/signatures."

Every safeguard was attached to the NONCE, none to the draft: a nonce is
single-use, but /api/auth/nonce mints a new one for the same draft on every
request, a new signature is one more Touch ID away, and nothing recorded that
the draft had been paid. So "$50 to Mom" paid twice. It did not need an
attacker: approve, lose the response to a timeout, the page re-enables the
button, the user taps again.

Pinned here:
  1. A repeat is refused as DUPLICATE, however fresh its nonce and signature,
     and carries the original result — a retry learns what happened.
  2. It is decided by the LEDGER, atomically: the executor claims the draft in
     the same transaction as the debit, so two racing requests cannot both pay.
  3. It survives a restart (a new gateway on the same DB still refuses).
  4. One draft, one attempt: a FAILED execution counts too.
  5. No nonce is issued for an executed draft, so no second fingerprint prompt.
  6. Contact edits get the same guarantee.
  7. An existing demo DB gains the table at startup, without a re-seed.
"""
from __future__ import annotations

import contextlib
import io
import threading
import time

import pytest
from fastapi.testclient import TestClient

from backend.audit.canonical import challenge_hash, hash_transcript, payload_hash
from backend.audit.log import AuditLog
from backend.auth.credentials import MockCredentialStore
from backend.data.db import connect, migrate
from backend.data.seed import seed
from backend.gateway import Gateway, MockExecutor, MockSigner, NonceStore
from backend.gateway.executor import AlreadyExecuted
from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import ResolvedPlan, ResolvedTransfer
from support import dest


class _EveryPayloadIsTheDraft:
    """Stand-in for the draft store in gateway unit tests: every submitted
    payload counts as its own ready draft, so these tests exercise the nonce /
    signature / expiry / policy rules in isolation. The real binding — only a
    ready draft's exact payload executes — is tested in test_draft_states.py."""

    def executable(self, draft_id, *, kind, submitted_hash):
        return None


# --------------------------------------------------------------------------- a gateway on a throwaway ledger
def _gateway(db, *, policy=True):
    signer = MockSigner()
    creds = MockCredentialStore()
    creds.register("cred_alice", signer.public_key)
    gw = Gateway(drafts=_EveryPayloadIsTheDraft(), signer=signer, nonce_store=NonceStore(), audit=AuditLog(db),
                 executor=MockExecutor(db), credentials=creds,
                 policy_db_path=db if policy else None)
    return gw, signer


@pytest.fixture
def ledger(tmp_path):
    db = tmp_path / "ledger.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    return db


def _plan(cents=5000, draft_id="draft-once", source="acct_savings"):
    now = int(time.time())
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[ResolvedTransfer(id="t1", source_account=source, payee_id="payee_17",
                               payee_display="Mom ··3310", amount_cents=cents,
                               **dest("payee_17"))],
        transcript_hash=hash_transcript("pay mom"), created_at=now, expires_at=now + 300)


def _submit(gw, signer, plan):
    """A FRESH nonce and a FRESH signature every time — the attack's premise."""
    nonce = gw.nonce_store.issue(plan.draft_id)
    sig = signer.sign(challenge_hash(payload_hash(plan), nonce))
    return gw.submit(plan, sig, nonce, "cred_alice")


def _balance(db, account="acct_savings"):
    conn = connect(db)
    try:
        return conn.execute("SELECT balance FROM accounts WHERE id=?", (account,)).fetchone()[0]
    finally:
        conn.close()


# --------------------------------------------------------------------------- 1. the repeat is refused, with the truth
def test_a_second_execution_with_a_fresh_nonce_and_signature_is_refused(ledger):
    """The WorkPlan's exact reproduction. Before this, both returned accepted."""
    gw, signer = _gateway(ledger)
    plan = _plan()
    before = _balance(ledger)

    first = _submit(gw, signer, plan)
    second = _submit(gw, signer, plan)

    assert first["accepted"] is True
    assert second["accepted"] is False and second["rejection"] == "DUPLICATE"
    assert _balance(ledger) == before - 5000, "debited more than once"


def test_the_repeat_carries_the_original_result(ledger):
    """A retry after a lost response must learn what actually happened."""
    gw, signer = _gateway(ledger)
    plan = _plan()
    first = _submit(gw, signer, plan)
    second = _submit(gw, signer, plan)
    assert second["execution"] == first["execution"]
    assert isinstance(second["executed_at"], int)
    assert "nothing was sent twice" in second["reason"]


def test_the_repeat_is_audited(ledger):
    gw, signer = _gateway(ledger)
    plan = _plan()
    _submit(gw, signer, plan)
    _submit(gw, signer, plan)
    last = gw.audit.all_entries()[-1]
    assert last["entry_type"] == "SIGNATURE" and '"rejection":"DUPLICATE"' in last["payload"]


# --------------------------------------------------------------------------- 2. atomic: racing requests
def test_the_ledger_claim_holds_even_past_the_gateways_early_check(ledger):
    """The gateway's early check is a courtesy; the guarantee is the executor's
    claim. Reach the executor directly — as the loser of a race does, having
    passed the early check before the winner committed — and it still refuses,
    rolling its own debit back."""
    gw, signer = _gateway(ledger)
    plan = _plan()
    before = _balance(ledger)
    assert _submit(gw, signer, plan)["accepted"] is True

    with pytest.raises(AlreadyExecuted) as exc:
        gw.executor.execute(plan, payload_hash=payload_hash(plan))

    assert exc.value.prior["outcome"] == "EXECUTED"
    assert _balance(ledger) == before - 5000, "the refused transaction must not debit"


def test_concurrent_submissions_pay_exactly_once(ledger):
    """Real threads, released together. Whichever wins, exactly one pays."""
    gw, signer = _gateway(ledger)
    plan = _plan()
    before = _balance(ledger)
    barrier = threading.Barrier(4)
    results = []

    def attempt():
        nonce = gw.nonce_store.issue(plan.draft_id)
        sig = signer.sign(challenge_hash(payload_hash(plan), nonce))
        barrier.wait()
        results.append(gw.submit(plan, sig, nonce, "cred_alice"))

    threads = [threading.Thread(target=attempt) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert sum(r["accepted"] for r in results) == 1
    assert sorted(r.get("rejection") for r in results if not r["accepted"]) == ["DUPLICATE"] * 3
    assert _balance(ledger) == before - 5000


# --------------------------------------------------------------------------- 3. durable
def test_it_survives_a_restart(ledger):
    """A new gateway — fresh nonce store, fresh memory — on the same ledger."""
    gw, signer = _gateway(ledger)
    plan = _plan()
    assert _submit(gw, signer, plan)["accepted"] is True

    restarted, signer2 = _gateway(ledger)
    assert _submit(restarted, signer2, plan)["rejection"] == "DUPLICATE"


# --------------------------------------------------------------------------- 4. one attempt, whatever the outcome
def test_a_failed_execution_is_the_drafts_one_attempt(ledger):
    """Insufficient funds at execution time: FAILED, recorded, not retryable —
    the signed card is spent, as the page already says. (Policy off, so the
    payment reaches the executor instead of being refused before it.)"""
    gw, signer = _gateway(ledger, policy=False)
    plan = _plan(cents=500_000, source="acct_joint")           # $5,000 from $1,200
    first = _submit(gw, signer, plan)
    assert first["execution"]["status"] == "FAILED"
    assert _submit(gw, signer, plan)["rejection"] == "DUPLICATE"


# --------------------------------------------------------------------------- 5 + 6. the HTTP surface
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


def _http_execute(client, plan):
    nonce = client.get("/api/auth/nonce", params={"draft_id": plan["draft_id"]}).json()["nonce"]
    sig = client.post("/api/auth/mock-sign", json={"resolved_plan": plan, "nonce": nonce}).json()
    return client.post("/api/gateway/execute", json={
        "resolved_plan": plan, "signature": sig["signature"], "nonce": nonce,
        "credential_id": sig["credential_id"]}).json()


def test_no_nonce_is_issued_for_an_executed_draft(client):
    """So the page never asks for a second fingerprint — and learns why."""
    d = client.post("/api/drafts", json={"transcript": "pay mom fifty dollars"}).json()
    assert _http_execute(client, d["resolved_plan"])["accepted"] is True

    r = client.get("/api/auth/nonce", params={"draft_id": d["draft_id"]})
    assert r.status_code == 409
    detail = r.json()["detail"]
    assert detail["already_executed"] is True
    assert detail["execution"]["status"] == "EXECUTED"


def test_the_draft_is_marked_executed(client):
    from backend.main import _drafts
    d = client.post("/api/drafts", json={"transcript": "pay mom fifty dollars"}).json()
    _http_execute(client, d["resolved_plan"])
    assert _drafts.get(d["draft_id"]).status == "executed"


def _rename_john(client):
    d = client.post("/api/drafts", json={"transcript": "rename John to Johnny"}).json()
    if d.get("status") == "clarify":
        d = client.post(f"/api/drafts/{d['draft_id']}/clarify",
                        json={"field": d["field"], "choice_id": "payee_22"}).json()
    return d["contact_change"]


def _http_apply(client, change):
    from backend.main import _signer
    ch = ResolvedContactChange.model_validate(change)
    nonce = client.get("/api/auth/nonce", params={"draft_id": ch.draft_id}).json()["nonce"]
    sig = _signer.sign(challenge_hash(payload_hash(ch), nonce))
    return client.post("/api/contacts/apply", json={
        "contact_change": change, "signature": sig, "nonce": nonce,
        "credential_id": "cred_alice"}).json()


def test_a_contact_edit_runs_once(client):
    """Via the gateway directly, past the nonce endpoint's early refusal."""
    change = _rename_john(client)
    assert _http_apply(client, change)["accepted"] is True

    from backend.main import _gateway, _nonce_store, _signer
    ch = ResolvedContactChange.model_validate(change)
    nonce = _nonce_store.issue(ch.draft_id)
    out = _gateway.submit_contact_change(
        ch, _signer.sign(challenge_hash(payload_hash(ch), nonce)), nonce, "cred_alice")
    assert out["rejection"] == "DUPLICATE"
    assert out["execution"]["status"] == "UPDATED"


def test_a_failed_contact_edit_keeps_its_claim_and_writes_nothing(ledger):
    """A stale old value undoes the edits (savepoint) but KEEPS the claim, so
    the failure is recorded as the draft's one attempt."""
    ex = MockExecutor(ledger)
    now = int(time.time())
    change = ResolvedContactChange.model_validate({
        "draft_id": "draft-contact", "created_at": now, "expires_at": now + 300,
        "transcript_hash": hash_transcript("rename john"),
        "edits": [{"payee_id": "payee_22", "payee_display": "John ··8892",
                   "field": "nickname", "old_value": "NOT-THE-STORED-VALUE",
                   "new_value": "Johnny"}]})

    assert ex.apply_contact_change(change, payload_hash="h")["status"] == "FAILED"
    conn = connect(ledger)
    try:
        assert conn.execute("SELECT nickname FROM payees WHERE id='payee_22'").fetchone()[0] == "John"
    finally:
        conn.close()
    assert ex.prior_execution("draft-contact")["outcome"] == "FAILED"
    with pytest.raises(AlreadyExecuted):
        ex.apply_contact_change(change, payload_hash="h")


# --------------------------------------------------------------------------- 7. existing databases
def test_an_existing_demo_db_gains_the_table_without_a_reseed(ledger):
    """The demo DB predates this table and holds a registered passkey; startup
    must add the table and touch nothing else (a re-seed would drop passkeys)."""
    conn = connect(ledger)
    try:
        conn.execute("DROP TABLE executions")
        conn.execute("INSERT INTO webauthn_credentials VALUES (?,?,?,?,?)",
                     ("cred_kept", "u_alice", b"cose", 3, int(time.time())))
        conn.commit()
        migrate(conn)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        kept = conn.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone()[0]
    finally:
        conn.close()
    assert "executions" in tables
    assert kept == 1
