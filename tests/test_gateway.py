"""
Gateway tests — the security core. (brief Section 4.2 acceptance test)

"A script calling the gateway directly with a well-formed but unsigned request
is rejected and logged." Plus the full verification matrix: valid signed ->
executed+logged, bad signature, replay, expired, swap-after-approval, unknown
credential, and sequential stop-at-first-failure execution (brief 4.1).
"""
from __future__ import annotations

import time

from backend.audit import AuditLog
from backend.audit.canonical import payload_hash, challenge_hash, hash_transcript
from backend.auth import MockCredentialStore
from backend.data.db import connect
from backend.data.seed import seed
from backend.gateway import Gateway, NonceStore, MockSigner, MockExecutor
from backend.models.schemas import ResolvedPlan, ResolvedTransfer, ResolvedBuyEquity

# Stub transcript (ASR lands in M7); its sha256 is the required transcript_hash.
_STUB_TX = "stub: transfer five hundred dollars to mom then buy aapl with the rest"
_STUB_TX_HASH = hash_transcript(_STUB_TX)
# The schema caps the authorization window at MAX_AUTH_WINDOW_S (300s), so a
# "far-future" expiry is impossible. Gateway tests hit the runtime expiry check
# (now > expires_at), so happy-path plans need created_at ~ now with a valid
# <=300s window that stays unexpired through the test run. A fixed past
# timestamp with a valid window would be expired at runtime (rejected EXPIRED).
_NOW = int(time.time())
_CREATED = _NOW                 # fresh plan: created ~ now
_EXPIRES = _CREATED + 300       # 300s window (the cap); stays > now through the run
# An expired-but-schema-valid plan: created 10 min ago, expires ~5 min ago. The
# window is valid (300s, <= cap) but expires_at < now -> gateway rejects EXPIRED.
# Used to prove the expiry check runs BEFORE nonce consumption.
_EXPIRED_CREATED = _NOW - 600
_EXPIRED_EXPIRES = _EXPIRED_CREATED + 300


def _build(tmp_path, ttl=120):
    """Seed a fresh temp DB and wire a fully-real gateway against a mock signer."""
    db_path = tmp_path / "ledger.db"
    seed(db_path)
    signer = MockSigner()
    creds = MockCredentialStore()
    creds.register("cred_alice", signer.public_key, user_id="u_alice")
    nonce_store = NonceStore(ttl_seconds=ttl)
    audit = AuditLog(db_path)
    executor = MockExecutor(db_path)
    gw = Gateway(
        signer=signer, nonce_store=nonce_store,
        audit=audit, executor=executor, credentials=creds,
    )
    return gw, signer, nonce_store, audit


def _plan(draft_id="d1", amount_cents=50000, source="acct_savings",
          transcript_hash=_STUB_TX_HASH, created_at=_CREATED,
          expires_at=_EXPIRES) -> ResolvedPlan:
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[
            ResolvedTransfer(
                id="t1", type="TRANSFER", source_account=source,
                payee_id="payee_17", payee_display="Mom", amount_cents=amount_cents,
            )
        ],
        transcript_hash=transcript_hash,
        created_at=created_at,
        expires_at=expires_at,
    )


def _sign(signer, plan, nonce) -> str:
    return signer.sign(challenge_hash(payload_hash(plan), nonce))


def _balance(tmp_path, account="acct_savings") -> int:
    conn = connect(tmp_path / "ledger.db")
    try:
        return conn.execute(
            "SELECT balance FROM accounts WHERE id=?", (account,)
        ).fetchone()[0]
    finally:
        conn.close()


# --------------------------------------------------------------------------- acceptance
def test_unsigned_request_rejected_and_logged(tmp_path):
    """THE brief acceptance test: well-formed but unsigned -> rejected + logged."""
    gw, _signer, nonce_store, audit = _build(tmp_path)
    plan = _plan()
    nonce = nonce_store.issue(plan.draft_id)

    result = gw.submit(plan, signature=None, nonce=nonce, credential_id="cred_alice")

    assert result["accepted"] is False
    assert result["rejection"] == "SIGNATURE"
    assert result["reason"] == "missing signature"
    entries = audit.all_entries()
    assert any(
        e["entry_type"] == "SIGNATURE" and "missing signature" in e["payload"]
        for e in entries
    ), "rejection must be logged to the audit chain"


def test_valid_signed_request_accepted_and_executed(tmp_path):
    gw, signer, nonce_store, audit = _build(tmp_path)
    plan = _plan(amount_cents=50000)
    nonce = nonce_store.issue(plan.draft_id)
    sig = _sign(signer, plan, nonce)

    result = gw.submit(plan, sig, nonce, "cred_alice")

    assert result["accepted"] is True
    assert result["execution"]["status"] == "EXECUTED"
    assert _balance(tmp_path) == 792050          # 842050 - 50000 cents
    assert any(e["entry_type"] == "EXECUTION" for e in audit.all_entries())


# --------------------------------------------------------------------------- verification matrix
def test_bad_signature_rejected(tmp_path):
    gw, _signer, nonce_store, _audit = _build(tmp_path)
    plan = _plan()
    nonce = nonce_store.issue(plan.draft_id)

    result = gw.submit(plan, "deadbeef" * 8, nonce, "cred_alice")   # 64 random hex

    assert result["accepted"] is False
    assert result["rejection"] == "SIGNATURE"
    assert result["reason"] == "bad signature"


def test_replayed_nonce_rejected(tmp_path):
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan = _plan()
    nonce = nonce_store.issue(plan.draft_id)
    sig = _sign(signer, plan, nonce)

    first = gw.submit(plan, sig, nonce, "cred_alice")
    assert first["accepted"] is True

    second = gw.submit(plan, sig, nonce, "cred_alice")   # same nonce + sig
    assert second["accepted"] is False
    assert second["rejection"] == "NONCE"
    assert "replay" in second["reason"]


def test_expired_nonce_rejected(tmp_path):
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan = _plan()
    nonce = nonce_store.issue(plan.draft_id)
    nonce_store._store[nonce].issued_at -= 1000          # backdate past the 120s TTL

    sig = _sign(signer, plan, nonce)
    result = gw.submit(plan, sig, nonce, "cred_alice")

    assert result["accepted"] is False
    assert result["rejection"] == "NONCE"
    assert "expired" in result["reason"]


def test_expired_payload_rejected_nonce_preserved(tmp_path):
    """S5: a payload whose expires_at is in the past is rejected with reason
    EXPIRED. Checked FIRST, before the nonce is consumed — so the issued nonce
    stays usable and a fresh, unexpired resubmission of the SAME draft still
    executes. The time bound lives inside the signed payload (the user's own
    consent expiring), distinct from the server-side 120s nonce TTL above.
    Rejected + logged, like every other rejection.

    The expired plan carries a SCHEMA-VALID window (created_at < expires_at,
    300s <= cap) that has simply elapsed at runtime — distinct from the
    N1/N2 inverted/over-long windows which are rejected at construction."""
    gw, signer, nonce_store, audit = _build(tmp_path)
    expired = _plan(created_at=_EXPIRED_CREATED,
                    expires_at=_EXPIRED_EXPIRES)   # valid window, already expired
    nonce = nonce_store.issue(expired.draft_id)
    sig = _sign(signer, expired, nonce)          # valid sig — only the expiry is wrong

    result = gw.submit(expired, sig, nonce, "cred_alice")

    assert result["accepted"] is False
    assert result["rejection"] == "EXPIRED"
    assert "expired" in result["reason"]
    # logged to the audit chain, like the other rejections
    assert any(
        '"EXPIRED"' in e["payload"] for e in audit.all_entries()
    ), "EXPIRED rejection must be logged to the audit chain"
    # nonce NOT consumed: a fresh, unexpired plan with the SAME nonce executes.
    # (same draft_id "d1"; only created_at/expires_at differ -> different hash
    # -> different sig; the nonce is bound to draft_id, not to the hash.)
    fresh = _plan()                               # created ~ now, expires ~ now+300
    fresh_sig = _sign(signer, fresh, nonce)
    result2 = gw.submit(fresh, fresh_sig, nonce, "cred_alice")
    assert result2["accepted"] is True
    assert result2["execution"]["status"] == "EXECUTED"


def test_swap_after_approval_rejected(tmp_path):
    """The brief 4.5 attack: approve draft A, submit draft B with A's nonce.
    Draft-binding makes this fail."""
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan_b = _plan(draft_id="dB")
    nonce = nonce_store.issue("dA")                  # bound to dA, not dB
    sig = _sign(signer, plan_b, nonce)               # valid sig for plan B's hash

    result = gw.submit(plan_b, sig, nonce, "cred_alice")

    assert result["accepted"] is False
    assert result["rejection"] == "NONCE"
    assert "swap-after-approval" in result["reason"]


def test_unknown_credential_rejected(tmp_path):
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan = _plan()
    nonce = nonce_store.issue(plan.draft_id)
    sig = _sign(signer, plan, nonce)

    result = gw.submit(plan, sig, nonce, "cred_nonexistent")

    assert result["accepted"] is False
    assert result["rejection"] == "SIGNATURE"
    assert result["reason"] == "unknown credential"


# --------------------------------------------------------------------------- execution semantics (brief 4.1)
def test_two_leg_sequential_execution(tmp_path):
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan = ResolvedPlan(
        draft_id="d2",
        plan=[
            ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_savings",
                             payee_id="payee_17", payee_display="Mom", amount_cents=50000),
            ResolvedBuyEquity(id="t2", type="BUY_EQUITY", source_account="acct_savings",
                              ticker="AAPL", amount_cents=100000,
                              estimated_shares=4, estimated_fill_price_cents=24150),
        ],
        transcript_hash=_STUB_TX_HASH,
        created_at=_CREATED,
        expires_at=_EXPIRES,
    )
    nonce = nonce_store.issue(plan.draft_id)
    sig = _sign(signer, plan, nonce)

    result = gw.submit(plan, sig, nonce, "cred_alice")

    assert result["accepted"] is True
    legs = result["execution"]["legs"]
    assert legs[0]["status"] == "EXECUTED"
    assert legs[1]["status"] == "EXECUTED"
    assert _balance(tmp_path) == 692050              # 842050 - 50000 - 100000


def test_stop_at_first_failure_marks_rest_blocked(tmp_path):
    gw, signer, nonce_store, _audit = _build(tmp_path)
    plan = ResolvedPlan(
        draft_id="d3",
        plan=[
            ResolvedTransfer(id="t1", type="TRANSFER", source_account="acct_savings",
                             payee_id="payee_17", payee_display="Mom", amount_cents=99999900),
            ResolvedTransfer(id="t2", type="TRANSFER", source_account="acct_joint",
                             payee_id="payee_17", payee_display="Mom", amount_cents=1000),
        ],
        transcript_hash=_STUB_TX_HASH,
        created_at=_CREATED,
        expires_at=_EXPIRES,
    )
    nonce = nonce_store.issue(plan.draft_id)
    sig = _sign(signer, plan, nonce)

    result = gw.submit(plan, sig, nonce, "cred_alice")

    assert result["accepted"] is True                  # signature valid; execution failed
    legs = result["execution"]["legs"]
    assert legs[0]["status"] == "FAILED"
    assert legs[1]["status"] == "BLOCKED"               # brief 4.1: stop at first failure
    assert result["execution"]["status"] == "FAILED"
