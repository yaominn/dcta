"""
DCTA — Direct Conversational Transaction Agent. (brief Section 1/2)

Scenario 1 — Voice-Enabled Payment and Transaction, with KYC and basic risk
control. Stated up front, as the submission requires.

Run:  uvicorn backend.main:app --reload
This is the Milestone 0 surface: a handful of read-only endpoints that prove
the mock ledger is seeded and FastAPI is alive. The real transaction pipeline
(ASR -> LLM -> resolver -> policy -> validator -> overlay -> WebAuthn ->
gateway -> audit) is built in Milestones 1-8.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel

from backend.config import settings
from backend.data.db import DB_PATH, get_conn
from backend.audit import AuditLog
from backend.audit.canonical import payload_hash, challenge_hash
from backend.gateway import Gateway, NonceStore, MockSigner, MockExecutor
from backend.auth import MockCredentialStore
from backend.models.schemas import ResolvedPlan

app = FastAPI(
    title="DCTA — Direct Conversational Transaction Agent",
    description=(
        "GenAI is a generator of drafts, never an executor of funds. "
        "Scenario 1 — Voice-Enabled Payment and Transaction (DBS track)."
    ),
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "project": "DCTA",
        "scenario": "Scenario 1 — Voice-Enabled Payment and Transaction, with KYC and basic risk control",
        "core_principle": "GenAI is a generator of drafts, never an executor of funds.",
        "milestone": "1 (gateway + audit + import-boundary)",
        "credentials_configured": settings.has_credentials,
        "note": "credentials empty = running on stubs; M1 security core needs no creds",
    }


@app.get("/api/seed/users")
def list_users():
    """Inspect seeded users (proves the DB is live)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM users").fetchall()
        return {"users": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/accounts")
def list_accounts(user_id: str = Query("u_alice")):
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,)).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail=f"no accounts for {user_id}")
        return {"accounts": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/payees")
def list_payees(user_id: str = Query("u_alice")):
    """Returns the FULL payee rows — legal names + last4 included here for
    inspection only. In the real pipeline the LLM is shown only {id, nickname};
    legal_name/last4 never enter a prompt (brief 4.3 opaque IDs)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM payees WHERE user_id = ?", (user_id,)).fetchall()
        return {"payees": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/billers")
def list_billers():
    """biller_07 carries the injection in its reference_text — the exact seed
    the M3 sanitizer test will prove never reaches a prompt (brief 4.3)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM billers").fetchall()
        return {"billers": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/headline")
def headline_arithmetic():
    """Locks the Section 13 demo arithmetic so the resolver (M4) has a target.
    All money is int cents: 842050 - 50000 = 792050 -> 32 whole AAPL shares
    @ 24150 = 772800, remainder 19250. Whole-share flooring is non-negotiable.
    No floats anywhere — the _display fields are strings for the UI only."""
    conn = get_conn()
    try:
        bal = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
        price = conn.execute("SELECT price FROM equities WHERE ticker='AAPL'").fetchone()[0]
    finally:
        conn.close()
    after_transfer = bal - 50000                  # 792050
    shares = after_transfer // price              # 32 — floor to whole shares
    cost = shares * price                         # 772800
    remainder = after_transfer - cost            # 19250
    from backend.display import cents_to_display
    return {
        "acct_savings_balance_cents": bal,
        "acct_savings_balance_display": cents_to_display(bal),
        "after_t1_minus_500_cents": after_transfer,
        "after_t1_minus_500_display": cents_to_display(after_transfer),
        "aapl_price_cents": price,
        "aapl_price_display": cents_to_display(price),
        "estimated_whole_shares": shares,
        "share_cost_cents": cost,
        "share_cost_display": cents_to_display(cost),
        "remainder_in_source_cents": remainder,
        "remainder_in_source_display": cents_to_display(remainder),
    }


# --------------------------------------------------------------------------- M1
# The security core, served over HTTP for the demo. Singletons share one mock
# signer + one registered demo credential ("cred_alice") so the happy path is
# exercisable end to end. Real WebAuthn (M2) swaps the signer + credential store.

_signer = MockSigner()
_credentials = MockCredentialStore()
_credentials.register("cred_alice", _signer.public_key)   # MOCK demo credential

_nonce_store = NonceStore(ttl_seconds=120)
_audit = AuditLog(DB_PATH)
_executor = MockExecutor(DB_PATH)
_gateway = Gateway(
    signer=_signer,
    nonce_store=_nonce_store,
    audit=_audit,
    executor=_executor,
    credentials=_credentials,
)


@app.get("/api/auth/nonce")
def issue_nonce(draft_id: str = Query(...)):
    """Issue a draft-bound, single-use, 120s-TTL nonce (brief 4.5).
    The nonce binds to this draft_id — a swap-after-approval fails at the gateway."""
    return {"nonce": _nonce_store.issue(draft_id),
            "draft_id": draft_id, "ttl_seconds": _nonce_store.ttl}


class MockSignRequest(BaseModel):
    """# MOCK dev-only convenience to demo the happy path. Would NOT exist in M2,
    where the browser signs via WebAuthn. Lets an HTTP client obtain a valid
    signature over the canonical challenge without the server's mock secret."""
    resolved_plan: ResolvedPlan
    nonce: str


@app.post("/api/auth/mock-sign")
def mock_sign(req: MockSignRequest):
    p_hash = payload_hash(req.resolved_plan)
    challenge = challenge_hash(p_hash, req.nonce)
    return {"signature": _signer.sign(challenge),
            "payload_hash": p_hash, "challenge": challenge,
            "credential_id": "cred_alice"}


class ExecuteRequest(BaseModel):
    """The ONLY shape the gateway accepts (brief 4.2): payload + signature + nonce.
    resolved_plan is validated into the frozen ResolvedPlan schema on the way in."""
    resolved_plan: ResolvedPlan
    signature: str | None = None
    nonce: str
    credential_id: str


@app.post("/api/gateway/execute")
def gateway_execute(req: ExecuteRequest):
    """The single execution chokepoint. Verifies nonce -> signature -> executes.
    Returns accepted=True on success; accepted=False (rejected+logged) on any
    verification failure (brief acceptance test: unsigned request rejected+logged)."""
    return _gateway.submit(req.resolved_plan, req.signature, req.nonce, req.credential_id)


@app.get("/api/audit/chain")
def audit_chain():
    """List the hash-chained audit log in order."""
    return {"entries": _audit.all_entries()}


@app.get("/api/audit/verify")
def audit_verify():
    """verify_chain(): ok=True or the exact entry where tampering broke the chain."""
    return _audit.verify_chain()
