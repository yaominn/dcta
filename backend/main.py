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

from backend.config import settings
from backend.data.db import get_conn

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
        "milestone": "0 (scaffold + seed)",
        "credentials_configured": settings.has_credentials,
        "note": "credentials empty = running on stubs, which is expected for M0",
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
    8420.50 - 500 = 7920.50 -> 32 whole AAPL shares @ 241.50 = 7728.00,
    remainder 192.50. Whole-share flooring is non-negotiable."""
    conn = get_conn()
    try:
        bal = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
        price = conn.execute("SELECT price FROM equities WHERE ticker='AAPL'").fetchone()[0]
    finally:
        conn.close()
    after_transfer = round(bal - 500, 2)
    shares = int(after_transfer // price)            # floor to whole shares
    cost = round(shares * price, 2)
    remainder = round(after_transfer - cost, 2)
    return {
        "acct_savings_balance": bal,
        "after_t1_minus_500": after_transfer,
        "aapl_price": price,
        "estimated_whole_shares": shares,
        "share_cost": cost,
        "remainder_in_source": remainder,
    }
