"""
Row fetching for the policy engine. (brief Section 8: backend/policy/)

Kept separate from engine.py so the rules stay pure and DB-free — the same
split backend/agent/ uses, and the one backend/resolver/ does NOT (it calls
get_conn() internally and consequently cannot be pointed at a test ledger).
Every function here takes an explicit `db_path`.
"""
from __future__ import annotations

import time

from backend.data.db import DB_PATH, connect
from backend.models.schemas import ResolvedPlan
from backend.policy.engine import PolicyContext


def load_context(user_id: str, *, db_path=None, now: int | None = None) -> PolicyContext:
    """Fetch the user row, the limits table and this user's money-movement history.

    History is the WHOLE of transaction_history for the user, not just today's:
    the daily rule needs today's rows and the anomaly rule needs the long-run
    median with each payee, and the table is demo-sized."""
    conn = connect(db_path or DB_PATH)
    try:
        user_row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        limits = {r["key"]: r["value"] for r in conn.execute("SELECT * FROM limits")}
        history = [dict(r) for r in conn.execute(
            "SELECT payee_id, leg_type, amount, ts FROM transaction_history WHERE user_id=?",
            (user_id,))]
    finally:
        conn.close()
    return PolicyContext(
        user=dict(user_row) if user_row else {},
        limits=limits,
        history=history,
        now=int(time.time()) if now is None else int(now),
    )


def owner_of(plan: ResolvedPlan, *, db_path=None) -> str | None:
    """The user who owns the accounts this plan debits, read from the ledger.

    The gateway needs a user to check policy against, and ResolvedPlan carries
    no user_id — deliberately: identity comes from the WebAuthn credential, not
    from the payload. Deriving the owner from the ACCOUNT ROWS instead of
    trusting a field in the request means a caller cannot nominate whose limits
    apply to them.

    Returns None if any account is unknown or the legs span more than one user —
    both of which the caller must treat as a rejection, not as "no policy".
    """
    account_ids = {leg.source_account for leg in plan.plan}
    if not account_ids:
        return None
    conn = connect(db_path or DB_PATH)
    try:
        placeholders = ",".join("?" * len(account_ids))
        rows = conn.execute(
            f"SELECT id, user_id FROM accounts WHERE id IN ({placeholders})",
            tuple(account_ids)).fetchall()
    finally:
        conn.close()
    if len(rows) != len(account_ids):
        return None                       # an account we don't know
    owners = {r["user_id"] for r in rows}
    return owners.pop() if len(owners) == 1 else None
