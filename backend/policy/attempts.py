"""
What happened to earlier payment attempts, so the scam score remembers them.

One row per transfer leg of every scored draft: who it was for, how much, the
outcome the user was shown, whether they were asked what it was for, and how
it ended. scam.py reads these back as history facts — a retry after a stopped
payment, a smaller amount after a larger one was stopped, several stopped
attempts in a day, warnings gone past.

    OPEN     drafted, not finished (asked, on screen, held, or waiting to run)
    SENT     the money moved
    STOPPED  blocked, declined, cancelled, or stopped by the freeze

Kept in the ledger, not the audit log: the audit log never holds payees or
amounts (scam.py to_audit()).
"""
from __future__ import annotations

from backend.data.db import DB_PATH, connect

OPEN, SENT, STOPPED = "OPEN", "SENT", "STOPPED"


def record(draft_id: str, user_id: str, legs, *, outcome: str, asked: bool, now: int,
           status: str = OPEN, db_path=None) -> None:
    """Upsert this draft's transfer legs. `legs`: the plan's TRANSFER legs. A
    re-scored draft (an answered question) updates its rows: the outcome only
    ever rises, and a draft that was asked stays asked."""
    conn = connect(db_path or DB_PATH)
    try:
        for leg in legs:
            conn.execute(
                "INSERT INTO scam_attempts (draft_id, leg_id, user_id, payee_id, amount, "
                "outcome, asked, status, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(draft_id, leg_id) DO UPDATE SET payee_id=excluded.payee_id, "
                "amount=excluded.amount, outcome=excluded.outcome, "
                "asked=MAX(asked, excluded.asked), status=excluded.status, "
                "updated_at=excluded.updated_at",
                (draft_id, leg.id, user_id, leg.payee_id, leg.amount_cents, outcome,
                 int(asked), status, now, now))
        conn.commit()
    finally:
        conn.close()


def mark(draft_id: str, status: str, *, now: int, db_path=None) -> None:
    """How an OPEN attempt ended. A finished one (SENT or STOPPED) stays as it is."""
    conn = connect(db_path or DB_PATH)
    try:
        conn.execute("UPDATE scam_attempts SET status=?, updated_at=? "
                     "WHERE draft_id=? AND status='OPEN'", (status, now, draft_id))
        conn.commit()
    finally:
        conn.close()


def recent(user_id: str, *, since: int, exclude_draft: str | None = None,
           db_path=None) -> list[dict]:
    """This user's attempts updated since `since`, except the draft being scored."""
    conn = connect(db_path or DB_PATH)
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM scam_attempts WHERE user_id=? AND updated_at>=? "
            "AND draft_id IS NOT ?", (user_id, since, exclude_draft))]
    finally:
        conn.close()
