"""
The two safety states the server enforces: a HOLD on one draft, and the user's
KILL SWITCH on all outgoing payments.

A hold is not a countdown on a page. The gateway refuses the held draft until
`release_at`, whatever the client sends — and when the time is up NOTHING
happens by itself: the user still has to press Confirm and sign. Cancelling a
hold needs no signature: making things safer should be as easy as possible;
only moving money needs a signature.

The kill switch freezes every outgoing payment for the user until they clear
it with a code on their phone. Engaging it needs nothing — one tap.
"""
from __future__ import annotations

from backend.data.db import DB_PATH, connect


def create_hold(draft_id: str, user_id: str, *, seconds: int, now: int, payload_hash: str,
                db_path=None) -> int:
    """Hold this draft until now + seconds; returns the release time.

    A hold covers the payload it was created for (hold_covers). The same
    payload again keeps its release time. A DIFFERENT payload on the same draft
    is a payment the user hasn't waited on yet, so its wait starts again —
    never shorter than before. Every re-resolve is a different payload (its
    signed created_at / expires_at are new), so in practice any answered
    question restarts the wait, not only one that changed the payee.
    Two requests at once can't both create it: one INSERT OR IGNORE."""
    conn = connect(db_path or DB_PATH)
    try:
        conn.execute("INSERT OR IGNORE INTO holds (draft_id, user_id, created_at, release_at, "
                     "status, payload_hash) VALUES (?,?,?,?,'PENDING',?)",
                     (draft_id, user_id, now, now + seconds, payload_hash))
        conn.execute("UPDATE holds SET release_at = MAX(release_at, ?), payload_hash = ? "
                     "WHERE draft_id = ? AND status = 'PENDING' "
                     "AND COALESCE(payload_hash, '') != ?",
                     (now + seconds, payload_hash, draft_id, payload_hash))
        conn.commit()
        return int(conn.execute("SELECT release_at FROM holds WHERE draft_id=?",
                                (draft_id,)).fetchone()["release_at"])
    finally:
        conn.close()


def hold_covers(hold: dict, payload_hash: str) -> bool:
    """Whether this hold was for this payload. A payment the hold wasn't for
    has had no wait of its own, however long ago this hold ran out. (A hold
    from before holds recorded their payload covers any.)"""
    return not hold.get("payload_hash") or hold["payload_hash"] == payload_hash


def get_hold(draft_id: str, *, db_path=None) -> dict | None:
    conn = connect(db_path or DB_PATH)
    try:
        row = conn.execute("SELECT * FROM holds WHERE draft_id=?", (draft_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def _set_status(draft_id: str, frm: str, to: str, db_path=None) -> bool:
    conn = connect(db_path or DB_PATH)
    try:
        cur = conn.execute("UPDATE holds SET status=? WHERE draft_id=? AND status=?",
                           (to, draft_id, frm))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def cancel_hold(draft_id: str, *, db_path=None) -> bool:
    """PENDING -> CANCELLED. True if a pending hold was cancelled."""
    return _set_status(draft_id, "PENDING", "CANCELLED", db_path)


def release_hold(draft_id: str, *, db_path=None) -> bool:
    """PENDING -> RELEASED, when the held payment finally executes."""
    return _set_status(draft_id, "PENDING", "RELEASED", db_path)


def cancel_user_holds(user_id: str, *, db_path=None) -> list[str]:
    conn = connect(db_path or DB_PATH)
    try:
        ids = [r["draft_id"] for r in conn.execute(
            "SELECT draft_id FROM holds WHERE user_id=? AND status='PENDING'", (user_id,))]
        conn.execute("UPDATE holds SET status='CANCELLED' WHERE user_id=? AND status='PENDING'",
                     (user_id,))
        conn.commit()
        return ids
    finally:
        conn.close()


# --------------------------------------------------------------------------- kill switch
def kill_switch_engaged(user_id: str, *, db_path=None) -> int | None:
    """engaged_at while engaged, else None."""
    conn = connect(db_path or DB_PATH)
    try:
        row = conn.execute("SELECT engaged_at FROM kill_switch WHERE user_id=? "
                           "AND released_at IS NULL", (user_id,)).fetchone()
        return int(row["engaged_at"]) if row else None
    finally:
        conn.close()


def engage_kill_switch(user_id: str, *, now: int, db_path=None) -> bool:
    """Engage. True if newly engaged (False: it already was). One statement, so
    two taps at once engage it once and both see the same answer."""
    conn = connect(db_path or DB_PATH)
    try:
        cur = conn.execute(
            "INSERT INTO kill_switch VALUES (?,?,NULL) ON CONFLICT(user_id) DO UPDATE "
            "SET engaged_at=excluded.engaged_at, released_at=NULL "
            "WHERE kill_switch.released_at IS NOT NULL", (user_id, now))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()


def release_kill_switch(user_id: str, *, now: int, db_path=None) -> bool:
    conn = connect(db_path or DB_PATH)
    try:
        cur = conn.execute("UPDATE kill_switch SET released_at=? WHERE user_id=? "
                           "AND released_at IS NULL", (now, user_id))
        conn.commit()
        return cur.rowcount == 1
    finally:
        conn.close()
