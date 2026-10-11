"""
The clock recurring payments are judged by: when something falls due, when an
automatic payment's day ends, when an approval expires.

Normally this is just time.time(). For a live demo, waiting a month for the
next bill is not an option, so with RECURRING_DEMO_CLOCK=1 the server (and the
`python -m backend.recurring` command) add a stored offset — moved forward by
the MOCK-only /api/recurring/clock/advance route. Without the flag the offset is
ignored, whatever the table holds: a deployment cannot be talked into running
next month's payments today. Only recurring due-time checks read this clock;
signing windows, nonces, holds and the scam rules keep real time.

Tests set `now` directly (run_due(now), the gateway's `now=`) rather than use
this offset.
"""
from __future__ import annotations

import time

from backend.config import env_flag
from backend.data.db import DB_PATH, connect


def demo_enabled() -> bool:
    return env_flag("RECURRING_DEMO_CLOCK")


def offset(*, db_path=None) -> int:
    if not demo_enabled():
        return 0
    conn = connect(db_path or DB_PATH)
    try:
        row = conn.execute("SELECT offset_s FROM recurring_clock WHERE id=1").fetchone()
    except Exception:                     # table not migrated yet: real time
        return 0
    finally:
        conn.close()
    return int(row["offset_s"]) if row else 0


def now(*, db_path=None) -> int:
    return int(time.time()) + offset(db_path=db_path)


def advance_to(target: int, *, db_path=None) -> int:
    """DEMO ONLY: move the recurring clock forward so it reads `target`. Never
    backwards (time running backwards would re-open windows). Returns the
    offset. Refuses unless RECURRING_DEMO_CLOCK is on."""
    if not demo_enabled():
        raise PermissionError("the demo clock is off (RECURRING_DEMO_CLOCK)")
    conn = connect(db_path or DB_PATH)
    try:
        new = max(offset(db_path=db_path), int(target) - int(time.time()))
        conn.execute("INSERT INTO recurring_clock (id, offset_s) VALUES (1, ?) "
                     "ON CONFLICT(id) DO UPDATE SET offset_s=excluded.offset_s", (new,))
        conn.commit()
        return new
    finally:
        conn.close()
