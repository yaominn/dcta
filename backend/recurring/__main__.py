"""
Run recurring bill payments from the command line — what a cron job or a
separate worker would call.

    python -m backend.recurring run-due          # run what's due now, once
    python -m backend.recurring loop [SECONDS]   # keep running it (default 30s)
    python -m backend.recurring status           # arrangements and their payments

It uses the same ledger, executor, audit log and rules as the server, through a
gateway that can verify no signature (scheduler.worker_gateway): it can only
mark payments due and pay the automatic ones a signed mandate allows. Safe to
run next to the server, or twice at once — each occurrence is debited at most
once. "Now" is the recurring clock: real time, unless RECURRING_DEMO_CLOCK=1
and the demo clock was moved forward.
"""
from __future__ import annotations

import sys
import time

from backend.data.db import connect, migrate
from backend.recurring import clock, schedule, store
from backend.recurring.scheduler import run_due, worker_gateway


def _run_once(gateway) -> None:
    now = clock.now()
    events = run_due(now, gateway=gateway)
    stamp = schedule.label(schedule.local_date(now, "Asia/Singapore"))
    if not events:
        print(f"[{stamp}] nothing due")
    for e in events:
        print(f"[{stamp}] {e['mandate_id']} #{e['seq']}: {e['status']}"
              + (f" — {e['reason']}" if e.get("reason") else ""))


def _status() -> None:
    conn = connect()
    try:
        for m in conn.execute("SELECT * FROM mandates ORDER BY created_at"):
            terms = store.load_terms(m)
            name = terms.biller_display if terms else "(record doesn't match its signature)"
            print(f"{m['mandate_id']}  {name}  {m['status']}/{m['mode']}  "
                  f"paid {m['paid_count']}, approvals {m['supervised_successes']}")
            for o in store.occurrences(conn, m["mandate_id"]):
                print(f"    #{o['seq']:<3} {o['due_date']}  {o['status']:<17} {o['reason'] or ''}")
    finally:
        conn.close()


def main(argv: list[str]) -> int:
    cmd = argv[0] if argv else "run-due"
    conn = connect()
    try:
        migrate(conn)
    finally:
        conn.close()
    if cmd == "status":
        _status()
        return 0
    gateway = worker_gateway()
    if cmd == "run-due":
        _run_once(gateway)
        return 0
    if cmd == "loop":
        every = int(argv[1]) if len(argv) > 1 else 30
        while True:
            _run_once(gateway)
            time.sleep(every)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
