"""
run_due(now): the one entry point a worker, cron job or the server's loop
calls. Deterministic in `now` — tests pass a controlled clock; the server and
`python -m backend.recurring run-due` pass clock.now().

For every occurrence whose due time has come (and nothing earlier):

  - its mandate isn't ACTIVE (paused, suspended)  -> SKIPPED, the user told.
    Resuming later does not catch it up.
  - supervised phase  -> PENDING_APPROVAL and a notification. Nothing is paid;
    the user approves it with their passkey (approve.py), or it EXPIRES at
    review_until.
  - automatic phase   -> Gateway.run_mandate_occurrence(), which pays it or
    holds it. Only on its due date: a run that comes later marks it MISSED.

Then approvals that ran out are EXPIRED, and arrangements with nothing left
are COMPLETED. Every transition is a conditional UPDATE under BEGIN IMMEDIATE,
so any number of workers can call this at once: one moves each occurrence, and
the executor's execution-key claim stops a second debit even if two reach it.
"""
from __future__ import annotations

from backend.audit.log import AuditEntryType, AuditLog
from backend.data.db import DB_PATH, connect
from backend.recurring import schedule, store


def run_due(now: int, *, gateway, db_path=None) -> list[dict]:
    db = db_path or gateway.executor.db_path
    conn = connect(db)
    try:
        due = [(r["mandate_id"], r["seq"]) for r in conn.execute(
            "SELECT o.mandate_id, o.seq FROM mandate_occurrences o JOIN mandates m "
            "USING (mandate_id) WHERE o.status='SCHEDULED' AND o.due_at<=? "
            "AND m.status IN ('ACTIVE','PAUSED','SUSPENDED') ORDER BY o.due_at, o.seq", (now,))]
    finally:
        conn.close()
    events = [_fall_due(mid, seq, now, gateway, db) for mid, seq in due]
    events += _expire(now, db, gateway.audit)
    _complete(now, db, gateway.audit)
    return events


def _fall_due(mandate_id: str, seq: int, now: int, gateway, db) -> dict:
    conn = connect(db)
    run_automatic = False
    try:
        conn.execute("BEGIN IMMEDIATE")
        m = store.get_mandate(conn, mandate_id)
        occ = store.occurrence(conn, mandate_id, seq)
        if occ is None or occ["status"] != "SCHEDULED":
            conn.rollback()
            return {"mandate_id": mandate_id, "seq": seq, "status": "ALREADY_HANDLED"}
        terms = store.load_terms(m)
        user = m["user_id"]
        if terms is None:
            store.set_occurrence(conn, mandate_id, seq, frm=("SCHEDULED",), to="SKIPPED", now=now,
                                 reason="the stored arrangement doesn't match what you signed")
            store.suspend(conn, m, None, "The stored arrangement doesn't match what you signed.",
                          now=now)
            outcome = "SKIPPED"
        elif m["status"] != "ACTIVE":
            why = "paused" if m["status"] == "PAUSED" else "stopped"
            store.set_occurrence(conn, mandate_id, seq, frm=("SCHEDULED",), to="SKIPPED",
                                 now=now, reason=f"arrangement {why}")
            store.notify(conn, user, "SKIPPED", f"{terms.biller_display} payment {seq} skipped",
                         f"{store.describe(terms, seq)} was due but NOT paid, because the "
                         f"arrangement is {why}. It won't be paid later.",
                         now=now, mandate_id=mandate_id, seq=seq)
            outcome = "SKIPPED"
        elif m["mode"] == "AUTO":
            if now > occ["auto_until"]:
                store.set_occurrence(conn, mandate_id, seq, frm=("SCHEDULED",), to="MISSED",
                                     now=now, reason="not run on its due date", phase="AUTO")
                store.notify(conn, user, "MISSED", f"{terms.biller_display} payment {seq} missed",
                             f"{store.describe(terms, seq)} couldn't be run on its due date, so "
                             f"it was NOT paid. It won't be paid late — pay it yourself if you "
                             f"need to.", now=now, mandate_id=mandate_id, seq=seq)
                outcome = "MISSED"
            else:
                conn.execute("UPDATE mandate_occurrences SET phase='AUTO', updated_at=? "
                             "WHERE mandate_id=? AND seq=? AND status='SCHEDULED'",
                             (now, mandate_id, seq))
                outcome, run_automatic = "AUTO", True
        elif now > occ["review_until"]:
            store.set_occurrence(conn, mandate_id, seq, frm=("SCHEDULED",), to="MISSED", now=now,
                                 reason="not offered for approval in time", phase="SUPERVISED")
            store.notify(conn, user, "MISSED", f"{terms.biller_display} payment {seq} missed",
                         f"{store.describe(terms, seq)} couldn't be offered for your approval "
                         f"in time, so it was NOT paid. It won't be paid late.",
                         now=now, mandate_id=mandate_id, seq=seq)
            outcome = "MISSED"
        else:
            store.set_occurrence(conn, mandate_id, seq, frm=("SCHEDULED",),
                                 to="PENDING_APPROVAL", now=now, phase="SUPERVISED")
            left = terms.supervised_approvals - m["supervised_successes"]
            until = schedule.label(schedule.local_date(occ["review_until"], terms.timezone))
            store.notify(conn, user, "DUE", f"Approve your {terms.biller_display} payment",
                         f"{store.describe(terms, seq)} is due. Open DCTA to review it and "
                         f"approve it with your passkey by {until}. Nothing is paid until you do."
                         + (f" After {left} more approval{'s' if left != 1 else ''}, payments "
                            f"will be made automatically, as you agreed."
                            if terms.auto_after_supervised and left > 0 else ""),
                         now=now, mandate_id=mandate_id, seq=seq)
            outcome = "PENDING_APPROVAL"
        conn.commit()
    finally:
        conn.close()
    if run_automatic:
        return {"mandate_id": mandate_id, "seq": seq,
                **gateway.run_mandate_occurrence(mandate_id, seq, now=now)}
    gateway.audit.append(AuditEntryType.MANDATE_OCCURRENCE, {
        "mandate_id": mandate_id, "seq": seq, "draft_id": occ["draft_id"],
        "stage": "due", "status": outcome})
    return {"mandate_id": mandate_id, "seq": seq, "status": outcome}


def _expire(now: int, db, audit: AuditLog) -> list[dict]:
    """Approvals that weren't given in time: EXPIRED, not paid, not retried."""
    conn = connect(db)
    out = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        marks = ",".join("?" * len(store.APPROVABLE))
        rows = [dict(r) for r in conn.execute(
            f"SELECT * FROM mandate_occurrences WHERE status IN ({marks}) AND review_until<?",
            (*store.APPROVABLE, now))]
        for occ in rows:
            if not store.set_occurrence(conn, occ["mandate_id"], occ["seq"], frm=store.APPROVABLE,
                                        to="EXPIRED", now=now, reason="not approved in time"):
                continue
            m = store.get_mandate(conn, occ["mandate_id"])
            terms = store.load_terms(m)
            if terms is not None:
                store.notify(conn, m["user_id"], "EXPIRED",
                             f"{terms.biller_display} payment {occ['seq']} expired",
                             f"{store.describe(terms, occ['seq'])} wasn't approved in time, so it "
                             f"was NOT paid. It won't be retried, and it doesn't count towards "
                             f"the approvals before automatic payment.",
                             now=now, mandate_id=occ["mandate_id"], seq=occ["seq"])
            out.append({"mandate_id": occ["mandate_id"], "seq": occ["seq"], "status": "EXPIRED",
                        "draft_id": occ["draft_id"]})
        conn.commit()
    finally:
        conn.close()
    for e in out:
        audit.append(AuditEntryType.MANDATE_OCCURRENCE, {**e, "stage": "expired"})
    return out


def _complete(now: int, db, audit: AuditLog) -> None:
    """An ACTIVE or PAUSED arrangement with no occurrence left open is done."""
    conn = connect(db)
    done = []
    try:
        conn.execute("BEGIN IMMEDIATE")
        marks = ",".join("?" * len(store.OPEN))
        for m in [dict(r) for r in conn.execute(
                f"SELECT * FROM mandates WHERE status IN ('ACTIVE','PAUSED') AND NOT EXISTS "
                f"(SELECT 1 FROM mandate_occurrences o WHERE o.mandate_id=mandates.mandate_id "
                f"AND o.status IN ({marks}))", store.OPEN)]:
            if store.set_mandate(conn, m["mandate_id"], frm=("ACTIVE", "PAUSED"), to="COMPLETED",
                                 now=now, reason="no payments left"):
                terms = store.load_terms(m)
                if terms is not None:
                    store.notify(conn, m["user_id"], "COMPLETED",
                                 f"{terms.biller_display}: arrangement finished",
                                 f"{m['paid_count']} of {terms.occurrence_count} payments were "
                                 f"made. Nothing more will be paid under it.",
                                 now=now, mandate_id=m["mandate_id"])
                done.append(m["mandate_id"])
        conn.commit()
    finally:
        conn.close()
    for mid in done:
        audit.append(AuditEntryType.MANDATE_STATUS, {"mandate_id": mid, "status": "COMPLETED"})


# --------------------------------------------------------------------------- a worker's gateway
class _NoSignatures:
    """A worker verifies no signatures: it only runs mandates."""
    public_key = None

    def verify(self, *_a) -> bool:
        return False


class _NoDrafts:
    def executable(self, draft_id, *, kind, submitted_hash):
        return ("STATE", "a recurring worker executes no drafts")


class _NoCredentials:
    def get(self, _credential_id):
        return None


def worker_gateway(db_path=None):
    """A Gateway for `python -m backend.recurring`: the same executor, audit
    log and policy as the server, but it can verify no signature and holds no
    drafts, so the only thing it can do is run_mandate_occurrence()."""
    from backend.config import settings
    from backend.gateway import Gateway, MockExecutor, NonceStore
    db = db_path or DB_PATH
    return Gateway(signer=_NoSignatures(), nonce_store=NonceStore(), audit=AuditLog(db),
                   executor=MockExecutor(db), credentials=_NoCredentials(), drafts=_NoDrafts(),
                   policy_db_path=db, recent_change_hours=settings.recent_change_hours,
                   cooling_hours=settings.credential_cooling_hours)
