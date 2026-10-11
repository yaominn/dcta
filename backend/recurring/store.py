"""
Recurring mandates and their occurrences, in SQLite — and the checks that run
INSIDE the executor's write transaction.

Most functions take an open connection so the caller decides the transaction.
The two hooks the executor calls (execution_refusal, record_execution) run
after it has claimed the occurrence's execution key and before it commits:
SQLite then holds the write lock, so a pause, a cancel, a biller change or a
second worker cannot land between the check and the debit. Whichever commits
first wins, and the loser sees the winner's state.

Statuses (docs/RECURRING_BILLS.md):

  mandate     ACTIVE | PAUSED | SUSPENDED (a safety stop: new terms needed)
              | CANCELLED | COMPLETED
  occurrence  SCHEDULED -> PENDING_APPROVAL (supervised: waiting for the user)
                        -> EXECUTED | FAILED | DECLINED | EXPIRED | CANCELLED
              SCHEDULED -> (automatic) EXECUTED | FAILED | HELD | NEEDS_REVIEW
              SCHEDULED -> MISSED (its day passed with no run) | SKIPPED (paused)
              HELD / NEEDS_REVIEW can still be approved by the user, like a
              supervised one, until review_until; then EXPIRED.
"""
from __future__ import annotations

import secrets

from backend.audit.canonical import canonical_json, payload_hash
from backend.data import billers as _billers
from backend.data.db import DB_PATH, connect
from backend.display import cents_to_display
from backend.models.mandates import RecurringBillMandate
from backend.recurring import schedule
from backend.recurring.terms import matches_terms

SIGNATURE, MANDATE = "signature", "mandate"           # who authorizes an execution
APPROVABLE = ("PENDING_APPROVAL", "NEEDS_REVIEW", "HELD")
OPEN = ("SCHEDULED",) + APPROVABLE
TERMINAL = ("EXECUTED", "FAILED", "DECLINED", "EXPIRED", "MISSED", "SKIPPED", "CANCELLED")


# --------------------------------------------------------------------------- create / read
def create(conn, terms: RecurringBillMandate, *, payload_hash_hex: str, credential_id: str,
           now: int) -> None:
    """Store a signed mandate and every occurrence it allows. The caller holds
    the transaction (the executor, after claiming the enrollment draft)."""
    conn.execute(
        "INSERT INTO mandates (mandate_id, version, user_id, terms, payload_hash, credential_id, "
        "draft_id, status, mode, created_at, updated_at) VALUES (?,?,?,?,?,?,?,'ACTIVE',"
        "'SUPERVISED',?,?)",
        (terms.mandate_id, terms.version, terms.user_id, canonical_json(terms.model_dump()),
         payload_hash_hex, credential_id, terms.draft_id, now, now))
    for seq, d in enumerate(terms.due_dates(), 1):
        conn.execute(
            "INSERT INTO mandate_occurrences (mandate_id, seq, due_date, due_at, auto_until, "
            "review_until, draft_id, status, updated_at) VALUES (?,?,?,?,?,?,?,'SCHEDULED',?)",
            (terms.mandate_id, seq, d.isoformat(), schedule.due_at(d, terms.timezone),
             schedule.day_end(d, terms.timezone), schedule.review_until(d, terms.timezone),
             # The execution key: unguessable like any draft id, and the ONE
             # key either path must claim to debit this occurrence.
             "occ_" + secrets.token_urlsafe(16), now))


def load_terms(row) -> RecurringBillMandate | None:
    """The stored terms, if they are still exactly what was signed: valid, the
    same hash, the same id, version and user as the row. None otherwise — and
    None stops every payment (fail closed on a tampered or unreadable row)."""
    try:
        terms = RecurringBillMandate.model_validate_json(row["terms"])
    except Exception:
        return None
    if (payload_hash(terms) != row["payload_hash"] or terms.mandate_id != row["mandate_id"]
            or terms.version != row["version"] or terms.user_id != row["user_id"]):
        return None
    return terms


def get_mandate(conn, mandate_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM mandates WHERE mandate_id=?", (mandate_id,)).fetchone()
    return dict(row) if row else None


def mandates_for(conn, user_id: str) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM mandates WHERE user_id=? ORDER BY created_at DESC", (user_id,))]


def occurrences(conn, mandate_id: str) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM mandate_occurrences WHERE mandate_id=? ORDER BY seq", (mandate_id,))]


def occurrence(conn, mandate_id: str, seq: int) -> dict | None:
    row = conn.execute("SELECT * FROM mandate_occurrences WHERE mandate_id=? AND seq=?",
                       (mandate_id, seq)).fetchone()
    return dict(row) if row else None


def occurrence_for_draft(conn, draft_id: str) -> dict | None:
    row = conn.execute("SELECT * FROM mandate_occurrences WHERE draft_id=?",
                       (draft_id,)).fetchone()
    return dict(row) if row else None


def pending_for(conn, user_id: str, now: int) -> list[dict]:
    """Occurrences the user can approve right now, oldest first."""
    marks = ",".join("?" * len(APPROVABLE))
    return [dict(r) for r in conn.execute(
        f"SELECT o.* FROM mandate_occurrences o JOIN mandates m USING (mandate_id) "
        f"WHERE m.user_id=? AND m.status='ACTIVE' AND o.status IN ({marks}) "
        f"AND o.due_at<=? AND o.review_until>=? ORDER BY o.due_at, o.seq",
        (user_id, *APPROVABLE, now, now))]


# --------------------------------------------------------------------------- notifications
def notify(conn, user_id: str, kind: str, title: str, body: str, *, now: int,
           mandate_id: str | None = None, seq: int | None = None) -> None:
    """Text only — never a link, never anything that approves a payment."""
    conn.execute("INSERT INTO notifications (user_id, kind, title, body, mandate_id, seq, "
                 "created_at) VALUES (?,?,?,?,?,?,?)",
                 (user_id, kind, title, body, mandate_id, seq, now))


def notifications(conn, user_id: str, *, limit: int = 50, after_id: int = 0) -> list[dict]:
    return [dict(r) for r in conn.execute(
        "SELECT * FROM notifications WHERE user_id=? AND id>? ORDER BY id DESC LIMIT ?",
        (user_id, after_id, limit))]


def money(terms: RecurringBillMandate) -> str:
    return "$" + cents_to_display(terms.amount_cents)


def describe(terms: RecurringBillMandate, seq: int) -> str:
    return (f"{terms.biller_display} payment {seq} of {terms.occurrence_count} "
            f"({money(terms)} from {terms.source_display})")


# --------------------------------------------------------------------------- state changes
def set_occurrence(conn, mandate_id: str, seq: int, *, frm: tuple, to: str, now: int,
                   reason: str | None = None, phase: str | None = None) -> bool:
    """Move one occurrence from any of `frm` to `to`. Conditional, so two
    workers (or a worker and the user) can't both move it: False = someone
    else already did."""
    marks = ",".join("?" * len(frm))
    cur = conn.execute(
        f"UPDATE mandate_occurrences SET status=?, reason=?, phase=COALESCE(?, phase), "
        f"updated_at=? WHERE mandate_id=? AND seq=? AND status IN ({marks})",
        (to, reason, phase, now, mandate_id, seq, *frm))
    return cur.rowcount == 1


def set_mandate(conn, mandate_id: str, *, frm: tuple, to: str, now: int,
                reason: str | None = None, user_id: str | None = None) -> bool:
    marks = ",".join("?" * len(frm))
    owner = " AND user_id=?" if user_id is not None else ""
    cur = conn.execute(
        f"UPDATE mandates SET status=?, status_reason=?, updated_at=? WHERE mandate_id=? "
        f"AND status IN ({marks}){owner}",
        (to, reason, now, mandate_id, *frm, *((user_id,) if user_id is not None else ())))
    return cur.rowcount == 1


def suspend(conn, mandate, terms, reason: str, *, now: int) -> bool:
    """A safety stop the user can't simply resume: the terms no longer match
    the world (the biller's reference changed) or the record can't be trusted.
    New terms need a new signature."""
    if not set_mandate(conn, mandate["mandate_id"], frm=("ACTIVE", "PAUSED"), to="SUSPENDED",
                       now=now, reason=reason):
        return False
    name = terms.biller_display if terms else "A recurring payment"
    notify(conn, mandate["user_id"], "SUSPENDED", f"{name}: automatic payments stopped",
           f"{reason} Nothing more will be paid under this arrangement. To keep paying, "
           f"review the details and set it up again.", now=now, mandate_id=mandate["mandate_id"])
    return True


def _immediate(db_path):
    conn = connect(db_path or DB_PATH)
    conn.execute("BEGIN IMMEDIATE")
    return conn


def pause(mandate_id: str, user_id: str, *, now: int, db_path=None) -> dict | None:
    """ACTIVE -> PAUSED, at once and durably. Takes the write lock, so it
    serialises with a payment in progress: either that payment committed first
    (and is reported), or it will find the mandate paused and not run."""
    conn = _immediate(db_path)
    try:
        m = get_mandate(conn, mandate_id)
        if m is None or m["user_id"] != user_id:
            conn.rollback()
            return None
        if set_mandate(conn, mandate_id, frm=("ACTIVE",), to="PAUSED", now=now,
                       reason="paused by you", user_id=user_id):
            terms = load_terms(m)
            notify(conn, user_id, "PAUSED", f"{terms.biller_display if terms else 'Recurring'}"
                   f" payments paused", "Nothing will be paid while it's paused, and payments "
                   "that fall due meanwhile are skipped, not paid later.", now=now,
                   mandate_id=mandate_id)
        conn.commit()
        return get_mandate(conn, mandate_id)
    finally:
        conn.close()


def resume(mandate_id: str, user_id: str, *, now: int, db_path=None) -> dict | None:
    """PAUSED -> ACTIVE. Payments skipped while paused stay skipped."""
    conn = _immediate(db_path)
    try:
        m = get_mandate(conn, mandate_id)
        if m is None or m["user_id"] != user_id:
            conn.rollback()
            return None
        if set_mandate(conn, mandate_id, frm=("PAUSED",), to="ACTIVE", now=now, reason=None,
                       user_id=user_id):
            terms = load_terms(m)
            notify(conn, user_id, "RESUMED", f"{terms.biller_display if terms else 'Recurring'}"
                   f" payments resumed", "Payments due from now on go ahead as agreed. "
                   "Anything skipped while paused was not paid.", now=now, mandate_id=mandate_id)
        conn.commit()
        return get_mandate(conn, mandate_id)
    finally:
        conn.close()


def cancel(mandate_id: str, user_id: str, *, now: int, db_path=None) -> dict | None:
    """-> CANCELLED, final. Every occurrence not yet paid is cancelled with it."""
    conn = _immediate(db_path)
    try:
        m = get_mandate(conn, mandate_id)
        if m is None or m["user_id"] != user_id:
            conn.rollback()
            return None
        if set_mandate(conn, mandate_id, frm=("ACTIVE", "PAUSED", "SUSPENDED"), to="CANCELLED",
                       now=now, reason="cancelled by you", user_id=user_id):
            marks = ",".join("?" * len(OPEN))
            conn.execute(f"UPDATE mandate_occurrences SET status='CANCELLED', "
                         f"reason='arrangement cancelled', updated_at=? WHERE mandate_id=? "
                         f"AND status IN ({marks})", (now, mandate_id, *OPEN))
            terms = load_terms(m)
            notify(conn, user_id, "CANCELLED", f"{terms.biller_display if terms else 'Recurring'}"
                   f" payments cancelled", "Nothing more will be paid under this arrangement.",
                   now=now, mandate_id=mandate_id)
        conn.commit()
        return get_mandate(conn, mandate_id)
    finally:
        conn.close()


# --------------------------------------------------------------------------- inside the executor's transaction
def execution_refusal(conn, occ: dict, plan, *, authority: str, now: int) -> str | None:
    """Why this occurrence must NOT be debited now, or None. Runs under the
    executor's write lock, after the gateway's own (fuller) checks: this is the
    last word, so it re-reads everything that can change underneath."""
    m = get_mandate(conn, occ["mandate_id"])
    if m is None:
        return "this recurring arrangement no longer exists"
    terms = load_terms(m)
    if terms is None:
        return "this arrangement's record doesn't match what you signed"
    if m["status"] != "ACTIVE":
        return f"this arrangement is {m['status'].lower()}"
    if not matches_terms(plan, terms):
        return "this isn't the payment the arrangement allows"
    if (m["paid_count"] >= terms.occurrence_count
            or m["paid_total_cents"] + terms.amount_cents > terms.total_cap_cents):
        return "this would go over the arrangement's limit"
    if now > terms.valid_until:
        return "this arrangement has ended"
    if not _billers.matches(conn, terms.biller_id, terms.biller_ref_version, terms.biller_ref_hash):
        return f"{terms.biller_display}'s payment details changed since you set this up"
    row = conn.execute("SELECT user_id FROM accounts WHERE id=?",
                       (terms.source_account,)).fetchone()
    if row is None or row["user_id"] != terms.user_id:
        return "the account to pay from isn't the arrangement holder's"
    if authority == SIGNATURE:
        if occ["status"] not in APPROVABLE:
            return f"this payment is {occ['status'].lower().replace('_', ' ')}"
        if not occ["due_at"] <= now <= occ["review_until"]:
            return "this payment isn't open for approval now"
        return None
    if authority == MANDATE:
        if occ["phase"] != "AUTO" or occ["status"] != "SCHEDULED":
            return "this payment isn't one the arrangement pays automatically"
        if (m["mode"] != "AUTO" or not terms.auto_after_supervised
                or m["supervised_successes"] < terms.supervised_approvals):
            return "automatic payment isn't switched on for this arrangement"
        if not occ["due_at"] <= now <= occ["auto_until"]:
            return "an automatic payment only runs on its due date"
        return None
    return "unknown authority"


def record_execution(conn, occ: dict, result: dict, *, authority: str, now: int) -> None:
    """The executor's result, recorded with the debit (same transaction): the
    occurrence's outcome, the mandate's counters, the switch to automatic
    payment after the third individually approved one, and the notification.
    A notification that can't be written rolls the payment back with it."""
    m = get_mandate(conn, occ["mandate_id"])
    terms = load_terms(m)
    mid, seq, user = occ["mandate_id"], occ["seq"], m["user_id"]
    if result["status"] != "EXECUTED":
        error = next((leg.get("error") for leg in result.get("legs", []) if leg.get("error")),
                     "the payment failed")
        set_occurrence(conn, mid, seq, frm=OPEN, to="FAILED", now=now, reason=error)
        notify(conn, user, "FAILED", f"{terms.biller_display} payment {seq} failed",
               f"{describe(terms, seq)} didn't go through: {error}. Nothing was debited, and it "
               f"won't be retried — pay it yourself if you need to.", now=now,
               mandate_id=mid, seq=seq)
        return
    set_occurrence(conn, mid, seq, frm=OPEN, to="EXECUTED", now=now)
    counts = authority == SIGNATURE and occ["phase"] == "SUPERVISED"
    successes = m["supervised_successes"] + (1 if counts else 0)
    paid = m["paid_count"] + 1
    mode = m["mode"]
    if (mode == "SUPERVISED" and terms.auto_after_supervised
            and successes >= terms.supervised_approvals):
        mode = "AUTO"
    status = "COMPLETED" if paid >= terms.occurrence_count else m["status"]
    conn.execute("UPDATE mandates SET supervised_successes=?, paid_count=?, "
                 "paid_total_cents=paid_total_cents+?, mode=?, status=?, updated_at=? "
                 "WHERE mandate_id=?",
                 (successes, paid, terms.amount_cents, mode, status, now, mid))
    automatic = authority == MANDATE
    notify(conn, user, "AUTO_PAID" if automatic else "PAID",
           f"{terms.biller_display} paid automatically" if automatic
           else f"{terms.biller_display} paid",
           f"{describe(terms, seq)} was paid"
           + (" automatically under your recurring arrangement" if automatic
              else " with your approval")
           + f" on {schedule.label(schedule.local_date(now, terms.timezone))}. "
           + f"Receipt: {occ['draft_id']}.", now=now, mandate_id=mid, seq=seq)
    if mode == "AUTO" and m["mode"] == "SUPERVISED" and status != "COMPLETED":
        notify(conn, user, "AUTO_ON", f"{terms.biller_display}: automatic payments start next",
               f"You've approved {successes} payments. As you agreed when you set this up, the "
               f"remaining ones will be paid automatically on their due dates — "
               f"{money(terms)} each, at most {terms.occurrence_count - paid} more. You'll be "
               f"told after each one, and you can pause or cancel at any time.",
               now=now, mandate_id=mid)
    if status == "COMPLETED":
        notify(conn, user, "COMPLETED", f"{terms.biller_display}: all payments made",
               f"All {terms.occurrence_count} payments under this arrangement are done.",
               now=now, mandate_id=mid)


def record_closed(conn, occ: dict, outcome: str, *, now: int) -> None:
    """The user declined (or the kill switch cancelled) an occurrence's
    approval. Final: it isn't paid, isn't retried, and doesn't count."""
    to = "DECLINED" if outcome == "DECLINED" else "CANCELLED"
    if not set_occurrence(conn, occ["mandate_id"], occ["seq"], frm=APPROVABLE, to=to, now=now,
                          reason="declined by you" if to == "DECLINED" else "cancelled"):
        return
    m = get_mandate(conn, occ["mandate_id"])
    terms = load_terms(m)
    if terms is not None:
        notify(conn, m["user_id"], to, f"{terms.biller_display} payment {occ['seq']} not made",
               f"{describe(terms, occ['seq'])} was {to.lower()}. Nothing was paid, and it won't "
               f"be retried. It doesn't count towards the approvals before automatic payment.",
               now=now, mandate_id=occ["mandate_id"], seq=occ["seq"])
