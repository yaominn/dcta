"""
Mock bank execution. (brief Section 4.1, Section 8: backend/gateway/)

# MOCK: simulates a bank execution gateway. No real DBS APIs (brief Section 12).

Execution semantics (brief 4.1): sequential, stop at first failure, mark later
legs BLOCKED. For M1 we exercise TRANSFER / PAY_BILL / BUY_EQUITY against the
seeded ledger; amounts are already concrete (the resolver lands in M4), so the
executor does no arithmetic — it only debits the resolved cents. All money is
int cents; no float(), no round() — integers need neither.

M5: an executed TRANSFER now appends a row to transaction_history. Until then
only seed.py ever wrote that table, so the daily-limit total and the velocity
count could never advance from an actual payment — a $20,000 daily cap that
executed transactions did not count against. PAY_BILL and BUY_EQUITY cannot be
recorded there: transaction_history.payee_id is NOT NULL and foreign-keys to
payees, so the table can only represent transfers. Stated, not silently
skipped.
"""
from __future__ import annotations

import json
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from backend.data.db import DB_PATH, connect
from backend.models.contacts import ResolvedContactAdd, ResolvedContactChange
from backend.models.schemas import ResolvedPlan

# Contact fields a signed change may write -> their column. A fixed map, so a
# column name never comes from a payload.
_CONTACT_COLUMNS = {"nickname": "nickname", "phone": "phone"}


class AlreadyExecuted(Exception):
    """This draft has already been through the executor. Carries the original
    execution so the caller can hand it back instead of an error."""

    def __init__(self, prior: dict):
        self.prior = prior
        super().__init__(f"draft {prior['draft_id']} already executed")


class MockExecutor:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    # ------------------------------------------------------------ at most once
    # A fresh nonce and a fresh signature are available for the same draft on
    # every request, and neither says "not again". So the guarantee lives here,
    # at the one place money moves: every execution first CLAIMS its draft_id
    # in `executions` (PRIMARY KEY), inside the same transaction as the debit.
    # A second claim cannot be written; a concurrent one blocks on SQLite's
    # write lock, then fails, and its transaction — debit included — rolls back.

    def prior_execution(self, draft_id: str) -> dict | None:
        """The recorded execution of this draft, or None if it never ran."""
        conn = connect(self.db_path)
        try:
            row = conn.execute("SELECT * FROM executions WHERE draft_id=?",
                               (draft_id,)).fetchone()
        finally:
            conn.close()
        if row is None:
            return None
        return {"draft_id": row["draft_id"], "kind": row["kind"],
                "payload_hash": row["payload_hash"], "outcome": row["outcome"],
                "result": json.loads(row["result"]), "executed_at": row["executed_at"]}

    def _claim(self, conn, draft_id: str, kind: str, payload_hash: str) -> None:
        """First write of the transaction: take the draft, or learn it is taken."""
        try:
            conn.execute("INSERT INTO executions VALUES (?,?,?,?,?,?)",
                         (draft_id, kind, payload_hash, "PENDING", "{}", int(time.time())))
        except sqlite3.IntegrityError:
            conn.rollback()
            prior = self.prior_execution(draft_id)
            raise AlreadyExecuted(prior) from None

    def close(self, draft_id: str, kind: str, payload_hash: str, outcome: str) -> dict:
        """Record that this draft ended WITHOUT running (DECLINED / CANCELLED).

        Same table, same PRIMARY KEY as an execution — deliberately. A decline
        racing a signature is settled by whichever claims the draft first: if
        the payment claimed it, this raises AlreadyExecuted and the user is
        told it was already sent; if this did, the payment's claim fails and
        nothing moves. The user is never told "nothing was sent" about money
        that was."""
        conn = connect(self.db_path)
        try:
            self._claim(conn, draft_id, kind, payload_hash)
            result = {"draft_id": draft_id, "status": outcome}
            self._record(conn, draft_id, result)
            conn.commit()
        finally:
            conn.close()
        return self.prior_execution(draft_id)

    @staticmethod
    def _record(conn, draft_id: str, result: dict) -> None:
        conn.execute("UPDATE executions SET outcome=?, result=? WHERE draft_id=?",
                     (result["status"], json.dumps(result), draft_id))

    # ------------------------------------------------------------ execution
    def execute(self, plan: ResolvedPlan, *, payload_hash: str) -> dict:
        """Run the plan at most once per draft_id. Raises AlreadyExecuted."""
        conn = connect(self.db_path)
        results = []
        aborted = False
        try:
            self._claim(conn, plan.draft_id, "payment", payload_hash)
            for leg in plan.plan:
                if aborted:
                    results.append({"id": leg.id, "type": leg.type, "status": "BLOCKED"})
                    continue
                try:
                    if leg.type == "TRANSFER":
                        self._debit(conn, leg.source_account, leg.amount_cents)
                        # MOCK: external payee credit not modeled in the seed ledger.
                    elif leg.type == "PAY_BILL":
                        self._debit(conn, leg.source_account, leg.amount_cents)
                    elif leg.type == "BUY_EQUITY":
                        self._debit(conn, leg.source_account, leg.amount_cents)
                        # MOCK: whole shares would settle into acct_invest (M4 resolves the count).
                    else:  # pragma: no cover - schema-constrained, unreachable
                        raise RuntimeError(f"unknown intent type {leg.type}")
                    # Recorded here, after the switch, so every executed leg
                    # lands in history exactly once — not only transfers.
                    self._record_leg(conn, leg)
                    results.append({"id": leg.id, "type": leg.type,
                                    "status": "EXECUTED", "amount_cents": leg.amount_cents})
                except Exception as exc:
                    results.append({"id": leg.id, "type": leg.type,
                                    "status": "FAILED", "error": str(exc)})
                    aborted = True
            result = {"draft_id": plan.draft_id, "legs": results,
                      "status": "FAILED" if aborted else "EXECUTED"}
            # A failed execution is recorded too: one draft, one attempt,
            # whatever the outcome — the card the user signed is spent.
            self._record(conn, plan.draft_id, result)
            conn.commit()
        finally:
            conn.close()
        return result

    def apply_contact_change(self, change: ResolvedContactChange, *,
                             payload_hash: str) -> dict:
        """Write a signed contact change. All edits or none.

        Each UPDATE is conditional on the stored value still being the OLD value
        the user saw and signed. If it changed since (another edit, another
        device), nothing is written: the user approved "X -> Y", not "whatever
        it is now -> Y"."""
        conn = connect(self.db_path)
        results = []
        try:
            self._claim(conn, change.draft_id, "contact_edit", payload_hash)
            # Edits in a savepoint: a stale value undoes the edits but KEEPS the
            # claim, so a failed change is recorded as this draft's one attempt.
            conn.execute("SAVEPOINT edits")
            result = None
            for e in change.edits:
                col = _CONTACT_COLUMNS[e.field]
                cur = conn.execute(
                    f"UPDATE payees SET {col}=? WHERE id=? AND COALESCE({col}, '')=?",
                    (e.new_value, e.payee_id, e.old_value))
                if cur.rowcount != 1:
                    conn.execute("ROLLBACK TO SAVEPOINT edits")
                    result = {"draft_id": change.draft_id, "status": "FAILED",
                              "error": f"{e.payee_display}'s {e.field} changed since this "
                                       "draft was made — nothing was updated",
                              "changes": []}
                    break
                if e.field == "phone":
                    # A new number is a new DESTINATION: bump its version and
                    # record when, in the same savepoint. A transfer drafted for
                    # the old number is now SUPERSEDED, and the scam rules see a
                    # recent change (backend/data/destinations.py).
                    conn.execute("UPDATE payees SET dest_version = dest_version + 1, "
                                 "dest_changed_at = ? WHERE id = ?", (int(time.time()), e.payee_id))
                results.append({"payee_display": e.payee_display, "field": e.field,
                                "old_value": e.old_value, "new_value": e.new_value,
                                "status": "UPDATED"})
            conn.execute("RELEASE SAVEPOINT edits")
            if result is None:
                result = {"draft_id": change.draft_id, "status": "UPDATED", "changes": results}
            self._record(conn, change.draft_id, result)
            conn.commit()
        finally:
            conn.close()
        return result

    def add_contact(self, add: ResolvedContactAdd, *, payload_hash: str) -> dict:
        """Write a signed new contact, with the hold it was signed with. At most
        once per draft, like everything else here.

        Refused (FAILED, nothing written) if the number was saved as another
        contact after the draft was made: the user approved adding a NEW
        destination, not a second name for an existing one."""
        conn = connect(self.db_path)
        try:
            self._claim(conn, add.draft_id, "contact_add", payload_hash)
            now = int(time.time())
            taken = conn.execute("SELECT nickname, last4 FROM payees WHERE user_id=? AND phone=?",
                                 (add.user_id, add.phone)).fetchone()
            if taken is not None:
                result = {"draft_id": add.draft_id, "status": "FAILED",
                          "error": f"that number was saved as {taken['nickname']} "
                                   f"\u00b7\u00b7{taken['last4']} since this draft was made "
                                   "\u2014 nothing was added"}
            else:
                payee_id = "payee_" + secrets.token_hex(4)
                hold_until = now + add.hold_minutes * 60 if add.hold_minutes else None
                # legal_name: a real bank would fill it from the PayNow lookup
                # of this number. There is no directory in the mock, so it is
                # left empty rather than invented.
                # A brand-new destination: version 1, "changed" now — so the
                # scam rules treat its first payments as a new destination.
                conn.execute(
                    "INSERT INTO payees (id, user_id, nickname, legal_name, last4, phone, "
                    "added_at, hold_until, dest_version, dest_changed_at) "
                    "VALUES (?,?,?,?,?,?,?,?,1,?)",
                    (payee_id, add.user_id, add.nickname, "",
                     re.sub(r"\D", "", add.phone)[-4:], add.phone, now, hold_until, now))
                result = {"draft_id": add.draft_id, "status": "ADDED",
                          "contact": {"payee_display": add.payee_display,
                                      "nickname": add.nickname, "phone": add.phone,
                                      "hold_until": hold_until}}
            self._record(conn, add.draft_id, result)
            conn.commit()
        finally:
            conn.close()
        return result

    def _record_leg(self, conn, leg) -> None:
        """Append EVERY executed leg to transaction_history, so the M5 daily and
        velocity rules see all the money that actually moved.

        This used to record transfers only, because payee_id was NOT NULL. The
        effect was that a $19,000 equity purchase left no trace and "daily
        limit" silently meant "daily TRANSFER limit" — a user could exceed it by
        mixing leg types across drafts. payee_id is nullable now and leg_type
        says what moved; the anomaly rule still matches on payee_id, so rows
        without one cannot pollute a per-payee baseline.

        The user is read from the debited account rather than taken on trust."""
        row = conn.execute("SELECT user_id FROM accounts WHERE id=?",
                           (leg.source_account,)).fetchone()
        if row is None:  # pragma: no cover - _debit already raised
            return
        conn.execute(
            "INSERT INTO transaction_history (user_id, payee_id, leg_type, amount, ts, "
            "dest_version) VALUES (?,?,?,?,?,?)",
            (row["user_id"], getattr(leg, "payee_id", None), leg.type,
             leg.amount_cents, datetime.now(timezone.utc).isoformat(),
             getattr(leg, "destination_version", None)),   # which destination was paid
        )

    def _debit(self, conn, account_id: str, amount_cents: int) -> None:
        row = conn.execute("SELECT balance FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"unknown account {account_id}")
        bal = row["balance"]
        if bal < amount_cents:
            raise RuntimeError(f"insufficient funds in {account_id}: {bal}c < {amount_cents}c")
        conn.execute("UPDATE accounts SET balance=? WHERE id=?", (bal - amount_cents, account_id))
