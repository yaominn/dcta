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
import sqlite3
import time
from datetime import datetime, timezone

from backend.data.db import DB_PATH, connect
from backend.models.contacts import ResolvedContactChange
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
            "INSERT INTO transaction_history (user_id, payee_id, leg_type, amount, ts) "
            "VALUES (?,?,?,?,?)",
            (row["user_id"], getattr(leg, "payee_id", None), leg.type,
             leg.amount_cents, datetime.now(timezone.utc).isoformat()),
        )

    def _debit(self, conn, account_id: str, amount_cents: int) -> None:
        row = conn.execute("SELECT balance FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"unknown account {account_id}")
        bal = row["balance"]
        if bal < amount_cents:
            raise RuntimeError(f"insufficient funds in {account_id}: {bal}c < {amount_cents}c")
        conn.execute("UPDATE accounts SET balance=? WHERE id=?", (bal - amount_cents, account_id))
