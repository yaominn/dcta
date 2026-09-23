"""
Mock bank execution. (brief Section 4.1, Section 8: backend/gateway/)

# MOCK: simulates a bank execution gateway. No real DBS APIs (brief Section 12).

Execution semantics (brief 4.1): sequential, stop at first failure, mark later
legs BLOCKED. For M1 we exercise TRANSFER / PAY_BILL / BUY_EQUITY against the
seeded ledger; amounts are already concrete (the resolver lands in M4), so the
executor does no arithmetic — it only debits the resolved cents. All money is
int cents; no float(), no round() — integers need neither.
"""
from __future__ import annotations

from backend.data.db import DB_PATH, connect
from backend.models.schemas import ResolvedPlan


class MockExecutor:
    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path

    def execute(self, plan: ResolvedPlan) -> dict:
        conn = connect(self.db_path)
        results = []
        aborted = False
        try:
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
                    results.append({"id": leg.id, "type": leg.type,
                                    "status": "EXECUTED", "amount_cents": leg.amount_cents})
                except Exception as exc:
                    results.append({"id": leg.id, "type": leg.type,
                                    "status": "FAILED", "error": str(exc)})
                    aborted = True
            conn.commit()
        finally:
            conn.close()
        return {"draft_id": plan.draft_id, "legs": results,
                "status": "FAILED" if aborted else "EXECUTED"}

    def _debit(self, conn, account_id: str, amount_cents: int) -> None:
        row = conn.execute("SELECT balance FROM accounts WHERE id=?", (account_id,)).fetchone()
        if row is None:
            raise RuntimeError(f"unknown account {account_id}")
        bal = row["balance"]
        if bal < amount_cents:
            raise RuntimeError(f"insufficient funds in {account_id}: {bal}c < {amount_cents}c")
        conn.execute("UPDATE accounts SET balance=? WHERE id=?", (bal - amount_cents, account_id))
