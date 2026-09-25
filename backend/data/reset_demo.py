"""
Reset the demo's MONEY without touching who you are.

    python -m backend.data.reset_demo

Rehearsing a demo spends the seeded balances and adds payments to the history
that the anomaly and limit rules read — after a few runs, "send 50 to john
from my savings" fails for want of funds, and a payee you practised with no
longer counts as "first-ever". A full `python -m backend.data.seed` fixes that
but also DROPS the registered passkeys, so the presenter must re-enroll Touch
ID minutes before going on stage.

This restores exactly two things to their seeded state:
  - account balances
  - the transaction history (the baseline for anomaly, daily-limit and
    velocity checks)

and deliberately keeps everything else:
  - registered passkeys          (no re-enrolling)
  - payee names and phone edits  (the demo may rely on them)
  - the audit log                (append-only by design; never rewritten)
  - the executions table         (an old draft must stay spent)

Run it with the server up or down: the server reads balances per request.
"""
from __future__ import annotations

from pathlib import Path

from backend.data.db import DB_PATH, connect
from backend.data.seed import ACCOUNTS, _history_rows


def reset_demo(db_path: Path = DB_PATH) -> dict:
    """Restore seeded balances and history. Returns what it did, for the CLI."""
    conn = connect(db_path)
    try:
        if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' "
                        "AND name='accounts'").fetchone() is None:
            raise SystemExit("No demo ledger yet — run `python -m backend.data.seed` first.")
        for acct_id, _user, _alias, balance, _type in ACCOUNTS:
            conn.execute("UPDATE accounts SET balance=? WHERE id=?", (balance, acct_id))
        conn.execute("DELETE FROM transaction_history")
        # The seed's own rows and statement shape: one baseline, not two copies.
        conn.executemany(
            "INSERT INTO transaction_history (user_id, payee_id, leg_type, amount, ts) "
            "VALUES (?,?,'TRANSFER',?,?)",
            _history_rows())
        conn.commit()
        balances = {r["id"]: r["balance"] for r in conn.execute("SELECT id, balance FROM accounts")}
        history = conn.execute("SELECT COUNT(*) FROM transaction_history").fetchone()[0]
        passkeys = conn.execute("SELECT COUNT(*) FROM webauthn_credentials").fetchone()[0]
    finally:
        conn.close()
    return {"balances": balances, "history_rows": history, "passkeys_kept": passkeys}


if __name__ == "__main__":
    from backend.display import account_label, cents_to_display

    out = reset_demo()
    print("Demo money reset.")
    for acct_id, cents in sorted(out["balances"].items()):
        print(f"  {account_label(acct_id):12} ${cents_to_display(cents)}")
    print(f"  history: {out['history_rows']} seeded payments")
    print(f"  kept: {out['passkeys_kept']} registered passkey(s), contact names, audit log")
