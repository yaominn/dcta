"""
`python -m backend.data.reset_demo` restores the demo's money and nothing else.

A full re-seed also drops registered passkeys, forcing the presenter to
re-enroll Touch ID right before the demo. This resets balances and the
payment history (the anomaly / limit baseline) and must leave the passkey,
contact edits, the audit log and the executions table exactly as they were.
"""
from __future__ import annotations

import contextlib
import io
import time

from backend.data.db import connect
from backend.data.reset_demo import reset_demo
from backend.data.seed import ACCOUNTS, seed


def test_reset_restores_money_and_keeps_identity(tmp_path):
    db = tmp_path / "ledger.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    conn = connect(db)
    try:
        # A rehearsal happened: money spent, payments recorded, a passkey
        # registered, a contact renamed, a draft executed, an audit entry.
        conn.execute("UPDATE accounts SET balance=1250 WHERE id='acct_savings'")
        conn.execute("UPDATE accounts SET balance=20000 WHERE id='acct_joint'")
        conn.execute("INSERT INTO transaction_history (user_id, payee_id, leg_type, amount, ts) "
                     "VALUES ('u_alice','payee_22','TRANSFER',200,'2026-09-25T00:00:00+00:00')")
        conn.execute("INSERT INTO webauthn_credentials VALUES (?,?,?,?,?)",
                     ("cred_touchid", "u_alice", b"cose", 7, int(time.time())))
        conn.execute("UPDATE payees SET nickname='Jonny' WHERE id='payee_22'")
        conn.execute("INSERT INTO executions VALUES (?,?,?,?,?,?)",
                     ("old-draft", "payment", "h", "EXECUTED", "{}", int(time.time())))
        conn.commit()
    finally:
        conn.close()

    out = reset_demo(db)

    conn = connect(db)
    try:
        balances = {r["id"]: r["balance"] for r in conn.execute("SELECT id, balance FROM accounts")}
        history = conn.execute("SELECT COUNT(*) FROM transaction_history").fetchone()[0]
        on_22 = conn.execute("SELECT COUNT(*) FROM transaction_history "
                             "WHERE payee_id='payee_22'").fetchone()[0]
        passkey = conn.execute("SELECT sign_count FROM webauthn_credentials "
                               "WHERE credential_id='cred_touchid'").fetchone()
        nickname = conn.execute("SELECT nickname FROM payees WHERE id='payee_22'").fetchone()[0]
        executed = conn.execute("SELECT COUNT(*) FROM executions").fetchone()[0]
    finally:
        conn.close()

    assert balances == {a[0]: a[3] for a in ACCOUNTS}            # seeded balances
    assert history == 18 and on_22 == 0                          # seeded baseline only
    assert passkey is not None and passkey["sign_count"] == 7     # passkey untouched
    assert nickname == "Jonny"                                   # contact edit kept
    assert executed == 1                                         # old draft stays spent
    assert out["passkeys_kept"] == 1


def test_an_unseeded_ledger_gets_a_clear_message(tmp_path):
    import pytest
    with pytest.raises(SystemExit, match="run `python -m backend.data.seed` first"):
        reset_demo(tmp_path / "empty.db")
