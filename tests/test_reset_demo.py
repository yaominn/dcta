"""
`python -m backend.data.reset_demo` restores the demo's money (and any demo
contacts removed while practising) and nothing else.

A full re-seed also drops registered passkeys, forcing the presenter to
re-enroll Touch ID right before the demo. This resets balances and the
payment history (the anomaly / limit baseline) and must leave the passkey,
contact edits, the audit log and the executions table exactly as they were.
"""
from __future__ import annotations

import contextlib
import io
import sqlite3
import time

from backend.data.db import connect
from backend.data.reset_demo import reset_demo
from backend.data.seed import ACCOUNTS, PAYEES, seed


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


def test_contacts_removed_in_a_rehearsal_come_back(tmp_path):
    """Removing Mom while practising mustn't break the demo. Not if a contact
    added since has the same number or name: one number, one contact, and no
    second "Mom" to choose between. The seeded Johns share a name on purpose."""
    db = tmp_path / "ledger.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    conn = connect(db)
    try:
        conn.execute("UPDATE payees SET removed_at=1 WHERE id IN "
                     "('payee_17', 'payee_21', 'payee_30')")
        conn.executemany(
            "INSERT INTO payees (id, user_id, nickname, legal_name, last4, phone, added_at) "
            "VALUES (?, 'u_alice', ?, '', ?, ?, 1)",
            [("payee_re", "Landlord", "7001", "+65 6123 7001"),      # same number
             ("payee_mum", "mom", "4321", "+65 8765 4321")])         # same name
        conn.commit()
    finally:
        conn.close()

    out = reset_demo(db)

    conn = connect(db)
    try:
        removed = {r["id"]: r["removed_at"] for r in conn.execute("SELECT id, removed_at FROM payees")}
    finally:
        conn.close()
    assert removed["payee_21"] is None                           # John ··4521 is back
    assert removed["payee_17"] is not None and removed["payee_30"] is not None
    assert removed["payee_re"] is None and removed["payee_mum"] is None
    assert out["not_restored"] == ["Landlord ··7001", "Mom ··3310"]


# payees before removed_at (contact removal): the shape an older demo DB has.
_PAYEES_BEFORE_REMOVED_AT = """
    CREATE TABLE payees (
        id              TEXT PRIMARY KEY,
        user_id         TEXT NOT NULL REFERENCES users(id),
        nickname        TEXT NOT NULL,
        legal_name      TEXT NOT NULL,
        last4           TEXT NOT NULL,
        phone           TEXT,
        added_at        INTEGER,
        hold_until      INTEGER,
        dest_version    INTEGER NOT NULL DEFAULT 1,
        dest_changed_at INTEGER
    )"""


def test_reset_brings_an_old_ledger_up_to_date_first(tmp_path):
    """A ledger from before removed_at, reset before the new server has ever
    started (startup is what migrates).

    The old table is swapped in rather than made with ALTER TABLE ... DROP
    COLUMN: that failed its schema check on Zach's machine ("error in table
    payees after drop column"; fine on SQLite 3.53.4). No ALTER at all here."""
    db = tmp_path / "ledger.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    cols = ("id, user_id, nickname, legal_name, last4, phone, added_at, hold_until, "
            "dest_version, dest_changed_at")
    conn = sqlite3.connect(db)          # foreign keys off (the default): payees can be swapped
    try:
        rows = conn.execute(f"SELECT {cols} FROM payees").fetchall()
        conn.execute("DROP TABLE payees")
        conn.execute(_PAYEES_BEFORE_REMOVED_AT)
        conn.executemany(f"INSERT INTO payees ({cols}) VALUES ({', '.join('?' * 10)})", rows)
        conn.commit()
    finally:
        conn.close()

    out = reset_demo(db)

    conn = connect(db)
    try:
        cols_now = {r["name"] for r in conn.execute("PRAGMA table_info(payees)")}
        payees = conn.execute("SELECT COUNT(*), COUNT(removed_at) FROM payees").fetchone()
    finally:
        conn.close()
    assert "removed_at" in cols_now
    assert tuple(payees) == (len(rows), 0) and len(rows) == len(PAYEES)      # every contact kept, none removed
    assert out["balances"] == {a[0]: a[3] for a in ACCOUNTS}          # and the reset itself ran
    assert out["history_rows"] == 18 and out["not_restored"] == []
