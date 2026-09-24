"""
Seed tests — prove the mock ledger matches brief Section 13 and the headline
arithmetic is locked in for the resolver (M4).
"""
from __future__ import annotations

import pytest

from backend.data import seed
from backend.data.db import get_conn


@pytest.fixture(scope="module", autouse=True)
def _seeded():
    seed.seed()  # idempotent
    yield


def _count(table: str) -> int:
    conn = get_conn()
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_users_seeded():
    assert _count("users") == 2
    conn = get_conn()
    try:
        bob = conn.execute("SELECT * FROM users WHERE id='u_bob'").fetchone()
        alice = conn.execute("SELECT * FROM users WHERE id='u_alice'").fetchone()
    finally:
        conn.close()
    assert bob["kyc_status"] == "PENDING"           # KYC gate target
    assert alice["kyc_status"] == "VERIFIED"
    assert alice["investment_eligible"] == 1          # can buy equity


def test_accounts_seeded():
    assert _count("accounts") == 3
    conn = get_conn()
    try:
        sav = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()
    finally:
        conn.close()
    assert sav["balance"] == 842050          # $8,420.50 in cents (int, not float)


def test_payees_seeded_with_two_johns():
    """payee_21 and payee_22 both nickname 'John' -> forces disambiguation (brief 4.4)."""
    assert _count("payees") == 4
    conn = get_conn()
    try:
        johns = conn.execute("SELECT * FROM payees WHERE nickname='John'").fetchall()
    finally:
        conn.close()
    assert len(johns) == 2
    last4s = {j["last4"] for j in johns}
    assert last4s == {"4521", "8892"}


def test_malicious_biller_reference_seeded():
    """biller_07 carries the injection in reference_text (brief 4.3). The M3
    sanitizer test will prove this string never reaches a prompt."""
    assert _count("billers") == 2
    conn = get_conn()
    try:
        b7 = conn.execute("SELECT * FROM billers WHERE id='biller_07'").fetchone()
    finally:
        conn.close()
    assert "ignore previous instructions" in b7["reference_text"]


def test_history_anomaly_baseline():
    """12x $50 (5000c) to payee_21 (median 5000c) -> 'fifty thousand' is 1000x, anomaly fires."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT amount FROM transaction_history WHERE payee_id='payee_21'"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 12
    assert all(r["amount"] == 5000 for r in rows)   # $50.00 in cents


def test_headline_arithmetic():
    """842050 - 50000 = 792050 -> 32 whole AAPL @ 24150 = 772800, remainder 19250.
    All integer cents — no floats, no round(), no drift."""
    conn = get_conn()
    try:
        bal = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
        price = conn.execute("SELECT price FROM equities WHERE ticker='AAPL'").fetchone()[0]
    finally:
        conn.close()
    after = bal - 50000
    shares = after // price
    assert shares == 32
    assert shares * price == 772800
    assert after - shares * price == 19250


def test_reset_audit_repairs_a_tampered_chain(tmp_path):
    """After a tamper demo the chain stays broken for every later run —
    verify_chain() reports the FIRST break, and a plain re-seed does not touch
    the append-only log. Without an opt-in reset the only cure is deleting
    dcta.db, which is a poor thing to discover at the submission demo."""
    from backend.audit import AuditLog
    from backend.audit.log import AuditEntryType
    from backend.data.seed import seed

    db = tmp_path / "ledger.db"
    seed(db)
    log = AuditLog(db)
    log.append(AuditEntryType.DRAFT, {"draft_id": "d1"})
    log.append(AuditEntryType.EXECUTION, {"draft_id": "d1", "outcome": "EXECUTED"})
    assert log.verify_chain()["ok"] is True

    log._raw_update_payload(log.all_entries()[0]["id"], '{"draft_id":"tampered"}')
    assert log.verify_chain()["ok"] is False

    seed(db)                      # a normal re-seed must NOT erase history
    assert AuditLog(db).verify_chain()["ok"] is False
    assert len(AuditLog(db).all_entries()) == 2

    seed(db, reset_audit=True)    # the opt-in reset does
    fresh = AuditLog(db)
    assert fresh.verify_chain()["ok"] is True
    assert fresh.all_entries() == []
