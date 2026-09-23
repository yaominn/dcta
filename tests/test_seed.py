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
    assert sav["balance"] == pytest.approx(8420.50)


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
    """12x $50 to payee_21 (median 50) -> 'fifty thousand' is 1000x, anomaly fires."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT amount FROM transaction_history WHERE payee_id='payee_21'"
        ).fetchall()
    finally:
        conn.close()
    assert len(rows) == 12
    assert all(r["amount"] == 50.0 for r in rows)


def test_headline_arithmetic():
    """8420.50 - 500 = 7920.50 -> 32 whole AAPL @ 241.50 = 7728.00, remainder 192.50."""
    conn = get_conn()
    try:
        bal = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
        price = conn.execute("SELECT price FROM equities WHERE ticker='AAPL'").fetchone()[0]
    finally:
        conn.close()
    after = round(bal - 500, 2)
    shares = int(after // price)
    assert shares == 32
    assert round(shares * price, 2) == 7728.00
    assert round(after - shares * price, 2) == 192.50
