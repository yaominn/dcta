"""
SQLite connection helper for the mock ledger. (brief Section 8: backend/data/)

# MOCK: this is a simulated bank ledger. No real DBS APIs are used anywhere.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "dcta.db"


def get_conn() -> sqlite3.Connection:
    """Open a connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_schema(conn: sqlite3.Connection) -> None:
    """Create all tables. Called by seed.py (idempotent: drops first)."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id                   TEXT PRIMARY KEY,
            nickname             TEXT NOT NULL,
            kyc_status           TEXT NOT NULL,           -- VERIFIED | PENDING
            investment_eligible  INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS accounts (
            id         TEXT PRIMARY KEY,
            user_id    TEXT NOT NULL REFERENCES users(id),
            alias      TEXT NOT NULL,                    -- 'acct_savings'
            balance    REAL NOT NULL,
            type       TEXT NOT NULL                     -- savings | joint | invest | settlement
        );

        CREATE TABLE IF NOT EXISTS payees (
            id          TEXT PRIMARY KEY,                -- 'payee_17' (opaque ID)
            user_id     TEXT NOT NULL REFERENCES users(id),
            nickname    TEXT NOT NULL,                   -- 'Mom'  <- shown to the LLM
            legal_name  TEXT NOT NULL,                   -- 'Jane Tan'  <- NEVER shown to the LLM
            last4       TEXT NOT NULL                    -- '3310'
        );

        CREATE TABLE IF NOT EXISTS billers (
            id             TEXT PRIMARY KEY,             -- 'biller_07' (opaque ID)
            name           TEXT NOT NULL,
            reference_text TEXT NOT NULL                  -- UNTRUSTED stored field (brief 4.3)
        );

        CREATE TABLE IF NOT EXISTS equities (
            ticker TEXT PRIMARY KEY,
            price  REAL NOT NULL
        );

        CREATE TABLE IF NOT EXISTS transaction_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   TEXT NOT NULL REFERENCES users(id),
            payee_id  TEXT NOT NULL REFERENCES payees(id),
            amount    REAL NOT NULL,
            ts        TEXT NOT NULL                       -- ISO-8601
        );

        CREATE TABLE IF NOT EXISTS limits (
            key   TEXT PRIMARY KEY,
            value REAL NOT NULL
        );
        """
    )
