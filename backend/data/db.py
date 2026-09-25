"""
SQLite connection helper for the mock ledger. (brief Section 8: backend/data/)

# MOCK: this is a simulated bank ledger. No real DBS APIs are used anywhere.
"""
from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "dcta.db"


def connect(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a connection with row access by column name.

    Pass a path to target an isolated DB (tests); omit it for the default
    mock ledger. Always sets row_factory + foreign_keys so callers are uniform.
    """
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def get_conn() -> sqlite3.Connection:
    """Default connection to the mock ledger DB."""
    return connect()


# One row per draft that has ever reached the executor — the at-most-once
# guarantee. draft_id is the PRIMARY KEY, so a second execution of the same
# draft cannot be written, even by two requests racing: the row is claimed in
# the SAME transaction as the debit, and whichever loses the race rolls its
# debit back. In the DB (not memory) so it survives a restart. `result` is the
# executor's JSON, replayed to a retry so a lost response can be recovered.
EXECUTIONS_DDL = """
CREATE TABLE IF NOT EXISTS executions (
    draft_id     TEXT PRIMARY KEY,
    kind         TEXT NOT NULL,       -- payment | contact_edit
    payload_hash TEXT NOT NULL,
    outcome      TEXT NOT NULL,       -- EXECUTED | FAILED | UPDATED
    result       TEXT NOT NULL,       -- the execution result, as JSON
    executed_at  INTEGER NOT NULL
);
"""


def migrate(conn: sqlite3.Connection) -> None:
    """Bring an existing ledger up to the current schema without re-seeding
    (a re-seed would drop the user's own edits and registered passkeys).
    Idempotent; called at app startup."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(payees)")}
    if cols and "phone" not in cols:
        conn.execute("ALTER TABLE payees ADD COLUMN phone TEXT")
        conn.commit()
    conn.executescript(EXECUTIONS_DDL)


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
            balance    INTEGER NOT NULL,                 -- cents (int minor units; never float)
            type       TEXT NOT NULL                     -- savings | joint | invest | settlement
        );

        CREATE TABLE IF NOT EXISTS payees (
            id          TEXT PRIMARY KEY,                -- 'payee_17' (opaque ID)
            user_id     TEXT NOT NULL REFERENCES users(id),
            nickname    TEXT NOT NULL,                   -- 'Mom'  <- shown to the LLM
            legal_name  TEXT NOT NULL,                   -- 'Jane Tan'  <- NEVER shown to the LLM
            last4       TEXT NOT NULL,                   -- '3310'
            phone       TEXT                             -- '+65 9123 3310'; NEVER shown to the LLM.
                                                         -- Editable by the user, via a signed draft only.
        );

        CREATE TABLE IF NOT EXISTS billers (
            id             TEXT PRIMARY KEY,             -- 'biller_07' (opaque ID)
            name           TEXT NOT NULL,
            reference_text TEXT NOT NULL                  -- UNTRUSTED stored field (brief 4.3)
        );

        CREATE TABLE IF NOT EXISTS equities (
            ticker TEXT PRIMARY KEY,
            price  INTEGER NOT NULL                  -- cents (int minor units; never float)
        );

        CREATE TABLE IF NOT EXISTS transaction_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id   TEXT NOT NULL REFERENCES users(id),
            -- NULLABLE on purpose. Only a TRANSFER has a payee; a bill payment
            -- or an equity purchase does not. While this was NOT NULL the
            -- executor could only record transfers, so a $19,000 share purchase
            -- was invisible to the daily limit and "daily limit" silently meant
            -- "daily TRANSFER limit". Every leg that moves money is recorded now.
            payee_id  TEXT REFERENCES payees(id),
            leg_type  TEXT NOT NULL DEFAULT 'TRANSFER',   -- TRANSFER | PAY_BILL | BUY_EQUITY
            amount    INTEGER NOT NULL,               -- cents (int minor units; never float)
            ts        TEXT NOT NULL                   -- ISO-8601
        );

        CREATE TABLE IF NOT EXISTS limits (
            key   TEXT PRIMARY KEY,
            value INTEGER NOT NULL                    -- money limits in cents; counts/mins as-is
        );

        -- M2: registered WebAuthn passkeys. One user may have several
        -- (platform authenticators are device-bound). public_key is the COSE-
        -- encoded key the gateway verifies against; sign_count advances each
        -- assertion and is the library's replay-protection signal.
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            credential_id  TEXT PRIMARY KEY,         -- base64url
            user_id        TEXT NOT NULL REFERENCES users(id),
            public_key     BLOB NOT NULL,            -- COSE-encoded
            sign_count     INTEGER NOT NULL DEFAULT 0,
            created_at     INTEGER NOT NULL           -- Unix seconds UTC
        );
        """
    )
    conn.executescript(EXECUTIONS_DDL)
