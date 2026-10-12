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
    kind         TEXT NOT NULL,       -- payment | contact_edit | contact_add | mandate
    payload_hash TEXT NOT NULL,
    outcome      TEXT NOT NULL,       -- EXECUTED | FAILED | UPDATED
    result       TEXT NOT NULL,       -- the execution result, as JSON
    executed_at  INTEGER NOT NULL
);
"""


# Scam protection (backend/policy/scam.py). A server-enforced HOLD on one draft:
# the gateway refuses it until release_at, whatever the page sends, and the end
# of the countdown sends NOTHING by itself — the user still confirms. And the
# user's KILL SWITCH: while engaged, no outgoing payment executes.
SAFETY_DDL = """
CREATE TABLE IF NOT EXISTS holds (
    draft_id    TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    release_at  INTEGER NOT NULL,
    status      TEXT NOT NULL CHECK (status IN ('PENDING','CANCELLED','RELEASED')),
    payload_hash TEXT                   -- the payload this wait was for
);
-- A LARGE payment, signed and checked, waiting RELEASE_DELAY_SECONDS before
-- the money moves (policy/scam.py). Cancelling it in that window goes through
-- the executions table like any cancel, so a cancel and the release can't both win.
CREATE TABLE IF NOT EXISTS delayed_payments (
    draft_id     TEXT PRIMARY KEY,
    user_id      TEXT NOT NULL,
    payload      TEXT NOT NULL,       -- the signed ResolvedPlan, as JSON
    payload_hash TEXT NOT NULL,
    created_at   INTEGER NOT NULL,
    release_at   INTEGER NOT NULL,
    status       TEXT NOT NULL CHECK (status IN ('PENDING','RUNNING','SENT','CANCELLED'))
);
-- Earlier payment attempts, for the scam score's history facts
-- (policy/attempts.py): one row per transfer leg of a scored draft.
CREATE TABLE IF NOT EXISTS scam_attempts (
    draft_id    TEXT NOT NULL,
    leg_id      TEXT NOT NULL,
    user_id     TEXT NOT NULL,
    payee_id    TEXT,
    amount      INTEGER NOT NULL,     -- cents
    outcome     TEXT NOT NULL,        -- the scam outcome the user was shown
    asked       INTEGER NOT NULL,     -- 1: asked what the payment was for
    status      TEXT NOT NULL CHECK (status IN ('OPEN','SENT','STOPPED')),
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL,
    PRIMARY KEY (draft_id, leg_id)
);
CREATE TABLE IF NOT EXISTS kill_switch (
    user_id     TEXT PRIMARY KEY,
    engaged_at  INTEGER NOT NULL,
    released_at INTEGER                 -- NULL while engaged
);
"""


# Recurring bill payments (backend/recurring/, docs/RECURRING_BILLS.md).
#
# mandates: one row per SIGNED RecurringBillMandate. `terms` is the canonical
# JSON the user's passkey signed (with the nonce) and `payload_hash` its hash;
# every execution re-derives the hash from `terms` and refuses on a mismatch,
# so editing a stored term stops the mandate rather than widening it. The
# counters are the server's own record — no browser flag says "automatic".
#
# mandate_occurrences: every payment the mandate allows, created with it.
# `draft_id` is the occurrence's execution key in the `executions` table, so an
# occurrence is debited at most once whichever path (the user's signature or
# the mandate) runs it, and however many workers try.
RECURRING_DDL = """
CREATE TABLE IF NOT EXISTS mandates (
    mandate_id           TEXT PRIMARY KEY,
    version              INTEGER NOT NULL,
    user_id              TEXT NOT NULL,
    terms                TEXT NOT NULL,      -- the signed RecurringBillMandate, canonical JSON
    payload_hash         TEXT NOT NULL,
    credential_id        TEXT NOT NULL,      -- the passkey that signed it
    draft_id             TEXT NOT NULL UNIQUE,
    status               TEXT NOT NULL CHECK (status IN
                             ('ACTIVE','PAUSED','SUSPENDED','CANCELLED','COMPLETED')),
    mode                 TEXT NOT NULL CHECK (mode IN ('SUPERVISED','AUTO')),
    supervised_successes INTEGER NOT NULL DEFAULT 0,
    paid_count           INTEGER NOT NULL DEFAULT 0,
    paid_total_cents     INTEGER NOT NULL DEFAULT 0,
    status_reason        TEXT,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS mandate_occurrences (
    mandate_id    TEXT NOT NULL REFERENCES mandates(mandate_id),
    seq           INTEGER NOT NULL,          -- 1..occurrence_count
    due_date      TEXT NOT NULL,             -- local date, YYYY-MM-DD
    due_at        INTEGER NOT NULL,          -- Unix s: DUE_LOCAL_TIME on due_date
    auto_until    INTEGER NOT NULL,          -- Unix s: end of the due date (automatic window)
    review_until  INTEGER NOT NULL,          -- Unix s: last moment it can be approved
    draft_id      TEXT NOT NULL UNIQUE,      -- the execution key (executions.draft_id)
    phase         TEXT CHECK (phase IN ('SUPERVISED','AUTO')),   -- set when it falls due
    status        TEXT NOT NULL CHECK (status IN
                      ('SCHEDULED','PENDING_APPROVAL','NEEDS_REVIEW','HELD','EXECUTED',
                       'FAILED','DECLINED','EXPIRED','MISSED','SKIPPED','CANCELLED')),
    reason        TEXT,
    updated_at    INTEGER NOT NULL,
    PRIMARY KEY (mandate_id, seq)
);
-- What the user is told: after every payment, and on a pause, failure, hold
-- or anything that needs them. Durable, so a closed app still shows it.
-- Text only: a notification never carries a link that authorizes anything.
CREATE TABLE IF NOT EXISTS notifications (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     TEXT NOT NULL,
    kind        TEXT NOT NULL,
    title       TEXT NOT NULL,
    body        TEXT NOT NULL,
    mandate_id  TEXT,
    seq         INTEGER,
    created_at  INTEGER NOT NULL,
    read_at     INTEGER
);
-- DEMO ONLY (RECURRING_DEMO_CLOCK=1): how far the recurring clock runs ahead
-- of real time, so a demo can reach next month's due date in seconds.
-- Ignored unless that flag is on (backend/recurring/clock.py).
CREATE TABLE IF NOT EXISTS recurring_clock (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    offset_s  INTEGER NOT NULL
);
"""


def migrate(conn: sqlite3.Connection) -> None:
    """Bring an existing ledger up to the current schema without re-seeding
    (a re-seed would drop the user's own edits and registered passkeys).
    Idempotent; called at app startup."""
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(payees)")}
    for col in ("phone TEXT", "added_at INTEGER", "hold_until INTEGER",
                "dest_version INTEGER NOT NULL DEFAULT 1", "dest_changed_at INTEGER",
                "removed_at INTEGER"):
        if cols and col.split()[0] not in cols:
            conn.execute(f"ALTER TABLE payees ADD COLUMN {col}")
            conn.commit()
    hcols = {r["name"] for r in conn.execute("PRAGMA table_info(transaction_history)")}
    if hcols and "dest_version" not in hcols:
        conn.execute("ALTER TABLE transaction_history ADD COLUMN dest_version INTEGER")
        conn.commit()
    bcols = {r["name"] for r in conn.execute("PRAGMA table_info(billers)")}
    if bcols and "ref_version" not in bcols:
        conn.execute("ALTER TABLE billers ADD COLUMN ref_version INTEGER NOT NULL DEFAULT 1")
        conn.commit()
    conn.executescript(EXECUTIONS_DDL)
    conn.executescript(SAFETY_DDL)
    conn.executescript(RECURRING_DDL)
    if "payload_hash" not in {r["name"] for r in conn.execute("PRAGMA table_info(holds)")}:
        conn.execute("ALTER TABLE holds ADD COLUMN payload_hash TEXT")
        conn.commit()


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
            phone       TEXT,                            -- '+65 9123 3310'; NEVER shown to the LLM.
                                                         -- Editable by the user, via a signed draft only.
            added_at    INTEGER,                         -- Unix s; NULL for the seeded contacts
            hold_until  INTEGER,                         -- Unix s; payments blocked until then
                                                         -- (a new contact's HOLD safeguard)
            -- WHERE the money goes, versioned (backend/data/destinations.py):
            -- bumps on every routing change (a new phone number), and the time
            -- of that change. A transfer signs the version it was drafted for.
            dest_version    INTEGER NOT NULL DEFAULT 1,
            dest_changed_at INTEGER,                     -- Unix s; NULL = unchanged since set up
            -- Unix s; removed from the contacts card. The row stays: payment
            -- history and the scam rules point at it. Gone from the list,
            -- payments and edits; anything drafted before is REMOVED.
            removed_at      INTEGER
        );

        CREATE TABLE IF NOT EXISTS billers (
            id             TEXT PRIMARY KEY,             -- 'biller_07' (opaque ID)
            name           TEXT NOT NULL,
            reference_text TEXT NOT NULL,                -- UNTRUSTED stored field (brief 4.3)
            -- bumps whenever reference_text changes (backend/data/billers.py):
            -- a recurring mandate signs the version, so a changed bill
            -- reference stops its payments until the user signs again.
            ref_version    INTEGER NOT NULL DEFAULT 1
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
            ts        TEXT NOT NULL,                  -- ISO-8601
            dest_version INTEGER                      -- the payee destination version paid;
                                                      -- NULL = before versioning (= version 1)
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
    conn.executescript(SAFETY_DDL)
    conn.executescript(RECURRING_DDL)
