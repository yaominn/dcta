"""
Registered credential lookup. (brief Section 8: backend/auth/)

Two credential stores, one verifier seam — the gateway calls only get(), so
the swap from the mock test key to real WebAuthn COSE keys is transparent to
it (the gateway code does not change between M1 and M2).

  - MockCredentialStore      : in-memory credential_id -> public key (hex str).
                               M1 only; lets the full verify -> execute -> log
                               path be exercised before any real biometric exists.
  - WebAuthnCredentialStore  : DB-backed credential_id -> (COSE public key bytes,
                               sign_count). M2; populated by the registration
                               ceremony. The sign count advances each assertion
                               and is the library's replay-protection signal.

Why auth owns this and the gateway consumes it (not the reverse): the agent
(the untrusted LLM side) must not reach auth OR gateway -- enforced by the
import-boundary test. Gateway -> auth is an allowed edge; agent -> auth is not.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict

from backend.data.db import connect


class MockCredentialStore:
    """# MOCK: in-memory credential_id -> public key."""

    def __init__(self):
        self._creds: Dict[str, str] = {}

    def register(self, credential_id: str, public_key: str) -> None:
        self._creds[credential_id] = public_key

    def get(self, credential_id: str) -> str | None:
        return self._creds.get(credential_id)


@dataclass
class WebAuthnCredential:
    """A registered passkey. Carries its own id so the verifier (which receives
    this object from the gateway) can advance the sign count after a successful
    assertion without the gateway needing to know about counters at all."""
    credential_id: str       # base64url
    user_id: str
    public_key: bytes        # COSE-encoded
    sign_count: int


class WebAuthnCredentialStore:
    """DB-backed store of real WebAuthn passkeys (M2). The gateway calls get()
    exactly as it does for the mock store; the returned object carries the COSE
    public key + current sign count the verifier needs."""

    def __init__(self, db_path: Path | str | None = None):
        self.db_path = db_path

    def _conn(self):
        return connect(self.db_path)

    def store(self, credential_id: str, user_id: str, public_key: bytes,
              sign_count: int = 0) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO webauthn_credentials "
                "(credential_id, user_id, public_key, sign_count, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (credential_id, user_id, public_key, sign_count, int(time.time())),
            )
            conn.commit()
        finally:
            conn.close()

    def get(self, credential_id: str) -> WebAuthnCredential | None:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT credential_id, user_id, public_key, sign_count "
                "FROM webauthn_credentials WHERE credential_id = ?",
                (credential_id,),
            ).fetchone()
            if row is None:
                return None
            return WebAuthnCredential(
                credential_id=row["credential_id"], user_id=row["user_id"],
                public_key=row["public_key"], sign_count=row["sign_count"],
            )
        finally:
            conn.close()

    def update_sign_count(self, credential_id: str, new_count: int) -> None:
        conn = self._conn()
        try:
            conn.execute(
                "UPDATE webauthn_credentials SET sign_count = ? "
                "WHERE credential_id = ?",
                (new_count, credential_id),
            )
            conn.commit()
        finally:
            conn.close()

    def list_for_user(self, user_id: str) -> list[WebAuthnCredential]:
        """All of a user's registered passkeys -> allowCredentials for signing."""
        conn = self._conn()
        try:
            rows = conn.execute(
                "SELECT credential_id, user_id, public_key, sign_count "
                "FROM webauthn_credentials WHERE user_id = ?",
                (user_id,),
            ).fetchall()
            return [
                WebAuthnCredential(
                    credential_id=r["credential_id"], user_id=r["user_id"],
                    public_key=r["public_key"], sign_count=r["sign_count"],
                )
                for r in rows
            ]
        finally:
            conn.close()
