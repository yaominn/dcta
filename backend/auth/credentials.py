"""
Registered credential lookup. (brief Section 8: backend/auth/)

# MOCK: maps credential_id -> public key (the verification key). In M2 this
becomes a DB-backed store of real WebAuthn COSE public keys registered during
the registration ceremony. The gateway only ever calls get(credential_id), so
the swap is transparent to it.

Why auth owns this and the gateway consumes it (not the reverse): the agent
(the untrusted LLM side) must not reach auth OR gateway — enforced by the
import-boundary test. Gateway -> auth is an allowed edge; agent -> auth is not.
"""
from __future__ import annotations

from typing import Dict


class MockCredentialStore:
    """# MOCK: in-memory credential_id -> public key."""

    def __init__(self):
        self._creds: Dict[str, str] = {}

    def register(self, credential_id: str, public_key: str) -> None:
        self._creds[credential_id] = public_key

    def get(self, credential_id: str) -> str | None:
        return self._creds.get(credential_id)
