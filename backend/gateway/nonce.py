"""
Server-issued, draft-bound, single-use nonces. (brief Section 4.5)

Why draft-bound, not per-session: a per-session nonce would let a user approve
draft A, then submit draft B carrying A's valid signature (a swap after
approval). Binding the nonce to a specific draft_id makes that swap fail at the
gateway: the nonce only validates for the draft it was minted for.

TTL 120s (brief default) keeps the signing window short. Single-use prevents
replay of a captured signed challenge.
"""
from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Dict


@dataclass
class _NonceRecord:
    draft_id: str
    issued_at: float
    used: bool = False


class NonceError(Exception):
    """Raised on consume() failure. Message is human-readable for the audit log + overlay."""


class NonceStore:
    def __init__(self, ttl_seconds: int = 120):
        self.ttl = ttl_seconds
        self._store: Dict[str, _NonceRecord] = {}

    def issue(self, draft_id: str) -> str:
        """Mint a fresh nonce bound to draft_id."""
        nonce = secrets.token_hex(16)
        self._store[nonce] = _NonceRecord(draft_id=draft_id, issued_at=time.time())
        return nonce

    def consume(self, nonce: str, draft_id: str) -> None:
        """Verify freshness, binding, single-use; then invalidate. Raises NonceError."""
        rec = self._store.get(nonce)
        if rec is None:
            raise NonceError("unknown nonce")
        if rec.used:
            raise NonceError("nonce already used (replay)")
        if rec.draft_id != draft_id:
            raise NonceError(
                f"nonce bound to draft {rec.draft_id}, not {draft_id} (swap-after-approval)"
            )
        if time.time() - rec.issued_at > self.ttl:
            raise NonceError("nonce expired (TTL exceeded)")
        rec.used = True
