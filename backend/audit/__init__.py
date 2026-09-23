"""
Hash-chained audit log + verify_chain(). (brief Section 4.5 / Section 8)

Each entry stores prev_hash and its own hash. Logs: transcript hash, draft
hash, validation result, policy result, signature and execution result.
verify_chain() reports EXACTLY where tampering occurred.

Implemented in Milestone 1 (the security core, before the LLM).
"""
from backend.audit.canonical import (
    canonical_json,
    payload_hash,
    entry_hash,
    challenge_hash,
    hash_transcript,
)
from backend.audit.log import AuditLog, AuditEntryType, GENESIS_HASH

__all__ = [
    "canonical_json",
    "payload_hash",
    "entry_hash",
    "challenge_hash",
    "hash_transcript",
    "AuditLog",
    "AuditEntryType",
    "GENESIS_HASH",
]
