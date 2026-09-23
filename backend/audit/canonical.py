"""
Canonical serialization + SHA-256. (brief Section 4.5)

The problem this solves: two "equal" JSON blobs can hash differently — key
order, 500.0 vs 500.00, timezone text. If the hash isn't stable, a user could
sign one thing and the gateway could "see" another: a silent swap. So we force
ONE canonical form before hashing:

  1. money is int cents (never float) — see the fail-closed guard below
  2. sort all object keys
  3. compact separators, no ASCII escaping
  4. SHA-256

"Money is int cents" is enforced IN CODE, not in a docstring: _normalize()
RAISES TypeError on any float in the payload. This is the same philosophy as
the import-boundary test — enforce the property, don't assert it. A float can
never silently enter a signed payload, because floats cannot be canonicalized
deterministically across languages (Python f'{2.675:.2f}'='2.67' but
JS (2.675).toFixed(2)='2.68'), which produced hash collisions (500.001 and
500.004 both rounded to '500.00' -> one signature valid for two different plans).

"What you see is what you sign" rests on this: the confirmation overlay must
render from this same canonical form, so the bytes the user approved (via the
blind WebAuthn challenge hash) are the bytes the gateway verifies.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from backend.models.schemas import ResolvedPlan


def _normalize(obj: Any) -> Any:
    """Recursively canonicalize. Keys left untouched (json.dumps sorts them).

    bool is checked before int (bool subclasses int). A float RAISES: money
    is int cents; floats cannot be canonicalized deterministically across
    languages and produced hash collisions. Fail closed, not conventional."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, float):
        raise TypeError(
            f"float in canonical payload: {obj!r}. Money is int cents. "
            "Floats cannot be canonicalized deterministically across languages."
        )
    if isinstance(obj, int):
        return obj
    if isinstance(obj, dict):
        return {k: _normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalize(v) for v in obj]
    return obj                         # str, None, etc.


def canonical_json(obj: dict) -> str:
    """Deterministic JSON for hashing: sorted keys, compact, fixed number format."""
    return json.dumps(_normalize(obj), sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(plan: ResolvedPlan) -> str:
    """SHA-256 over the canonical form of a ResolvedPlan. This is what gets signed."""
    return hashlib.sha256(canonical_json(plan.model_dump()).encode()).hexdigest()


def entry_hash(prev_hash: str, entry_type: str, payload_json: str, created_at: str) -> str:
    """SHA-256 over a hash-chain entry. prev_hash binding makes the chain
    tamper-evident: editing one entry changes its hash and breaks every later link."""
    blob = f"{prev_hash}|{entry_type}|{payload_json}|{created_at}".encode()
    return hashlib.sha256(blob).hexdigest()


def challenge_hash(payload_hash_hex: str, nonce: str) -> str:
    """The WebAuthn challenge (brief 4.5): sha256(payload_hash + server_nonce).
    The authenticator signs this blind hash; the gateway verifies the same."""
    return hashlib.sha256((payload_hash_hex + nonce).encode()).hexdigest()
