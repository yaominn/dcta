"""
Where a bill payment's money goes — versioned, so a recurring mandate can bind it.

The mirror of destinations.py for billers. A biller's `reference_text` (the
account number with the biller) decides whose bill the money settles, and it
is UNTRUSTED stored text (biller_07's carries a prompt injection). So:

  - it is never shown raw: `masked` is built from its digits only, "Ref ••231";
  - a recurring mandate signs `version` and `ref_hash` (sha256 of the text), and
    every payment under it checks both. A changed reference — a new account
    number, or a tampered row — stops the mandate (SUSPENDED) until the user
    reviews and signs new terms. Nothing re-binds silently.

# MOCK: a real bank would get billers and references from the biller registry.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class BillerRef:
    biller_id: str
    name: str
    version: int
    ref_hash: str
    masked: str


def mask(reference_text: str) -> str:
    """The first run of 3+ digits, shown as its last three: "Acct 88231" -> "Ref ••231".
    Only digits leave this function, so injected text can't reach a card."""
    m = re.search(r"\d{3,}", reference_text or "")
    return "Ref ••" + m.group(0)[-3:] if m else "Ref on file"


def ref_hash(reference_text: str) -> str:
    return hashlib.sha256((reference_text or "").encode("utf-8")).hexdigest()


def current(conn, biller_id: str) -> BillerRef | None:
    row = conn.execute("SELECT id, name, reference_text, ref_version FROM billers WHERE id=?",
                       (biller_id,)).fetchone()
    if row is None:
        return None
    return BillerRef(biller_id=row["id"], name=row["name"],
                     version=int(row["ref_version"] or 1),
                     ref_hash=ref_hash(row["reference_text"]), masked=mask(row["reference_text"]))


def all_billers(conn) -> list[BillerRef]:
    return [current(conn, r["id"]) for r in conn.execute("SELECT id FROM billers ORDER BY name")]


def matches(conn, biller_id: str, version: int, signed_hash: str) -> bool:
    """True if the biller still has the reference a mandate signed."""
    cur = current(conn, biller_id)
    return cur is not None and cur.version == version and cur.ref_hash == signed_hash


def change_reference(conn, biller_id: str, reference_text: str) -> int:
    """Record a new reference for a biller and bump its version. Returns the
    new version. # MOCK: the demo's stand-in for the biller registry changing
    an account number; the caller commits."""
    conn.execute("UPDATE billers SET reference_text=?, ref_version=ref_version+1 WHERE id=?",
                 (reference_text, biller_id))
    return int(conn.execute("SELECT ref_version FROM billers WHERE id=?",
                            (biller_id,)).fetchone()["ref_version"])
