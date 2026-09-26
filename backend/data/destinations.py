"""
Where a transfer's money goes — versioned, so the signature can bind it.

Before this, contact edits changed a payee's name and phone and nothing tied a
payment to either: "change Mom's number, then pay Mom $500" — the classic
"Hi Mum, this is my new number" scam — sailed through, because the signed
payment named only "Mom". Now each payee's destination (its PayNow mobile
number, in this demo) has a VERSION that bumps on every routing change and the
TIME of that change, and a transfer signs:

    destination_version   which version it was drafted for
    destination_masked    what the user saw: "+65 9123 ••10"
    destination_hash      sha256 of the full routing value

The gateway refuses a transfer whose signed version is no longer the payee's
current one (SUPERSEDED), and the scam rules read `changed_at`.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Destination:
    payee_id: str
    version: int
    kind: str                 # PAYNOW_MOBILE | BANK_ACCOUNT
    masked: str
    routing_hash: str
    changed_at: int | None    # Unix s; None = unchanged since the contact was set up


def mask(routing: str) -> str:
    """"+65 9123 3310" -> "+65 9123 ••10": enough to recognise, not to reuse."""
    digits = re.sub(r"\D", "", routing)
    if len(digits) < 4:
        return "••" + digits[-2:]
    shown = routing[: len(routing) - 4] if routing else ""
    return (shown + "••" + digits[-2:]).strip()


def routing_hash(routing: str) -> str:
    return hashlib.sha256(re.sub(r"\D", "", routing).encode()).hexdigest()


def current(conn, payee_id: str) -> Destination | None:
    """The payee's destination as the ledger holds it NOW."""
    row = conn.execute(
        "SELECT id, phone, last4, dest_version, dest_changed_at FROM payees WHERE id=?",
        (payee_id,)).fetchone()
    if row is None:
        return None
    if row["phone"]:
        kind, routing = "PAYNOW_MOBILE", row["phone"]
    else:                                       # no mobile on file: the account number
        kind, routing = "BANK_ACCOUNT", "•••• " + row["last4"]
    return Destination(
        payee_id=row["id"], version=int(row["dest_version"] or 1), kind=kind,
        masked=mask(routing) if kind == "PAYNOW_MOBILE" else routing,
        routing_hash=routing_hash(routing), changed_at=row["dest_changed_at"])
