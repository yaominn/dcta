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
current one (SUPERSEDED) — and the executor asks again under its write lock,
so a change landing after the gateway's check can't slip in before the debit.
The scam rules read `changed_at`.
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


_COLUMNS = "id, phone, last4, dest_version, dest_changed_at"


def current(conn, payee_id: str) -> Destination | None:
    """The payee's destination as the ledger holds it NOW."""
    row = conn.execute(f"SELECT {_COLUMNS} FROM payees WHERE id=?", (payee_id,)).fetchone()
    return _from_row(row) if row is not None else None


def for_user(conn, user_id: str) -> dict[str, Destination]:
    """Every payee's current destination for this user, in one query."""
    return {r["id"]: _from_row(r) for r in conn.execute(
        f"SELECT {_COLUMNS} FROM payees WHERE user_id=?", (user_id,))}


def superseded(conn, plan) -> bool:
    """True if a bound transfer in `plan` no longer goes where it was drafted
    to (a new number since). Unbound transfers are the gateway's to refuse."""
    for leg in plan.plan:
        if leg.type != "TRANSFER" or leg.destination_version is None:
            continue
        cur = current(conn, leg.payee_id)
        if (cur is None or cur.version != leg.destination_version
                or cur.routing_hash != leg.destination_hash):
            return True
    return False


def _from_row(row) -> Destination:
    if row["phone"]:
        kind, routing = "PAYNOW_MOBILE", row["phone"]
    else:                                       # no mobile on file: the account number
        kind, routing = "BANK_ACCOUNT", "•••• " + row["last4"]
    return Destination(
        payee_id=row["id"], version=int(row["dest_version"] or 1), kind=kind,
        masked=mask(routing) if kind == "PAYNOW_MOBILE" else routing,
        routing_hash=routing_hash(routing), changed_at=row["dest_changed_at"])
