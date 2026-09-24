"""
Display-edge formatting. (brief: money is int cents everywhere except the UI)

This is the ONLY place money cents are turned into human dollar strings. It is
used by the overlay and CLI/HTTP output — NEVER before hashing. The canonical
form is int cents; canonical_json raises on any float. Formatting to dollars
happens here, at the edge, where a string can't leak back into a signed payload.
"""
from __future__ import annotations


def cents_to_display(cents: int) -> str:
    """842050 -> '8,420.50'.  19250 -> '192.50'.  Negative supported for debits.

    Pure formatting — never used before canonical_json/hashing."""
    sign = "-" if cents < 0 else ""
    dollars, remaining = divmod(abs(cents), 100)
    return f"{sign}{dollars:,}.{remaining:02d}"


def account_label(account_id: str) -> str:
    """'acct_savings' -> 'Savings'. Mirrors acctLabel() in frontend/app.js."""
    name = account_id[5:] if account_id.startswith("acct_") else account_id
    return name[:1].upper() + name[1:]


def plan_summary(plan) -> str:
    """One line per leg, from the SERVER'S copy of a ResolvedPlan. Used for the
    out-of-band confirmation message, which must describe the transaction
    independently of whatever the overlay rendered."""
    parts = []
    for leg in plan.plan:
        src = account_label(leg.source_account)
        amt = "$" + cents_to_display(leg.amount_cents)
        if leg.type == "TRANSFER":
            parts.append(f"send {amt} to {leg.payee_display} from {src}")
        elif leg.type == "PAY_BILL":
            parts.append(f"pay {amt} to {leg.biller_display} from {src}")
        else:
            parts.append(f"buy {leg.estimated_shares} {leg.ticker} for {amt} from {src}")
    return "; then ".join(parts)


def change_summary(change) -> str:
    """The out-of-band message text for a ResolvedContactChange, from the
    server's copy — same role as plan_summary()."""
    parts = []
    for e in change.edits:
        what = "phone number" if e.field == "phone" else "name"
        parts.append(f"change {e.payee_display}'s {what} to {e.new_value}")
    return "; and ".join(parts)
