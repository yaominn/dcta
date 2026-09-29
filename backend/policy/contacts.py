"""
Policy for contact edits. Pure and deterministic, like engine.py.

A new NAME is cosmetic. A new PHONE NUMBER is not: in Singapore it is a PayNow
proxy, so changing a payee's number changes where money sent to them goes —
the step an account-takeover makes just before a payment. So a phone change
always needs the out-of-band confirmation (gateway/stepup.py), exactly like an
anomalous payment, and the gateway enforces it. A new number on the scam-number
feed is refused outright, as it is when adding a contact (policy/new_contact.py).
"""
from __future__ import annotations

from backend.models.contacts import ResolvedContactChange
from backend.policy.new_contact import REPORTED_REASON, is_reported


def contact_change_step_up(change: ResolvedContactChange) -> list[str]:
    """Reasons this change needs an out-of-band confirmation; [] if none."""
    return [f"Changing {e.payee_display}'s phone number changes where payments "
            f"to them go — please confirm it's you."
            for e in change.edits if e.field == "phone"]


def contact_change_refusal(change: ResolvedContactChange) -> str | None:
    """Why this change must not be made, else None: a new number on the scam
    feed is never saved. Re-derived at the gateway from the payload alone,
    whatever was drafted or signed — the same rule as adding a contact."""
    if any(e.field == "phone" and is_reported(e.new_value) for e in change.edits):
        return REPORTED_REASON
    return None
