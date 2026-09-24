"""
Policy for contact edits. Pure and deterministic, like engine.py.

A new NAME is cosmetic. A new PHONE NUMBER is not: in Singapore it is a PayNow
proxy, so changing a payee's number changes where money sent to them goes —
the step an account-takeover makes just before a payment. So a phone change
always needs the out-of-band confirmation (gateway/stepup.py), exactly like an
anomalous payment, and the gateway enforces it.
"""
from __future__ import annotations

from backend.models.contacts import ResolvedContactChange


def contact_change_step_up(change: ResolvedContactChange) -> list[str]:
    """Reasons this change needs an out-of-band confirmation; [] if none."""
    return [f"Changing {e.payee_display}'s phone number changes where payments "
            f"to them go — please confirm it's you."
            for e in change.edits if e.field == "phone"]
