"""Shared test helpers.

`dest(payee_id)`: the SEEDED destination of a payee, as the resolver would bind
it into a transfer. The gateway refuses a transfer that isn't bound to its
payee's current destination (backend/data/destinations.py), so tests that
hand-build plans for the gateway must bind them too — with exactly the fields
a real draft carries.
"""
from __future__ import annotations

from backend.data import destinations
from backend.data.seed import PAYEES

_PHONES = {row[0]: row[5] for row in PAYEES}


def dest(payee_id: str) -> dict:
    phone = _PHONES[payee_id]
    return {"destination_version": 1,
            "destination_masked": destinations.mask(phone),
            "destination_hash": destinations.routing_hash(phone)}
