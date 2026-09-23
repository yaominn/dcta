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
