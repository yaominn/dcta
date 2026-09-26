"""
Which pipeline a request goes to: a payment, a contact edit, or a contacts list.

Routing is NOT a security decision. Whatever this returns, the request still
ends at a draft the user must review and sign (or, for the list, a read-only
view of the user's own contacts), so a mis-route produces a question or a
wrong-looking card — never an action. That is why a small deterministic rule
set is acceptable here, and why it errs towards "payment": the payment
pipeline asks when it does not understand.
"""
from __future__ import annotations

import re

_FIELD = r"(?:nick\s?name|name|phone(?:\s+number)?|mobile(?:\s+number)?|number|contact\s+number|handphone)"

# "add Bob as a contact", "save a new payee", "new contact Bob 9123 4567",
# "add uncle bob, his number is 9123 4567". Checked before _EDIT: "set up a new
# contact" is an add, not an edit.
_ADD = re.compile(
    r"\b(?:add|save|create|new)\b.*\b(?:contacts?|payees?)\b"
    r"|^\s*(?:please\s+)?(?:add|save)\s+.+\b(?:number|phone|mobile|\d{4})",
    re.I)
_LIST = re.compile(
    r"\b(?:show|list|see|view|display|what\s+are|who\s+are)\b.*\b(?:contacts?|payees?)\b"
    r"|^\s*(?:my\s+)?(?:contacts?|payees?)\s*[?.!]*\s*$",
    re.I)
_EDIT = re.compile(
    r"^\s*(?:please\s+)?rename\b"
    r"|\b(?:change|update|set|edit|correct|fix)\b.*\b" + _FIELD + r"\b",
    re.I)


def classify_request(transcript: str) -> str:
    """'contact_list' | 'contact_add' | 'contact_edit' | 'payment'."""
    if _LIST.search(transcript):
        return "contact_list"
    if _ADD.search(transcript):
        return "contact_add"
    if _EDIT.search(transcript):
        return "contact_edit"
    return "payment"
