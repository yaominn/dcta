"""
Which pipeline a request goes to: a payment, a contact edit, a contacts list,
or a recurring bill setup.

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
_ADD_FIRST = re.compile(r"^\s*(?:please\s+)?(?:add|save|create)\b", re.I)
_LIST = re.compile(
    r"\b(?:show|list|see|view|display|what\s+are|who\s+are)\b.*\b(?:contacts?|payees?)\b"
    r"|^\s*(?:my\s+)?(?:contacts?|payees?)\s*[?.!]*\s*$",
    re.I)
_EDIT = re.compile(
    r"^\s*(?:please\s+)?rename\b"
    r"|\b(?:change|update|set|edit|correct|fix)\b.*\b" + _FIELD + r"\b",
    re.I)


# "every month", "monthly", "recurring", "autopay", "standing instruction"...:
# the user is asking for something ONGOING. That goes to recurring setup, which
# asks for every detail it can't read and needs its own signature — a one-time
# payment never becomes a recurring one by inference.
_RECURRING = re.compile(
    r"\b(?:every|each)\s+(?:\w+\s+)?(?:day|week|fortnight|month|quarter|year)s?\b"
    r"|\b(?:daily|weekly|fortnightly|monthly|quarterly|yearly|annually)\b"
    r"|\b(?:recurring|repeating|auto[\s-]?pay|standing\s+(?:order|instruction)|direct\s+debit"
    r"|giro|regularly|on\s+a\s+schedule)\b"
    r"|\bset\s+up\b.*\b(?:bill|payment)s?\b.*\bautomatic",
    re.I)
# "pay my bill" and nothing else: one payment, or an arrangement? Asked, never
# assumed either way.
_BARE_BILL = re.compile(
    r"^\s*(?:please\s+)?(?:pay|settle|do)\s+(?:my|the|our|a|this\s+month'?s)\s+"
    r"(?:\w+\s+)?bills?\s*(?:for\s+me\s*)?(?:please)?\s*[.!?]*\s*$",
    re.I)


def classify_request(transcript: str) -> str:
    """'contact_list' | 'contact_add' | 'contact_edit' | 'recurring_bill' |
    'bill_ambiguous' | 'payment'."""
    # A request that starts with "add"/"save" is an addition, whatever the
    # name: "add See Toh as a contact" is not "see contacts".
    if _ADD_FIRST.search(transcript) and _ADD.search(transcript):
        return "contact_add"
    if _LIST.search(transcript):
        return "contact_list"
    if _ADD.search(transcript):
        return "contact_add"
    if _EDIT.search(transcript):
        return "contact_edit"
    if _RECURRING.search(transcript):
        return "recurring_bill"
    if _BARE_BILL.search(transcript):
        return "bill_ambiguous"
    return "payment"
