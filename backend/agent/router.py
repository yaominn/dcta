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


# A money verb AND an amount, and not asked as a question: a payment the
# parser failed to read. It keeps "I didn't catch a payment" and never reaches
# the question classifier, so a payment makes no extra model call even when
# parsing fails. "why didn't my $50 send go through?" and "give me all my
# transactions" are questions, not payments.
_MONEY_VERB = re.compile(
    r"\b(?:pay|paid|send|sent|transfer|give(?!\s+me\b)|buy|purchase|wire|remit|move|top\s*up)\b",
    re.I)
_ASKED = re.compile(r"^\s*(?:why|what|how|where|when|which|who|whose)\b", re.I)
_AMOUNT = re.compile(
    r"\d|\$|\b(?:one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|"
    r"fifteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|hundred|thousand|"
    r"grand|half|all|rest|everything)\b", re.I)


def looks_like_payment(transcript: str) -> bool:
    return bool(_MONEY_VERB.search(transcript) and _AMOUNT.search(transcript)
                and not _ASKED.search(transcript))


# Money mentioned only in the past: "I paid mom 500 yesterday right?", "can
# you check if I sent 50 to mom?", "did I pay mom?". Asked about, not asked
# for, so the payment reader must not turn it into a new draft (it did: a
# $500 one). Any present-tense request beside it ("mom paid for dinner, send
# her 30", "resend it", "if not pay her 500") keeps it a payment. Not a
# security decision: a miss is a read-only answer, or a draft still to sign.
_PAST_MONEY = re.compile(
    r"\b(?:paid|sent|transferred|gave|bought|purchased|wired|remitted|moved|topped\s+up)\b"
    r"|\b(?:did|didn'?t|have|haven'?t|has|hasn'?t|had)\s+(?:\w+\s+){1,2}?"
    r"(?:pay|send|transfer|give|buy|wire|move)\b", re.I)
_REQUEST = re.compile(
    r"\b(?:pay|send|transfer|give(?!\s+me\b)|buy|purchase|wire|remit|move|top\s*up|"
    r"re-?send|re-?pay|repeat|redo|retry|again)\b", re.I)


def only_past_payments(transcript: str) -> bool:
    if not _PAST_MONEY.search(transcript):
        return False
    return not _REQUEST.search(_PAST_MONEY.sub(" ", transcript))
