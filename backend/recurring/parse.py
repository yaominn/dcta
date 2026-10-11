"""
Read a recurring bill request by RULES — the model is never asked.

"Pay SP Group S$85 from savings every month, starting 1 November, for six
months." gives: biller SP Group, account savings, S$85.00, MONTHLY, starting
1 November (this year's, or next year's if that has passed), 6 payments.

This is a PREFILL, not a decision. Anything the rules can't read for certain
is left empty and listed in `missing`, and the user confirms or fills in every
field on the setup form before any terms exist (terms.py). In particular:

  - no frequency, start date or end is ever assumed — "pay SP Group monthly"
    asks when to start and when to stop;
  - no account is defaulted (a one-time payment defaults to savings; a
    recurring one asks, because it will keep debiting that account);
  - an amount is taken only when exactly one amount was said.

So a misread here produces a question or a wrong-looking form, never a mandate.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date

from backend.recurring import schedule
from backend.validator.amounts import money_occurrences

_NUMBER_WORDS = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12, "eighteen": 18,
    "twenty": 20, "twenty-four": 24, "twenty four": 24, "thirty-six": 36,
}
_NUM = r"(\d{1,3}|" + "|".join(sorted(map(re.escape, _NUMBER_WORDS), key=len, reverse=True)) + r")"
_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], 1)}
_MONTH = r"(jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"
_DAY = r"(\d{1,2})(?:st|nd|rd|th)?"
_DATE = (r"(?:(?:the\s+)?" + _DAY + r"\s+(?:of\s+)?" + _MONTH + r"(?:\s*,?\s*(\d{4}))?"
         r"|" + _MONTH + r"\s+" + _DAY + r"(?:\s*,?\s*(\d{4}))?"
         r"|(\d{4})-(\d{2})-(\d{2}))")

_MONTHLY = re.compile(r"\b(?:every|each|per|a|once\s+a)\s+month\b|\bmonthly\b", re.I)
_WEEKLY = re.compile(r"\b(?:every|each|per|a|once\s+a)\s+week\b|\bweekly\b", re.I)
# Recurring words the setup understands only as "recurring, but how often?".
_OTHER_FREQ = re.compile(r"\b(?:daily|every\s+day|fortnightly|every\s+(?:two|2|other)\s+weeks?"
                         r"|quarterly|yearly|annually|every\s+year|every\s+\w+\s+months)\b", re.I)
_START = re.compile(r"\b(?:start(?:ing|s)?|beginning|begin|from|commencing)\s+(?:on\s+|from\s+)?"
                    + _DATE, re.I)
_END_DATE = re.compile(r"\b(?:until|till|til|up\s+to|ending|ends|end)\s+(?:on\s+)?" + _DATE, re.I)
_FOR_N = re.compile(r"\bfor\s+(?:the\s+next\s+)?" + _NUM + r"\s+(months?|weeks?|payments?|times|instal(?:l)?ments?)\b",
                    re.I)
_N_PAYMENTS = re.compile(r"\b" + _NUM + r"\s+(payments?|times|instal(?:l)?ments?)\b", re.I)
_ACCOUNT = re.compile(r"\b(savings?|spending|joint)\b", re.I)
_ACCOUNT_IDS = {"saving": "acct_savings", "savings": "acct_savings",
                "spending": "acct_joint", "joint": "acct_joint"}


@dataclass
class SetupFields:
    """What the rules read. None = not said (or not certain): the form asks."""
    biller_id: str | None = None
    source_account: str | None = None
    amount_cents: int | None = None
    frequency: str | None = None
    start_date: str | None = None
    occurrence_count: int | None = None
    end_date: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"biller_id": self.biller_id, "source_account": self.source_account,
                "amount_cents": self.amount_cents, "frequency": self.frequency,
                "start_date": self.start_date, "occurrence_count": self.occurrence_count,
                "end_date": self.end_date}

    def missing(self) -> list[str]:
        out = [k for k in ("biller_id", "source_account", "amount_cents", "frequency",
                           "start_date") if getattr(self, k) is None]
        if self.occurrence_count is None and self.end_date is None:
            out.append("end")
        return out


QUESTIONS = {
    "biller_id": "Which bill should I pay?",
    "source_account": "Which account should it come from?",
    "amount_cents": "How much is each payment? It has to be the same amount every time.",
    "frequency": "How often should it be paid — weekly or monthly?",
    "start_date": "When should the first payment be?",
    "end": "When should it stop — after how many payments, or on what date?",
}


def _number(text: str) -> int | None:
    t = text.lower().strip()
    return int(t) if t.isdigit() else _NUMBER_WORDS.get(t)


def _date_from(groups: tuple, today: date) -> date | None:
    """A match of _DATE -> a date. A date with no year is the next one on or
    after `today`: "1 November" said in October is this November."""
    d1, m1, y1, m2, d2, y2, iy, im, iday = groups
    try:
        if iy:
            return date(int(iy), int(im), int(iday))
        day, mon, year = (d1, m1, y1) if d1 else (d2, m2, y2)
        month = _MONTHS[mon[:3].lower()]
        if year:
            return date(int(year), month, int(day))
        guess = date(today.year, month, int(day))
        return guess if guess >= today else date(today.year + 1, month, int(day))
    except (ValueError, KeyError):
        return None


def extract(transcript: str, *, billers: list, today: date) -> SetupFields:
    """`billers`: BillerRef rows (backend/data/billers.py). `today`: the local
    date in the mandate's time zone."""
    text = transcript or ""
    out = SetupFields()

    named = [b for b in billers if re.search(r"\b" + re.escape(b.name) + r"\b", text, re.I)]
    if len(named) == 1:
        out.biller_id = named[0].biller_id

    accounts = {_ACCOUNT_IDS[m.lower()] for m in _ACCOUNT.findall(text)}
    if len(accounts) == 1:
        out.source_account = accounts.pop()

    amounts = set(money_occurrences(_without_schedule(text)))
    if len(amounts) == 1:
        out.amount_cents = amounts.pop()

    monthly, weekly = bool(_MONTHLY.search(text)), bool(_WEEKLY.search(text))
    if _OTHER_FREQ.search(text):
        out.notes.append("I can set up weekly or monthly payments.")
    elif monthly != weekly:
        out.frequency = schedule.MONTHLY if monthly else schedule.WEEKLY

    m = _START.search(text)
    if m:
        start = _date_from(m.groups(), today)
        if start is not None:
            out.start_date = start.isoformat()

    m = _END_DATE.search(text)
    if m:
        end = _date_from(m.groups(), today)
        if end is not None:
            out.end_date = end.isoformat()
    m = _FOR_N.search(text) or _N_PAYMENTS.search(text)
    if m and out.end_date is None:
        n, unit = _number(m.group(1)), m.group(2).lower()
        unit_freq = (schedule.MONTHLY if unit.startswith("month") else
                     schedule.WEEKLY if unit.startswith("week") else None)
        # "for six months" counts payments only when it matches how often:
        # monthly for six months is 6; weekly "for six months" is left to ask.
        if n and (unit_freq is None or unit_freq == out.frequency):
            out.occurrence_count = n
    return out


def _without_schedule(text: str) -> str:
    """The request minus its dates and counts, so "1 November" and "six months"
    aren't read as amounts."""
    for pat in (_START, _END_DATE, _FOR_N, _N_PAYMENTS):
        text = pat.sub(" ", text)
    return text
