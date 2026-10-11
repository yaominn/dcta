"""
Setup form -> RecurringBillMandate terms, and a mandate's occurrence -> the
ordinary one-payment plan the user signs for it.

Everything here is deterministic and reads the ledger, never the request, for
what money moves where: the biller's name and reference version come from the
billers table, the account must be the user's own, and the amount must fit the
per-transaction limit. A field that fails comes back as an error for the form
to show; nothing is guessed to make it pass.
"""
from __future__ import annotations

import re
import secrets
from datetime import date

from backend.audit.canonical import hash_transcript
from backend.data import billers as _billers
from backend.display import account_label, cents_to_display
from backend.models.mandates import (DEFAULT_TIMEZONE, MAX_OCCURRENCES, MAX_SPAN_DAYS,
                                     SUPERVISED_APPROVALS, RecurringBillMandate)
from backend.models.schemas import MAX_AUTH_WINDOW_S, ResolvedPayBill, ResolvedPlan
from backend.recurring import schedule

_AMOUNT = re.compile(r"^\s*(?:s?\$)?\s*(\d{1,7})(?:\.(\d{1,2}))?\s*$", re.I)


def new_mandate_id() -> str:
    return "mdt_" + secrets.token_urlsafe(18)


def parse_amount(value) -> int | None:
    """"85", "85.00", "$85.5", 8500 (already cents, int) -> cents. Never a float."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    m = _AMOUNT.match(str(value or ""))
    if not m:
        return None
    cents = int(m.group(1)) * 100 + int((m.group(2) or "0").ljust(2, "0"))
    return cents or None


def build(form: dict, *, conn, user_id: str, draft_id: str, mandate_id: str,
          transcript: str, now: int, tz: str = DEFAULT_TIMEZONE) -> tuple[RecurringBillMandate | None, dict]:
    """(terms, {}) when every field is valid, else (None, {field: message}).

    `form` holds the user's confirmed values: biller_id, source_account,
    amount (string or cents), frequency, start_date, and either
    occurrence_count or end_date, plus `auto_after_supervised` — True/False,
    with no default: leaving it out is an error, never "no"."""
    errors: dict[str, str] = {}
    today = schedule.local_date(now, tz)

    biller = _billers.current(conn, str(form.get("biller_id") or ""))
    if biller is None:
        errors["biller_id"] = "Choose the bill to pay."

    account = str(form.get("source_account") or "")
    row = conn.execute("SELECT user_id FROM accounts WHERE id=?", (account,)).fetchone()
    if row is None or row["user_id"] != user_id or account == "acct_invest":
        errors["source_account"] = "Choose one of your accounts."

    amount = parse_amount(form.get("amount_cents") if form.get("amount") is None
                          else form.get("amount"))
    cap = conn.execute("SELECT value FROM limits WHERE key='per_transaction'").fetchone()
    if amount is None:
        errors["amount"] = "Enter the amount of each payment, e.g. 85.00."
    elif cap and amount > int(cap["value"]):
        errors["amount"] = f"Each payment can be at most ${cents_to_display(int(cap['value']))}."

    frequency = form.get("frequency")
    if frequency not in schedule.FREQUENCIES:
        errors["frequency"] = "Choose weekly or monthly."

    start = None
    try:
        start = schedule.parse_date(str(form.get("start_date") or ""))
    except ValueError:
        errors["start_date"] = "Choose the date of the first payment."
    if start is not None and schedule.due_at(start, tz) <= now:
        errors["start_date"] = "The first payment has to be in the future."

    count = None
    if not errors.keys() & {"frequency", "start_date"}:
        raw_count, raw_end = form.get("occurrence_count"), form.get("end_date")
        if raw_count not in (None, "") and raw_end not in (None, ""):
            errors["end"] = "Choose a number of payments OR an end date, not both."
        elif raw_count not in (None, ""):
            try:
                count = int(raw_count)
            except (TypeError, ValueError):
                count = 0
            if not 1 <= count <= MAX_OCCURRENCES:
                errors["end"] = f"Choose between 1 and {MAX_OCCURRENCES} payments."
                count = None
        elif raw_end not in (None, ""):
            try:
                end = schedule.parse_date(str(raw_end))
            except ValueError:
                end = None
            if end is None or end < start:
                errors["end"] = "The end date has to be on or after the first payment."
            else:
                count = schedule.count_until(frequency, start, end, limit=MAX_OCCURRENCES)
                if count > MAX_OCCURRENCES:
                    errors["end"] = f"That's more than {MAX_OCCURRENCES} payments."
                    count = None
        else:
            errors["end"] = "Choose when it stops: a number of payments or an end date."
        if count:
            dates = schedule.occurrence_dates(frequency, start, count)
            if (dates[-1] - dates[0]).days > MAX_SPAN_DAYS:
                errors["end"] = "A recurring payment can run for at most five years."

    auto = form.get("auto_after_supervised")
    if not isinstance(auto, bool):
        errors["auto_after_supervised"] = (
            "Choose whether to approve every payment yourself, or the first "
            f"{SUPERVISED_APPROVALS} and then pay automatically.")

    if errors:
        return None, errors
    dates = schedule.occurrence_dates(frequency, start, count)
    terms = RecurringBillMandate(
        mandate_id=mandate_id, version=1, draft_id=draft_id, user_id=user_id,
        source_account=account, source_display=account_label(account),
        biller_id=biller.biller_id, biller_display=biller.name,
        biller_reference_masked=biller.masked, biller_ref_version=biller.version,
        biller_ref_hash=biller.ref_hash, amount_cents=amount, frequency=frequency,
        timezone=tz, due_local_time=schedule.DUE_LOCAL_TIME, start_date=start.isoformat(),
        end_date=dates[-1].isoformat(), occurrence_count=count,
        per_payment_cap_cents=amount, total_cap_cents=amount * count,
        supervised_approvals=SUPERVISED_APPROVALS, auto_after_supervised=auto,
        valid_until=schedule.review_until(dates[-1], tz),
        transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + MAX_AUTH_WINDOW_S)
    return terms, {}


def preview(terms: RecurringBillMandate) -> dict:
    """What the review card shows besides the terms: the first dates, the last,
    and when automatic payment would begin. Derived from the terms only."""
    dates = terms.due_dates()
    n = terms.supervised_approvals
    return {
        "first_dates": [schedule.label(d) for d in dates[:3]],
        "final_date": schedule.label(dates[-1]),
        "due_time": f"{terms.due_local_time} ({terms.timezone})",
        "count": terms.occurrence_count,
        "amount_display": "$" + cents_to_display(terms.amount_cents),
        "total_display": "$" + cents_to_display(terms.total_cap_cents),
        "frequency_label": "Every month" if terms.frequency == schedule.MONTHLY else "Every week",
        "approvals": (f"You approve the first {n} payments one by one. After {n} approved "
                      f"payments, the rest are paid automatically on their due date."
                      if terms.auto_after_supervised and terms.occurrence_count > n else
                      "You approve every payment yourself — nothing is paid automatically."),
        "auto_from_payment": (n + 1 if terms.auto_after_supervised
                              and terms.occurrence_count > n else None),
        "short_months": ("In a month without that day, it's paid on the month's last day."
                         if terms.frequency == schedule.MONTHLY
                         and schedule.parse_date(terms.start_date).day > 28 else None),
    }


def occurrence_transcript(terms: RecurringBillMandate, seq: int, due: date) -> str:
    """The words an occurrence's one-payment draft is bound to (its
    transcript_hash): which mandate, which payment, for what. Server text."""
    return (f"Recurring payment {seq} of {terms.occurrence_count} for "
            f"{terms.biller_display}: ${cents_to_display(terms.amount_cents)} from "
            f"{terms.source_display}, due {schedule.label(due)} "
            f"(arrangement {terms.mandate_id} v{terms.version}).")


def occurrence_plan(terms: RecurringBillMandate, *, draft_id: str, seq: int, due: date,
                    now: int) -> ResolvedPlan:
    """The ordinary one-payment plan for one occurrence — exactly the mandate's
    biller, account and amount, nothing else. For a supervised occurrence it is
    what the user signs; for an automatic one it is only the executor's input
    (it is never submitted, so its 5-minute window authorizes nothing)."""
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[ResolvedPayBill(id="b1", source_account=terms.source_account,
                              biller_id=terms.biller_id, biller_display=terms.biller_display,
                              amount_cents=terms.amount_cents)],
        transcript_hash=hash_transcript(occurrence_transcript(terms, seq, due)),
        created_at=now, expires_at=now + MAX_AUTH_WINDOW_S)


def matches_terms(plan: ResolvedPlan, terms: RecurringBillMandate) -> bool:
    """A plan that pays exactly one occurrence of these terms."""
    if len(plan.plan) != 1:
        return False
    leg = plan.plan[0]
    return (leg.type == "PAY_BILL" and leg.source_account == terms.source_account
            and leg.biller_id == terms.biller_id and leg.amount_cents == terms.amount_cents)
