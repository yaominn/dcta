"""
The recurring-bill mandate: what the user signs ONCE to let a fixed bill be
paid on a schedule. A SEPARATE contract from schemas.py (frozen v1, one
payment, a 5-minute window) — deliberately.

Why not stretch ResolvedPlan: a ResolvedPlan is an authorization to move one
amount, once, within MAX_AUTH_WINDOW_S of being drafted. Giving it a longer
expires_at, or re-using its signature next month, would turn every existing
"one payment" guarantee into "some payments, for a while". The mandate is its
own kind of authorization, with its own limits, so neither can be mistaken for
the other:

  - It is BOUNDED by construction: a fixed amount in integer cents, a fixed
    count (<= MAX_OCCURRENCES), dates the user reviewed, a per-payment cap
    equal to that amount and a total cap equal to amount x count — the
    validator below refuses terms that disagree with themselves, so they can
    never be signed.
  - It names WHERE the money goes as it was when signed: the biller id, the
    version of its reference, and a hash of the reference itself
    (backend/data/billers.py). A changed reference stops every payment.
  - It carries the user's EXPLICIT choice about automatic payment
    (auto_after_supervised). False means every payment needs its own approval;
    True means the first SUPERVISED_APPROVALS need it and later ones may be
    paid by the server — only within these exact terms and the safety rules of
    the day (gateway.run_mandate_occurrence).
  - Like every signed payload here, it binds draft_id (the nonce binds to it),
    a transcript hash, and a short SIGNING window (created_at / expires_at <=
    MAX_AUTH_WINDOW_S). That window is how long the user has to sign; the
    mandate's own authority ends at valid_until.

No field here comes from a model: recurring setup is parsed by rules and every
value is confirmed by the user in a form (backend/recurring/terms.py).
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.models.schemas import MAX_AMOUNT_CENTS, MAX_AUTH_WINDOW_S
from backend.recurring import schedule

MAX_OCCURRENCES = 60                 # five years of monthly payments
MAX_SPAN_DAYS = 5 * 366
SUPERVISED_APPROVALS = 3
DEFAULT_TIMEZONE = "Asia/Singapore"


class RecurringBillMandate(BaseModel):
    """The canonical payload hashed and signed to create a recurring bill
    payment. Every field is shown on the review card."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    kind: Literal["RECURRING_BILL_MANDATE"] = "RECURRING_BILL_MANDATE"
    mandate_id: str = Field(pattern=r"^mdt_[A-Za-z0-9_-]{16,40}$")    # server-issued
    version: int = Field(ge=1)
    draft_id: str
    user_id: str
    source_account: str
    source_display: str                       # "Savings" — from OUR ids, never the model
    biller_id: str
    biller_display: str                       # the biller's name, from the DB
    biller_reference_masked: str              # "Ref ••231" — never the raw text
    biller_ref_version: int = Field(ge=1)
    biller_ref_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    amount_cents: int = Field(gt=0, le=MAX_AMOUNT_CENTS)
    currency: Literal["SGD"] = "SGD"
    frequency: Literal["WEEKLY", "MONTHLY"]
    timezone: str
    due_local_time: str = Field(pattern=r"^\d{2}:\d{2}$")
    short_month_rule: Literal["LAST_DAY_OF_MONTH"] = "LAST_DAY_OF_MONTH"
    start_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")
    end_date: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}$")    # the LAST payment's date
    occurrence_count: int = Field(ge=1, le=MAX_OCCURRENCES)
    per_payment_cap_cents: int = Field(gt=0, le=MAX_AMOUNT_CENTS)
    total_cap_cents: int = Field(gt=0)
    supervised_approvals: int = Field(ge=1, le=MAX_OCCURRENCES)
    auto_after_supervised: bool
    valid_until: int                          # Unix s: no payment of any kind after this
    transcript_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: int                           # the SIGNING window, not the mandate's life
    expires_at: int

    @model_validator(mode="after")
    def _check(self):
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MAX_AUTH_WINDOW_S:
            raise ValueError(f"signing window exceeds {MAX_AUTH_WINDOW_S}s")
        try:
            schedule.zone(self.timezone)
        except Exception:
            raise ValueError(f"unknown time zone {self.timezone!r}") from None
        if self.due_local_time != schedule.DUE_LOCAL_TIME:
            raise ValueError(f"payments fall due at {schedule.DUE_LOCAL_TIME}")
        # Fixed amount: the cap IS the amount, and the total IS amount x count.
        # A variable bill would need a trusted bill feed this demo doesn't have.
        if self.per_payment_cap_cents != self.amount_cents:
            raise ValueError("the per-payment cap must equal the fixed amount")
        if self.total_cap_cents != self.amount_cents * self.occurrence_count:
            raise ValueError("the total cap must equal amount x number of payments")
        if self.supervised_approvals != SUPERVISED_APPROVALS:
            raise ValueError(f"the first {SUPERVISED_APPROVALS} payments need approval")
        # The dates must be the ones the schedule rules give: the end date the
        # user saw is the last due date, and the life of the mandate ends with
        # the last payment's approval window.
        dates = self.due_dates()
        if dates[-1].isoformat() != self.end_date:
            raise ValueError("end_date is not the last due date of this schedule")
        if (dates[-1] - dates[0]).days > MAX_SPAN_DAYS:
            raise ValueError("a recurring payment can run for at most five years")
        if self.valid_until != schedule.review_until(dates[-1], self.timezone):
            raise ValueError("valid_until does not match the last payment")
        if not re.fullmatch(r"[^\x00-\x1f]{1,64}", self.biller_display):
            raise ValueError("bad biller name")
        return self

    def due_dates(self):
        return schedule.occurrence_dates(self.frequency, schedule.parse_date(self.start_date),
                                         self.occurrence_count)
