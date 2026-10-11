"""
When a recurring bill falls due — pure date arithmetic, no clock, no database.

Every rule here is deterministic, so the dates the user reviews and signs are
the dates the scheduler pays on:

  - WEEKLY : the start date, then every 7 days.
  - MONTHLY: the start date's day of the month, every month. A month without
             that day (the 31st in April, the 29th-31st in February) pays on
             its LAST day, and the next month goes back to the start's day:
             31 Jan -> 28 Feb -> 31 Mar -> 30 Apr. Never drifts to the 28th.
  - A payment falls due at DUE_LOCAL_TIME on its date, in the mandate's IANA
    time zone (Asia/Singapore for the demo), so "1 November" means 09:00 SGT
    on 1 November, whatever the server's own zone is.

Two windows, both whole local days, both bounded:

  - an AUTOMATIC payment runs on its due date only (from DUE_LOCAL_TIME until
    local midnight). A run that only comes later — the server was down, the
    arrangement was paused — does not catch up: that payment is MISSED.
  - a payment waiting for the user's approval can be approved until the end
    of the REVIEW_DAYS-th day after its due date, then it EXPIRES. It is never
    paid later without a fresh approval.
"""
from __future__ import annotations

import calendar
from datetime import date, datetime, time, timedelta
from zoneinfo import ZoneInfo

WEEKLY, MONTHLY = "WEEKLY", "MONTHLY"
FREQUENCIES = (WEEKLY, MONTHLY)
DUE_LOCAL_TIME = "09:00"
REVIEW_DAYS = 3
SHORT_MONTH_RULE = "LAST_DAY_OF_MONTH"


def parse_date(text: str) -> date:
    """"2026-11-01" -> date. Raises ValueError on anything else."""
    return date.fromisoformat(text)


def _month_add(d: date, months: int, anchor_day: int) -> date:
    y, m = divmod(d.month - 1 + months, 12)
    year, month = d.year + y, m + 1
    return date(year, month, min(anchor_day, calendar.monthrange(year, month)[1]))


def occurrence_dates(frequency: str, start: date, count: int) -> list[date]:
    """The `count` due dates, first to last."""
    if frequency == WEEKLY:
        return [start + timedelta(days=7 * i) for i in range(count)]
    if frequency == MONTHLY:
        return [_month_add(start, i, start.day) for i in range(count)]
    raise ValueError(f"unknown frequency {frequency!r}")


def count_until(frequency: str, start: date, end: date, *, limit: int) -> int:
    """How many due dates fall on or before `end` (at most limit + 1, so a
    caller can tell "too many" from "exactly the limit")."""
    n = 0
    while n <= limit:
        if occurrence_dates(frequency, start, n + 1)[-1] > end:
            break
        n += 1
    return n


def zone(tz: str) -> ZoneInfo:
    return ZoneInfo(tz)


def _hhmm(text: str) -> time:
    h, m = text.split(":")
    return time(int(h), int(m))


def due_at(d: date, tz: str, local_time: str = DUE_LOCAL_TIME) -> int:
    """Unix seconds of `local_time` on `d` in `tz`."""
    return int(datetime.combine(d, _hhmm(local_time), tzinfo=zone(tz)).timestamp())


def day_end(d: date, tz: str) -> int:
    """The last second of local day `d` in `tz` (Unix seconds)."""
    nxt = datetime.combine(d + timedelta(days=1), time(0), tzinfo=zone(tz))
    return int(nxt.timestamp()) - 1


def review_until(d: date, tz: str) -> int:
    """Until when a payment due on `d` can still be approved."""
    return day_end(d + timedelta(days=REVIEW_DAYS), tz)


def local_date(ts: int, tz: str) -> date:
    return datetime.fromtimestamp(ts, zone(tz)).date()


def label(d: date) -> str:
    """"Sun 1 Nov 2026" — the same on every machine (no locale)."""
    return f"{calendar.day_abbr[d.weekday()]} {d.day} {calendar.month_abbr[d.month]} {d.year}"
