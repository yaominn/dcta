"""
Answers to the questions a request with no payment can ask ("how much do I
have?", "why did you stop that?"). The model only picked the label
(backend/agent/question.py); every sentence here is fixed text filled from the
ledger by this code, so nothing the model writes reaches the screen.

Never says whether a payment is safe. A stopped request's answer only repeats
the rule sentences the user was already shown.

Outside backend/agent/ on purpose: the agent package is DB-free and must not
reach the ledger directly (tests/test_import_boundary.py).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path

from backend.data.db import connect, get_conn
from backend.display import account_label, cents_to_display

WHAT_CAN_YOU_DO = ("I can pay people and bills, buy shares, and manage your contacts. "
                   "Nothing moves until you approve it.")
OFF_TOPIC = "I can only help with your money and contacts here."
NOTHING_STOPPED = "Nothing has been stopped recently."
SCAMSHIELD = "If someone is pushing you to pay, call ScamShield on 1799."
NO_PAYMENTS = "No payments yet."
RECENT_COUNT = 5


def _conn(db_path: Path | None):
    return connect(db_path) if db_path is not None else get_conn()


def _money(cents: int) -> str:
    return "$" + cents_to_display(cents)


def _balance_rows(user_id: str, db_path: Path | None) -> list[tuple[str, int]]:
    """(account label, cents) for the accounts the user spends from (the
    investments settlement account is internal), savings first."""
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id, balance FROM accounts WHERE user_id=? AND type != 'settlement' "
            "ORDER BY CASE type WHEN 'savings' THEN 0 ELSE 1 END, id", (user_id,)).fetchall()
    finally:
        conn.close()
    return [(account_label(r["id"]), r["balance"]) for r in rows]


def balance(user_id: str, *, db_path: Path | None = None) -> str:
    """'Savings $8,420.50 · Spending $1,200.00.'"""
    rows = _balance_rows(user_id, db_path)
    if not rows:
        return "No accounts found."
    return " · ".join(f"{name} {_money(cents)}" for name, cents in rows) + "."


def _day(ts: str) -> str:
    """'12 Oct', in this server's local time."""
    try:
        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if when.tzinfo is not None:
            when = when.astimezone()
        return f"{when.day} {when:%b}"
    except (ValueError, AttributeError):
        return "earlier"


def _recent_rows(user_id: str, db_path: Path | None) -> list[tuple[str, str, int]]:
    """(day, who it went to, cents) for the last few payments, newest first.
    A bill or a share purchase has no payee on record, so it says what it was."""
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT h.leg_type, h.amount, h.ts, p.nickname, p.last4 "
            "FROM transaction_history h LEFT JOIN payees p ON p.id = h.payee_id "
            # Newest first by when it happened (rows aren't inserted in date
            # order: the seed writes its history oldest-last). ts is ISO-8601 UTC.
            "WHERE h.user_id=? ORDER BY h.ts DESC, h.id DESC LIMIT ?",
            (user_id, RECENT_COUNT)).fetchall()
    finally:
        conn.close()
    out = []
    for r in rows:
        if r["leg_type"] == "PAY_BILL":
            who = "A bill"
        elif r["leg_type"] == "BUY_EQUITY":
            who = "Shares"
        else:
            who = f"{r['nickname']} ··{r['last4']}" if r["nickname"] else "A payee"
        out.append((_day(r["ts"]), who, r["amount"]))
    return out


# A row with no payee, as the sentence says it.
_SAID = {"A bill": "for a bill", "Shares": "for shares", "A payee": "to a payee"}


def recent_payments(user_id: str, *, db_path: Path | None = None) -> str:
    """The last few payments, newest first, one per line:
    '$50.00 to Mom ··3310 · 12 Oct'."""
    rows = _recent_rows(user_id, db_path)
    if not rows:
        return NO_PAYMENTS
    lines = []
    for day, who, cents in rows:
        what = _SAID.get(who, "to " + who)
        lines.append(f"{_money(cents)} {what} · {day}")
    return "\n".join(lines)


def _table(title: str, columns: list[tuple[str, bool]], rows: list[list[str]],
           footer: list[str] | None = None) -> dict:
    """A table the app draws as a card: columns are (label, numeric) and a
    numeric column is right-aligned. Every cell is text this code wrote."""
    out = {"title": title,
           "columns": [{"label": label, "numeric": numeric} for label, numeric in columns],
           "rows": rows}
    if footer:
        out["footer"] = footer
    return out


def balance_table(user_id: str, *, db_path: Path | None = None) -> dict | None:
    rows = _balance_rows(user_id, db_path)
    if not rows:
        return None
    total = ["Total", _money(sum(cents for _, cents in rows))] if len(rows) > 1 else None
    return _table("Balances", [("Account", False), ("Balance", True)],
                  [[name, _money(cents)] for name, cents in rows], footer=total)


def recent_table(user_id: str, *, db_path: Path | None = None) -> dict | None:
    rows = _recent_rows(user_id, db_path)
    if not rows:
        return None
    return _table("Recent payments", [("Date", False), ("Paid to", False), ("Amount", True)],
                  [[day, who, _money(cents)] for day, who, cents in rows])


def why_stopped(reasons: list[str] | None) -> str:
    """The last stopped request's own reason sentences (rule text the user was
    shown), then where to call. Never a judgement of its own."""
    if not reasons:
        return NOTHING_STOPPED
    said = " ".join(r.strip() if r.strip().endswith((".", "!", "?", ")")) else r.strip() + "."
                    for r in reasons if r and r.strip())
    return f"{said} {SCAMSHIELD}" if said else NOTHING_STOPPED


def reply(label: str, user_id: str, *, stopped: list[str] | None = None,
          db_path: Path | None = None) -> dict:
    """The info reply for a label. "contacts" is handled by the caller (it is
    the contacts list itself, not a sentence). An answer with several rows
    also carries them as a `table` for the app to draw; `message` stays the
    same answer as text (spoken aloud, and for any client without tables)."""
    table = None
    if label == "balance":
        message = balance(user_id, db_path=db_path)
        table = balance_table(user_id, db_path=db_path)
    elif label == "recent_payments":
        message = recent_payments(user_id, db_path=db_path)
        table = recent_table(user_id, db_path=db_path)
    elif label == "why_stopped":
        message = why_stopped(stopped)
    elif label == "what_can_you_do":
        message = WHAT_CAN_YOU_DO
    else:
        message = OFF_TOPIC
    out = {"status": "info", "kind": "answer", "message": message}
    if table:
        out["table"] = table
    return out
