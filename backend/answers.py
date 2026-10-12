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


def balance(user_id: str, *, db_path: Path | None = None) -> str:
    """'Savings $8,420.50 · Spending $1,200.00.' — the accounts the user spends
    from (the investments settlement account is internal)."""
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT id, balance FROM accounts WHERE user_id=? AND type != 'settlement' "
            "ORDER BY CASE type WHEN 'savings' THEN 0 ELSE 1 END, id", (user_id,)).fetchall()
    finally:
        conn.close()
    if not rows:
        return "No accounts found."
    return " · ".join(f"{account_label(r['id'])} {_money(r['balance'])}" for r in rows) + "."


def _day(ts: str) -> str:
    """'12 Oct', in this server's local time."""
    try:
        when = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if when.tzinfo is not None:
            when = when.astimezone()
        return f"{when.day} {when:%b}"
    except (ValueError, AttributeError):
        return "earlier"


def recent_payments(user_id: str, *, db_path: Path | None = None) -> str:
    """The last few payments, newest first, one per line:
    '$50.00 to Mom ··3310 · 12 Oct'. A bill or a share purchase has no payee
    on record, so it says what it was."""
    conn = _conn(db_path)
    try:
        rows = conn.execute(
            "SELECT h.leg_type, h.amount, h.ts, p.nickname, p.last4 "
            "FROM transaction_history h LEFT JOIN payees p ON p.id = h.payee_id "
            "WHERE h.user_id=? ORDER BY h.id DESC LIMIT ?", (user_id, RECENT_COUNT)).fetchall()
    finally:
        conn.close()
    if not rows:
        return NO_PAYMENTS
    lines = []
    for r in rows:
        if r["leg_type"] == "PAY_BILL":
            what = "for a bill"
        elif r["leg_type"] == "BUY_EQUITY":
            what = "for shares"
        else:
            what = f"to {r['nickname']} ··{r['last4']}" if r["nickname"] else "to a payee"
        lines.append(f"{_money(r['amount'])} {what} · {_day(r['ts'])}")
    return "\n".join(lines)


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
    the contacts list itself, not a sentence)."""
    if label == "balance":
        message = balance(user_id, db_path=db_path)
    elif label == "recent_payments":
        message = recent_payments(user_id, db_path=db_path)
    elif label == "why_stopped":
        message = why_stopped(stopped)
    elif label == "what_can_you_do":
        message = WHAT_CAN_YOU_DO
    else:
        message = OFF_TOPIC
    return {"status": "info", "kind": "answer", "message": message}
