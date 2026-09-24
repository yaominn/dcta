"""
Ownership: the person who signed must own what the payload touches.

The signature step proves a registered passkey approved EXACTLY this payload.
It says nothing about WHOSE passkey that is relative to the money: before this
check, any valid passkey could authorize a debit from any account, pay into
another customer's saved payee, or rename another customer's contact. The
gateway already knew both halves — the credential store records each passkey's
user, and policy.owner_of() reads the accounts' owner — it just never compared
them.

Runs AFTER signature verification, never before: an unsigned or badly signed
request for someone else's account is rejected for its signature, so this check
cannot be used to probe who owns what.

Every lookup reads the ledger rows, never a field in the request, and fails
CLOSED: an unknown signer, an unknown account or payee, or one owned by anyone
else is a rejection, never "nothing to check".

Billers and equity tickers are shared by every customer and belong to no one,
so they carry no ownership.

The evidence on success is the point for the demo: the gateway does not just
decline to object, it states whose passkey signed and what that person owns.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from backend.data.db import connect
from backend.models.contacts import ResolvedContactChange
from backend.models.schemas import ResolvedPlan


@dataclass
class Ownership:
    ok: bool
    reason: str = ""
    evidence: dict = field(default_factory=dict)


def check_plan(plan: ResolvedPlan, signer: str | None, *, db_path) -> Ownership:
    """Every debited account and every transfer's payee must belong to the signer."""
    accounts = {leg.source_account for leg in plan.plan}
    payees = {leg.payee_id for leg in plan.plan if leg.type == "TRANSFER"}
    return _check(signer, accounts=accounts, payees=payees, db_path=db_path)


def check_contact_change(change: ResolvedContactChange, signer: str | None, *,
                         db_path) -> Ownership:
    """Every payee being edited must belong to the signer."""
    return _check(signer, accounts=set(),
                  payees={e.payee_id for e in change.edits}, db_path=db_path)


def _check(signer: str | None, *, accounts: set[str], payees: set[str],
           db_path) -> Ownership:
    if not signer:
        return Ownership(False, "the signing credential is not registered to any user")
    if not accounts and not payees:
        return Ownership(False, "the payload names nothing to authorize")

    conn = connect(db_path)
    try:
        user = conn.execute("SELECT nickname FROM users WHERE id=?", (signer,)).fetchone()
        acct_rows = _rows(conn, "SELECT id, user_id, type AS label FROM accounts", accounts)
        payee_rows = _rows(conn, "SELECT id, user_id, nickname AS label FROM payees", payees)
    finally:
        conn.close()

    if user is None:
        return Ownership(False, "the signing credential's user does not exist")

    # Name only the ids the REQUEST supplied — never the actual owner, which
    # would turn a rejection into an account-ownership oracle.
    for kind, wanted, rows in (("account", accounts, acct_rows),
                               ("payee", payees, payee_rows)):
        found = {r["id"]: r for r in rows}
        for item in sorted(wanted):
            if item not in found:
                return Ownership(False, f"unknown {kind} {item}")
            if found[item]["user_id"] != signer:
                return Ownership(False, f"the signer does not own {kind} {item}")

    return Ownership(True, evidence={
        "verified": True,
        "signer": signer,
        "signer_name": user["nickname"],
        "accounts": [{"id": r["id"], "label": r["label"]} for r in sorted(acct_rows, key=_id)],
        "payees": [{"id": r["id"], "label": r["label"]} for r in sorted(payee_rows, key=_id)],
    })


def _rows(conn, select: str, ids: set[str]) -> list:
    if not ids:
        return []
    marks = ",".join("?" * len(ids))
    return conn.execute(f"{select} WHERE id IN ({marks})", tuple(ids)).fetchall()


def _id(row) -> str:
    return row["id"]
