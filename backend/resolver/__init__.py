"""
Deterministic Resolver + clarify loop. (brief Section 5 / Section 8)

Responsibility: take the LLM's symbolic `IntentPlan` and resolve every field to
a concrete, verified value — PURE deterministic code, no LLM. The resolver is
the boundary at which a *mention* (what the user said) becomes a *concrete id*
(a row in our database). That mapping is never delegated to the model, because
the model must never emit an identifier naming a row (brief governing rule).

  - Payee/biller/equity mention -> concrete id, with 0 / 1 / 2+ logic:
        0  -> ask ("I don't have a payee called X")
        1  -> proceed
        2+ -> ask with distinguishing detail ("John ··4521, or John ··8892?")
  - Symbolic amount ({after_leg, op}) -> a concrete number against a SIMULATED
    ledger (copy starting balances, apply each leg in order, read the referenced
    leg's own source-account balance). Integer arithmetic only — no floats.
  - BUY_EQUITY: floor to WHOLE shares; the remainder stays in the account. The
    signed `amount_cents` is the SPEND (shares × price), not the allocated
    dollars — that is the reading that makes the headline acceptance case
    (32 shares, 772800 cents, remainder 19250) come out right. See write-up.
  - `unresolved` from the LLM is a HINT, not a gate: every required field is
    independently verified, regardless of what `unresolved` says. Clarifying
    authority stays with the resolver, never the model.
  - Insufficient funds / a symbolic amount that resolves to zero -> a clarifying
    question, never a constructed zero-amount leg (`amount_cents` is `gt=0`).

The return is either a complete `ResolvedPlan` (canonical, hashable, signable)
or a `Clarify` (one short voice-first question + enough state to resume). The
resume mechanism: `answers={field: chosen_id}` — the resolver re-runs the
deterministic match and validates the chosen id is among the candidates, so a
caller can never inject an id the mention doesn't justify. Open questions
(0-match / empty plan / insufficient) re-pipeline through ASR+parse rather than
`answers`; see the write-up for that boundary.

# This module is LLM-free by construction and by test: tests/test_import_boundary
# .py forbids backend.resolver from reaching backend.agent, so "deterministic" is
# a CI-checked property, not a docstring claim (brief 5.4).
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable

from backend.audit.canonical import hash_transcript
from backend.data.db import connect, get_conn
from backend.display import account_label, cents_to_display
from backend.models.schemas import (
    MAX_AUTH_WINDOW_S,
    AmountOp,
    BuyEquityIntent,
    IntentPlan,
    LiteralAmount,
    PayBillIntent,
    ResolvedBuyEquity,
    ResolvedPayBill,
    ResolvedPlan,
    ResolvedTransfer,
    SymbolicAmount,
    TransferIntent,
)


# --------------------------------------------------------------------------- mention normalisation
# ASR output and real model output carry whitespace, punctuation and filler
# words that the stub never produced: " mom", "mom.", "Mom,", "my savings",
# "savings account". Matching case only (the M4 shipping behaviour) rejected all
# of those, which is indefensible in front of a user. `_normalize` is applied to
# BOTH sides of every comparison, in ONE place, so the rule cannot drift between
# the four mention kinds.
#
# Filler words are dropped token-wise. Because the SAME function normalises the
# stored value, dropping "the" is safe even for a payee actually nicknamed "The
# Landlord" — both sides lose it.
_FILLER = frozenset({"my", "the", "a", "an", "account", "accounts", "please", "to"})


def _normalize(text: str) -> str:
    """Casefold, split on non-word characters, drop filler tokens, rejoin.

    "  Mom, " -> "mom";  "my savings account" -> "savings";  "AAPL." -> "aapl".
    Returns "" when nothing but filler is left, which is a 0-match (a question),
    never a guess."""
    tokens = [t for t in re.split(r"\W+", text.casefold(), flags=re.UNICODE) if t]
    kept = [t for t in tokens if t not in _FILLER]
    return " ".join(kept or tokens)


# What the user says -> the seeded `accounts.type` it means. The seed types are
# savings / joint / settlement; nobody says "settlement", so the investment
# account was previously unreachable by ANY spoken word. Deliberately small and
# demo-scoped, like EQUITY_NAME_TO_TICKER below.
ACCOUNT_TYPE_SYNONYMS: dict[str, str] = {
    "investment": "settlement",
    "investments": "settlement",
    "invest": "settlement",
    "brokerage": "settlement",
    "trading": "settlement",
    "current": "joint",
    "checking": "joint",
    # The demo presents the joint account as the everyday "Spending" account
    # (frontend ACCOUNT_LABELS), so the words on screen must resolve to it.
    "spending": "joint",
    "everyday": "joint",
    "saving": "savings",
}

# backend/agent/prompts.py instructs the model: "source_account is the account
# the user named; if they did not name one, use {"mention": "default"}". So
# "default" is a hint that THE USER WAS SILENT — not the name of an account.
# Matching it literally against accounts.type found nothing, so every transcript
# that did not name an account dead-ended in a clarification, including the
# README's own demo sentence. The rule below is the fix, and it is deliberately
# explicit rather than silent: the resolved source_account is a concrete id that
# the overlay renders, so the user still SEES which account is being debited
# before signing. A default you can see is consent; a default you cannot is the
# failure this project exists to prevent.
_DEFAULT_ACCOUNT_MENTIONS = frozenset({"default", "", "mine", "usual"})
_DEFAULT_ACCOUNT_TYPE = "savings"


# Curated name -> ticker table. The DB stores tickers + prices only (no company
# name column), so company-name matching lives here as a small, demo-quality
# constant. Real company-name search would be a DB column or a maintained table
# — kept small and honest about its scope, not a silent overclaim.
EQUITY_NAME_TO_TICKER: dict[str, str] = {
    "apple": "AAPL",
    "dbs": "D05",
    "ocbc": "O39",
}


# --------------------------------------------------------------------------- result types
@dataclass
class Clarify:
    """A single clarifying question + enough state to resume once answered.

    `field` is the dotted key (e.g. "t1.target") a caller uses in `answers`.
    `choices` carries the candidate rows (DB-sourced display only) for every
    mention question — both a 2+ disambiguation and a 0-match, so either can be
    answered in one round-trip. It is empty only for `empty` / `zero` /
    `insufficient`, where no candidate row exists to choose from.
    """
    question: str
    field: str
    kind: str                       # payee | biller | account | equity | empty | zero | insufficient | equity_too_small
    choices: list[dict]
    resume_state: dict


@dataclass
class Resolved:
    """A complete, canonical, signable plan."""
    plan: ResolvedPlan


@dataclass
class _LegResult:
    """Internal: a resolved leg plus the simulated-ledger effects to apply."""
    resolved: Any                  # a ResolvedTransfer | ResolvedPayBill | ResolvedBuyEquity
    source_acct: str               # the concrete account id this leg debited
    debit: int                     # cents actually debited (== spend for BUY_EQUITY)


# --------------------------------------------------------------------------- public API
def resolve(
    intent_plan: IntentPlan,
    *,
    transcript: str,
    user_id: str,
    now: int | None = None,
    draft_id: str | None = None,
    answers: dict[str, str] | None = None,
    db_path=None,
) -> Resolved | Clarify:
    """Turn a symbolic IntentPlan into a concrete ResolvedPlan, or a clarifying
    question. Deterministic; touches no LLM.

    `answers` resumes a 2+ disambiguation: pass the chosen id back under the
    `field` key the Clarify reported. The id is validated against a fresh
    deterministic match — a caller cannot inject an id the mention doesn't
    justify (same enforce-the-property move as extra="forbid").

    `db_path` targets an isolated ledger (tests); omit it for the default mock
    ledger. Without it a test cannot resolve against a tmp_path DB the way
    tests/test_gateway.py does.
    """
    now = int(time.time()) if now is None else int(now)
    draft_id = draft_id or uuid.uuid4().hex
    answers = answers or {}

    # resume state: self-contained enough that the caller can resume after one
    # round-trip. draft_id is load-bearing — a resumed resolution keeps the same
    # draft_id so the WebAuthn nonce binding is stable across the clarify loop.
    resume: dict[str, Any] = {
        "intent_plan": intent_plan.model_dump(),
        "transcript": transcript,
        "user_id": user_id,
        "draft_id": draft_id,
    }

    # An empty IntentPlan is the parser saying "I understood no intent". Nothing
    # downstream has anything to resolve: ask, and build NO ResolvedPlan (a
    # signature over an empty authorization is valid crypto and meaningless
    # consent — see ResolvedPlan.plan min_length=1).
    if not intent_plan.plan:
        return Clarify(
            question="I didn't catch a payment in that — what would you like to do?",
            field="__empty__",
            kind="empty",
            choices=[],
            resume_state=resume,
        )

    conn = connect(db_path) if db_path is not None else get_conn()
    try:
        # SIMULATED ledger: a copy. The real DB is never mutated here — execution
        # is the gateway's job, after a signature. We only read balances to
        # compute symbolic amounts and to refuse plans that would fail at execution.
        balances: dict[str, int] = {
            row["id"]: row["balance"]
            for row in conn.execute(
                "SELECT id, balance FROM accounts WHERE user_id=?", (user_id,)
            ).fetchall()
        }
        leg_source: dict[str, str] = {}          # leg id -> resolved source acct id
        resolved_legs: list[Any] = []

        for leg in intent_plan.plan:
            result = _resolve_leg(
                conn, leg, user_id, balances, leg_source, answers, resume
            )
            if isinstance(result, Clarify):
                return result
            # apply this leg's debit to the simulated ledger, in plan order
            balances[result.source_acct] -= result.debit
            leg_source[leg.id] = result.source_acct
            resolved_legs.append(result.resolved)
    finally:
        conn.close()

    # Defensive: a non-empty plan that resolved every leg always has >=1 leg
    # (the only exit paths above are Clarify). ResolvedPlan enforces min_length=1
    # at construction regardless.
    plan = ResolvedPlan(
        draft_id=draft_id,
        plan=resolved_legs,
        transcript_hash=hash_transcript(transcript),
        created_at=now,
        expires_at=now + MAX_AUTH_WINDOW_S,
    )
    return Resolved(plan=plan)


# --------------------------------------------------------------------------- per-leg resolution
def _resolve_leg(
    conn,
    leg: Any,
    user_id: str,
    balances: dict[str, int],
    leg_source: dict[str, str],
    answers: dict[str, str],
    resume: dict[str, Any],
) -> _LegResult | Clarify:
    is_symbolic = isinstance(leg.amount, SymbolicAmount)

    # 1. SOURCE ACCOUNT ------------------------------------------------------
    # For a symbolic-amount leg the account is DERIVED from the referenced leg's
    # own source_account (brief 5.2: "never stated"), so a ref can never
    # contradict the leg it depends on. The leg still carries a source_account
    # mention (the schema requires it) but for symbolic legs we ignore it for
    # the debit — the stub parser may fill it with "default" when the user said
    # nothing; deriving keeps that from becoming a spurious clarify.
    if is_symbolic:
        source_acct = leg_source.get(leg.amount.after_leg)
        # after_leg is guaranteed by the schema to be an EARLIER leg, so its
        # source is already resolved and present. Unreachable in practice.
        if source_acct is None:  # pragma: no cover
            return Clarify(
                question="I couldn't determine the account for that step — which account?",
                field=f"{leg.id}.source_account",
                kind="account",
                choices=[],
                resume_state=resume,
            )
    else:
        acct = _resolve_account(
            conn, leg.source_account.mention, user_id,
            answers, f"{leg.id}.source_account", resume,
        )
        if isinstance(acct, Clarify):
            return acct
        source_acct = acct

    # 2. TARGET --------------------------------------------------------------
    if isinstance(leg, TransferIntent):
        tgt = _resolve_payee(
            conn, leg.target.mention, user_id,
            answers, f"{leg.id}.target", resume,
        )
        if isinstance(tgt, Clarify):
            return tgt
        payee_id, payee_display = tgt
    elif isinstance(leg, PayBillIntent):
        tgt = _resolve_biller(
            conn, leg.target.mention,
            answers, f"{leg.id}.target", resume,
        )
        if isinstance(tgt, Clarify):
            return tgt
        biller_id, biller_display = tgt
    elif isinstance(leg, BuyEquityIntent):
        tgt = _resolve_equity(
            conn, leg.ticker.mention,
            answers, f"{leg.id}.ticker", resume,
        )
        if isinstance(tgt, Clarify):
            return tgt
        ticker, price = tgt
    else:  # pragma: no cover - schema-constrained, unreachable
        raise RuntimeError(f"unknown intent type {leg.type!r}")

    # 3. AMOUNT -------------------------------------------------------------
    if is_symbolic:
        # the balance of the referenced leg's OWN source account, from the
        # simulated ledger at this point (i.e. after that leg — and any
        # intervening legs that also debited it — have executed).
        ref_acct = leg_source[leg.amount.after_leg]
        balance_now = balances[ref_acct]
        if leg.amount.op == AmountOp.ALL:
            amount = balance_now
        else:  # HALF — integer division; an odd balance loses a cent by design
            amount = balance_now // 2
    else:
        amount = leg.amount.literal_cents

    # 4. BUY_EQUITY: floor to whole shares -----------------------------------
    shares = None
    if isinstance(leg, BuyEquityIntent):
        if price <= 0:  # pragma: no cover - DB invariant
            return Clarify(
                question=f"I couldn't get a price for {ticker} — try again?",
                field=f"{leg.id}.amount",
                kind="equity_too_small",
                choices=[],
                resume_state=resume,
            )
        shares = amount // price
        if shares <= 0:
            # not enough to buy a single whole share -> clarify, never a zero leg
            return Clarify(
                question=(
                    f"{cents_to_display(amount)} isn't enough for a whole share of "
                    f"{ticker} at {cents_to_display(price)} — a different amount or account?"
                ),
                field=f"{leg.id}.amount",
                kind="equity_too_small",
                choices=[],
                resume_state=resume,
            )
        # the SPEND is what's debited; the remainder stays in the account.
        # amount_cents on the resolved leg is the spend, not the allocated
        # dollars (see module docstring).
        debit = shares * price
    else:
        debit = amount

    # 5. ZERO / INSUFFICIENT FUNDS ------------------------------------------
    # `amount_cents` is `gt=0`: a leg that moves nothing must not be constructed.
    # A symbolic ALL on a drained account lands here (debit == 0) -> clarify.
    if debit <= 0:
        return Clarify(
            question=(
                "After that, there'd be nothing left in that account to move — "
                "a different amount or account?"
            ),
            field=f"{leg.id}.amount",
            kind="zero",
            choices=[],
            resume_state=resume,
        )
    # Never sign a plan the executor would reject: if the simulated balance
    # can't cover the debit, ask rather than fail at execution time.
    if balances[source_acct] < debit:
        return Clarify(
            question=(
                f"Your account only has ${cents_to_display(balances[source_acct])} — "
                "a smaller amount, or a different account?"
            ),
            field=f"{leg.id}.amount",
            kind="insufficient",
            choices=[],
            resume_state=resume,
        )

    # 6. BUILD THE RESOLVED LEG ---------------------------------------------
    if isinstance(leg, TransferIntent):
        rleg = ResolvedTransfer(
            id=leg.id, type="TRANSFER", source_account=source_acct,
            payee_id=payee_id, payee_display=payee_display, amount_cents=debit,
        )
    elif isinstance(leg, PayBillIntent):
        rleg = ResolvedPayBill(
            id=leg.id, type="PAY_BILL", source_account=source_acct,
            biller_id=biller_id, biller_display=biller_display, amount_cents=debit,
        )
    else:
        rleg = ResolvedBuyEquity(
            id=leg.id, type="BUY_EQUITY", source_account=source_acct,
            ticker=ticker, amount_cents=debit,
            estimated_shares=shares, estimated_fill_price_cents=price,
        )
    return _LegResult(rleg, source_acct, debit)


# --------------------------------------------------------------------------- mention matchers
def _article(kind: str) -> str:
    """'an account', 'a payee' — the question is read aloud in the demo."""
    return "an" if kind[:1] in "aeiou" else "a"


def _pick(
    rows: list,
    mention: str,
    kind: str,
    field: str,
    resume: dict[str, Any],
    answers: dict[str, str],
    display: Callable[[Any], str],
    value: Callable[[Any], Any],
    ident: Callable[[Any], str],
    fallback: list | None = None,
    zero_question: str | None = None,
) -> Any:
    """0 / 1 / 2+ logic shared by every mention kind.

    Returns `value(row)` on a unique match (or a validated answer), else a
    Clarify carrying answerable `choices`.

    Both the 2+ and the 0-match paths are answerable via `answers[field]`, and
    in both cases the id is validated against a freshly computed candidate list
    — for 2+, the rows the mention matched; for 0-match, the user's own list
    (`fallback`). A caller can never smuggle in an id that neither justifies.
    Previously the 0-match path returned before it read `answers` and carried no
    choices at all, so "I don't have a payee called X" could not be answered:
    re-parsing the same transcript reproduced the same 0-match, which is an
    infinite loop in a voice flow.
    """
    candidates = rows if rows else list(fallback or [])

    if len(rows) == 1:
        return value(rows[0])

    chosen = answers.get(field)
    if chosen:
        for r in candidates:
            if str(ident(r)) == str(chosen):
                return value(r)
        # an id that is not among the candidates is ignored -> re-clarify

    choices = [{"id": ident(r), "display": display(r)} for r in candidates]
    if not rows:
        opts = " or ".join(c["display"] for c in choices[:4])
        question = zero_question or (
            f"I don't have {_article(kind)} {kind} called {mention!r}"
            + (f" — did you mean {opts}?" if opts else " — who did you mean?")
        )
    else:
        question = "Did you mean " + " or ".join(c["display"] for c in choices[:4]) + "?"
    return Clarify(
        question=question, field=field, kind=kind,
        choices=choices, resume_state=resume,
    )


def _match(rows: list, mention: str, key: str, synonyms: dict[str, str] | None = None) -> list:
    """Rows whose `key` normalises equal to the normalised mention. Both sides go
    through _normalize, so whitespace, punctuation, case and filler words cannot
    cause a false 0-match. Matching happens in Python rather than SQL `lower()`
    precisely so the two sides share one normaliser."""
    norm = _normalize(mention)
    if synonyms:
        norm = synonyms.get(norm, norm)
        keys = {_normalize(str(r[key])) for r in rows}
        if norm not in keys:
            # Several words, all naming the SAME account ("everyday spending"):
            # use it. Words naming different accounts ("joint savings") match
            # nothing, so the caller asks — never a guess between two accounts.
            named = {synonyms.get(t, t) for t in norm.split()
                     if t in synonyms or t in keys}
            if len(named) == 1:
                norm = named.pop()
    return [r for r in rows if _normalize(str(r[key])) == norm]


def _resolve_account(conn, mention, user_id, answers, field, resume):
    # Match on accounts.type (savings/joint/settlement) — NOT alias, which the
    # seed sets equal to the id and is useless for matching what a human says.
    # This is also the only field the M3 sanitizer exposes to the LLM.
    rows = conn.execute(
        "SELECT id, type, balance FROM accounts WHERE user_id=?", (user_id,)
    ).fetchall()

    zero_question = None
    if _normalize(mention) in _DEFAULT_ACCOUNT_MENTIONS:
        # The user named no account: use the documented default (their savings
        # account), or the only account they have. Anything else -> ask, with
        # every account offered as an answerable choice.
        matched = [r for r in rows if _normalize(r["type"]) == _DEFAULT_ACCOUNT_TYPE]
        if len(matched) != 1:
            matched = rows if len(rows) == 1 else []
        zero_question = "Which account should I use?"
    else:
        matched = _match(rows, mention, "type", ACCOUNT_TYPE_SYNONYMS)

    return _pick(
        matched, mention, "account", field, resume, answers,
        # Named as the page names it (backend/display.py), not by raw type.
        display=lambda r: f"{account_label(r['id'])} ({cents_to_display(r['balance'])})",
        value=lambda r: r["id"],
        ident=lambda r: r["id"],
        fallback=rows,
        zero_question=zero_question,
    )


def _resolve_payee(conn, mention, user_id, answers, field, resume):
    rows = conn.execute(
        "SELECT id, nickname, last4 FROM payees WHERE user_id=?", (user_id,)
    ).fetchall()
    # payee_display is built from OUR DB only: nickname + last4. Never from the
    # LLM, never from legal_name or biller reference_text (attacker-controllable;
    # biller_07.reference_text carries a live injection). Same format for the
    # disambiguation question and the signed payee_display, for a single
    # provenance-safe surface.
    return _pick(
        _match(rows, mention, "nickname"), mention, "payee", field, resume, answers,
        display=lambda r: f"{r['nickname']} ··{r['last4']}",
        value=lambda r: (r["id"], f"{r['nickname']} ··{r['last4']}"),
        ident=lambda r: r["id"],
        fallback=rows,
    )


def _resolve_biller(conn, mention, answers, field, resume):
    # Billers are not user-scoped in the schema (no user_id column) -> match
    # globally on name. biller_display is the name only — there is no last4,
    # and reference_text is the injection carrier, so it is never used.
    rows = conn.execute("SELECT id, name FROM billers").fetchall()
    return _pick(
        _match(rows, mention, "name"), mention, "biller", field, resume, answers,
        display=lambda r: r["name"],
        value=lambda r: (r["id"], r["name"]),
        ident=lambda r: r["id"],
        fallback=rows,
    )


def _resolve_equity(conn, mention, answers, field, resume):
    # The mention may be a ticker ("AAPL", "aapl.") or a company name ("Apple",
    # "my apple"). Try the ticker first, then the curated name->ticker table. An
    # unknown symbol is a clarify case offering the known tickers, never a guess.
    rows = conn.execute("SELECT ticker, price FROM equities").fetchall()
    matched = _match(rows, mention, "ticker")
    if not matched:
        tk = EQUITY_NAME_TO_TICKER.get(_normalize(mention))
        if tk:
            matched = [r for r in rows if r["ticker"] == tk]
    return _pick(
        matched, mention, "equity", field, resume, answers,
        display=lambda r: r["ticker"],
        value=lambda r: (r["ticker"], r["price"]),
        ident=lambda r: r["ticker"],
        fallback=rows,
    )
