"""
Independent amount extraction + symbolic recomputation. (brief §4.1)

This is the genuinely-independent half of the validator. It does two things the
resolver also does, but re-implemented here so the validator does NOT call into
`backend.resolver` — calling the resolver's own function would prove nothing
about independence.

  1. `extract_literal_cents(clause)` — pull EVERY amount derivable from one
     clause by rule (digits and number words), as a SET. Clause-localized: the
     caller pairs leg i with clause i, so a literal swapped in from a different
     clause is caught (a value globally derivable but not from THIS leg's clause
     is a freeze). The global "does this number appear in the transcript?"
     check is wrong on purpose — see the module docstring of `__init__`.

  2. `recompute_symbolic(intent_plan, resolved_plan, conn)` — recompute the
     symbolic arithmetic from first principles against a FRESH ledger copy:
     start balances, apply each leg's debit in order, read the referenced leg's
     own source-account balance, apply ALL/HALF, and for equity floor to whole
     shares so the result is the SPEND (shares × price), not the allocation.
     Compare that to the resolved leg's `amount_cents`.

Honest scope (state to judges, do not overclaim):
  The literal extractor catches HALLUCINATED amounts — a number the model
  invented that the user never said. It does NOT reliably catch MIS-HEARD
  amounts: "six" and "seven" are both valid number words, and the transcript is
  ASR output, so a mis-transcription can yield a valid-looking figure. The
  symbolic recomputation is the fully-independent check, because it never
  touches the transcript's number grammar at all — it re-derives the figure
  from the ledger and the op, then compares. (brief §4.1, §2)
"""
from __future__ import annotations

import re
from typing import TYPE_CHECKING

from backend.models.schemas import (
    AmountOp,
    ResolvedBuyEquity,
    ResolvedPayBill,
    ResolvedTransfer,
    SymbolicAmount,
)

if TYPE_CHECKING:
    import sqlite3
    from backend.models.schemas import IntentPlan, ResolvedPlan


# --------------------------------------------------------------------------- number words
# Re-implemented here (not imported from agent/stub) so the validator's literal
# check is its own code. The grammar of English number words is shared knowledge;
# the implementation is not. Kept to the demo vocabulary.
_ONES = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
    "seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "thirteen": 13, "fourteen": 14, "fifteen": 15, "sixteen": 16,
    "seventeen": 17, "eighteen": 18, "nineteen": 19,
}
_TENS = {
    "twenty": 20, "thirty": 30, "forty": 40, "fifty": 50,
    "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90,
}
_NUMBER_VOCAB = set(_ONES) | set(_TENS) | {"hundred", "thousand"}
# Units that follow a number run and fix its scale (cents vs dollars).
_DOLLAR_UNITS = {"dollar", "dollars", "bucks", "buck"}
_CENT_UNITS = {"cent", "cents"}
# Units that MULTIPLY the number before them: "5k", "two grand", "1.5k",
# "5 thousand". Spoken shorthand the parser (an LLM) reads without effort; the
# validator must read it too, or it freezes a correct plan.
_MULTIPLIERS = {"k": 1000, "grand": 1000, "thousand": 1000, "hundred": 100}


def _words_to_int(words: list[str]) -> int | None:
    """'five hundred' -> 500, 'two hundred fifty' -> 250, 'a hundred' -> 100,
    'fifty thousand' -> 50000. None if a token is not a number word."""
    total, current = 0, 0
    for w in words:
        if w in _ONES:
            current += _ONES[w]
        elif w in _TENS:
            current += _TENS[w]
        elif w in ("a", "an") and current == 0:
            current = 1
        elif w == "hundred":
            current = (current or 1) * 100
        elif w == "thousand":
            total += (current or 1) * 1000
            current = 0
        else:
            return None
    return total + current


# --------------------------------------------------------------------------- literal extraction
# Digit amounts: "$500", "500", "1,200", "50.25", "500 dollars", "50 cents".
# String composition only — NO float ever touches money (same rule as canonical.py).
# Digits followed by a multiplier: "5k", "$1.5k", "2 grand", "5 thousand".
# Matched FIRST, and its span is consumed, so "5 grand" is $5,000 and NOT also
# $5 — an extra reading would let a tampered $5 pass the amount check.
_DIGIT_MULTIPLIED = re.compile(r"\$?\s*(\d+)(?:\.(\d+))?\s*(k|grand|thousand|hundred)\b", re.I)


def _multiplied_to_cents(whole_str: str, frac: str | None, unit: str) -> int | None:
    """"1.5k" -> 150000c by integer arithmetic (no float touches money). None
    if it does not come out to a whole number of cents."""
    scale = _MULTIPLIERS[unit.lower()] * 100          # cents per unit
    cents = int(whole_str) * scale
    if frac:
        num = int(frac) * scale
        den = 10 ** len(frac)
        if num % den:
            return None
        cents += num // den
    return cents


_DIGIT_AMOUNT = re.compile(
    r"\$?\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(dollars?|bucks?|cents?)?\b",
    re.I,
)


def _digit_run_to_cents(whole_str: str, frac: str | None, unit: str | None) -> int:
    """"$500" / "500" -> 50000; "50.25" -> 5025; "50 cents" -> 50."""
    whole = int(whole_str.replace(",", ""))
    if unit and unit.lower() in _CENT_UNITS:
        return whole
    return whole * 100 + (int(frac.ljust(2, "0")) if frac else 0)


def extract_literal_cents(clause: str) -> set[int]:
    """Every amount (in cents) derivable from `clause` by rule.

    Returns a SET so the caller can ask "is the literal_cents among the amounts
    this clause actually contains?" — the clause-localized check (brief §4.1).
    A literal that is globally derivable (it appears in another clause) but not
    in THIS leg's clause is not in this set, and that is the cross-clause swap
    the global check admitted.
    """
    out: set[int] = set()

    # digits with a multiplier first; their spans are consumed (see above)
    consumed: list[tuple[int, int]] = []
    for m in _DIGIT_MULTIPLIED.finditer(clause):
        cents = _multiplied_to_cents(m.group(1), m.group(2), m.group(3))
        if cents is not None:
            out.add(cents)
        consumed.append(m.span())

    def _free(pos: int) -> bool:
        return not any(a <= pos < b for a, b in consumed)

    # digit amounts — every match, not just the first
    for m in _DIGIT_AMOUNT.finditer(clause):
        if _free(m.start(1)):
            out.add(_digit_run_to_cents(m.group(1), m.group(2), m.group(3)))

    # number-word runs — scan tokens; a run is a maximal sequence of number
    # words (optionally led by "a"/"an"), possibly followed by a dollar/cent unit.
    tokens = [t for t in re.finditer(r"[A-Za-z]+", clause) if _free(t.start())]
    word = lambda k: tokens[k].group(0).lower() if k < len(tokens) else ""
    i = 0
    while i < len(tokens):
        tok = word(i)
        is_run_start = tok in _NUMBER_VOCAB or (
            tok in ("a", "an") and word(i + 1) in ("hundred", "thousand", "grand")
        )
        if is_run_start:
            j = i
            run: list[str] = []
            while j < len(tokens):
                w = word(j)
                if w in _NUMBER_VOCAB or (w in ("a", "an") and j == i):
                    run.append(w)
                    j += 1
                elif (w == "and" and run and run[-1] in ("hundred", "thousand")
                      and (word(j + 1) in _ONES or word(j + 1) in _TENS)):
                    j += 1              # "a hundred AND fifty" -> 150
                else:
                    break
            value = _words_to_int(run)
            if value:
                unit = word(j)
                if unit in ("k", "grand"):            # "two grand", "fifty k"
                    cents = value * _MULTIPLIERS[unit] * 100
                    j += 1
                else:
                    cents = value if unit in _CENT_UNITS else value * 100
                out.add(cents)
            i = max(j, i + 1)
        else:
            i += 1
    return out


# --------------------------------------------------------------------------- symbolic recomputation
def _equity_price(conn: "sqlite3.Connection", ticker: str) -> int:
    row = conn.execute(
        "SELECT price FROM equities WHERE lower(ticker)=lower(?)", (ticker,)
    ).fetchone()
    return int(row["price"]) if row else 0


def recompute_symbolic(
    intent_plan: "IntentPlan",
    resolved_plan: "ResolvedPlan",
    conn: "sqlite3.Connection",
) -> dict[str, int]:
    """Independently recompute every leg's `amount_cents` from the ledger.

    Walks legs in plan order against a FRESH copy of the account balances:
      - literal leg      -> debit = the resolved spend (the resolver floored
                             equity to whole shares; the literal check elsewhere
                             verifies the spoken figure, not the arithmetic)
      - symbolic leg     -> read the referenced leg's OWN source-account balance
                             (after preceding debits), apply ALL/HALF, and for
                             equity floor to whole shares so the result is the
                             SPEND (shares × price), not the allocation.

    Returns {leg_id: independently_recomputed_amount_cents}. The caller compares
    symbolic legs' recomputed value to the resolved leg's `amount_cents`; literal
    legs are checked by `extract_literal_cents` + resolved-vs-literal consistency
    in the amount check, not by this map.

    This is a SEPARATE implementation from `backend.resolver._resolve_leg`: it
    reads the resolved plan's concrete `source_account` (a resolved fact, not the
    resolver's function) and re-derives the NUMBER. If it just called the
    resolver, a bug in the resolver would be invisible to the auditor.
    """
    resolved_by_id = {leg.id: leg for leg in resolved_plan.plan}

    # fresh ledger: copy the starting balances of every account this plan touches.
    acct_ids = {leg.source_account for leg in resolved_plan.plan}
    placeholders = ",".join("?" for _ in acct_ids) or "''"
    balances: dict[str, int] = {}
    if acct_ids:
        for r in conn.execute(
            f"SELECT id, balance FROM accounts WHERE id IN ({placeholders})",
            tuple(acct_ids),
        ).fetchall():
            balances[r["id"]] = int(r["balance"])

    recomputed: dict[str, int] = {}
    for ileg in intent_plan.plan:
        rleg = resolved_by_id.get(ileg.id)
        if rleg is None:                      # structural mismatch; caller freezes
            continue
        if isinstance(ileg.amount, SymbolicAmount):
            ref = resolved_by_id.get(ileg.amount.after_leg)
            ref_acct = ref.source_account if ref is not None else rleg.source_account
            balance_now = balances.get(ref_acct, 0)
            if ileg.amount.op == AmountOp.ALL:
                allocated = balance_now
            else:                            # HALF — integer division by design
                allocated = balance_now // 2
            if isinstance(rleg, ResolvedBuyEquity):
                price = _equity_price(conn, rleg.ticker)
                shares = allocated // price if price > 0 else 0
                debit = shares * price       # the SPEND, not the allocation
            else:
                debit = allocated
        else:
            # literal: the resolved amount_cents IS the debit (spend for equity).
            # The literal check verifies the spoken figure separately; here we
            # only carry the debit forward to keep the ledger walk honest.
            debit = rleg.amount_cents
        recomputed[ileg.id] = debit
        balances[rleg.source_account] = balances.get(rleg.source_account, 0) - debit
    return recomputed
