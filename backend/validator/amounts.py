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
from dataclasses import dataclass
from functools import lru_cache
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

# --------------------------------------------------------------------------- not money
# Every number used to count as money, so "pay mom five hundred to account
# 123-456" yielded {$500, $123, $456} and a draft paying $123 PASSED the amount
# check. These are numbers that are NOT amounts, blanked out (same length, so
# positions are unchanged) before anything is read.
#
# Deliberately NARROW: a mask that is too greedy is worse than none. Blanking
# "account five" in "…savings account five hundred" left "hundred" = $100 — a
# wrong amount the check would then accept. So an account reference is masked
# only when SHAPED like one (5+ digits, digit groups, 3+ spoken digits), never
# merely because a number follows the word "account".
_DIGIT_WORDS = r"(?:zero|oh|one|two|three|four|five|six|seven|eight|nine)"
_MONTHS = (r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|june?|july?|aug(?:ust)?"
           r"|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)")
# A mask must NEVER cut a spoken amount in half: nothing it blanks may be
# followed by a multiplier or money word. "for unit 5 hundred dollars" once
# lost "unit 5" and read the leftover "hundred" as $100 — a wrong amount the
# check would accept.
_KEEPS_AMOUNT = r"(?!\s*(?:hundred|thousand|k|grand|dollars?|bucks?|cents?|sgd)\b)"
_NOT_MONEY = re.compile(
    r"\b(?:account|acct|acc|a/c)\b(?:\s+(?:no\.?|number|num))?\s*[:#]?\s*"
    r"(?:\d{3,}(?:[\s-]+\d{3,})+|\d{5,}|(?:" + _DIGIT_WORDS + r"\b[\s-]*){3,})"
    + _KEEPS_AMOUNT +                                         # account 123 456 / 55512 / one two three
    r"|\b\d+(?:-\d+)+\b"                                      # 123-456: a reference, not a sum
    r"|(?<![$\d.,])\b\d{7,}\b(?!\s*(?:dollars?|bucks?|cents?|sgd)\b)"  # 7+ bare digits: account / phone
    # Only UNAMBIGUOUS labels. "for the bus 20", "ticket 20", "table 5" often
    # carry the fare itself, and masking a real amount freezes a correct payment.
    r"|\b(?:room|unit|apt|apartment|flat|block|blk|floor|level|suite|invoice|ref"
    r"|reference)\s*(?:no\.?|number|#)?"
    r"\s*\d+[a-z]?\b" + _KEEPS_AMOUNT +                          # room 204, unit 12: a label
    r"|#\s*\d+\b" + _KEEPS_AMOUNT +                              # #12
    r"|\b\d+(?:\.\d+)?\s*(?:shares?|pm|am|percent|times|days?|weeks?|months?|years?"
    r"|hours?|hrs?|minutes?|mins?|o'?clock)\b"                 # 10 shares, 3 pm, 5 days
    r"|\b\d+(?:\.\d+)?\s*%"                                    # 5%
    r"|\bon\s+(?:the\s+)?\d{1,2}(?:st|nd|rd|th)?\s+(?:of\s+)?" + _MONTHS + r"\b",  # on 25 sep
    re.I)
# The same units after a NUMBER-WORD run: "five pm", "ten shares".
_DETERMINERS = {"the", "that", "this", "which", "each", "every", "another", "any",
                "either", "neither", "no", "other"}
_NOT_MONEY_UNITS = {"shares", "share", "pm", "am", "percent", "times", "day", "days",
                    "week", "weeks", "month", "months", "year", "years", "hour",
                    "hours", "minute", "minutes", "oclock"}


def _mask_non_money(text: str) -> str:
    return _NOT_MONEY.sub(lambda m: " " * len(m.group(0)), text)


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
# String composition only — NO float ever touches money (same rule as canonical.py).
# "50 dollars and 25 cents" is ONE amount ($50.25), not $50 and $0.25.
_DOLLARS_AND_CENTS = re.compile(
    r"\$?\s*(\d+)\s*(?:dollars?|bucks?)\s+and\s+(\d{1,2})\s*cents?\b", re.I)
# Digits followed by a multiplier: "5k", "$1.5k", "2 grand", "5 thousand".
# Matched FIRST, and its span is consumed, so "5 grand" is $5,000 and NOT also
# $5 — an extra reading would let a tampered $5 pass the amount check.
_DIGIT_MULTIPLIED = re.compile(r"\$?\s*(\d+)(?:\.(\d+))?\s*(k|grand|thousand|hundred)\b", re.I)
# Digit amounts: "$500", "500", "1,200", "50.25", "500 dollars", "50 cents".
_DIGIT_AMOUNT = re.compile(
    r"\$?\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(dollars?|bucks?|cents?)?\b",
    re.I,
)
_CURRENCY_BEFORE = re.compile(r"(?:\$|\bsgd|\bs\$|\busd)\s*$", re.I)


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


def _digit_run_to_cents(whole_str: str, frac: str | None, unit: str | None) -> int:
    """"$500" / "500" -> 50000; "50.25" -> 5025; "50 cents" -> 50."""
    whole = int(whole_str.replace(",", ""))
    if unit and unit.lower() in _CENT_UNITS:
        return whole
    return whole * 100 + (int(frac.ljust(2, "0")) if frac else 0)


@dataclass(frozen=True)
class Amount:
    """One amount read from a clause, and where. `marked` = a money word or
    symbol is attached ("$50", "50 dollars", "5k", "SGD 50"); `unit` is
    "dollars" / "cents" / "" (bare)."""
    cents: int
    start: int
    end: int
    marked: bool
    unit: str = ""


def extract_amounts(clause: str) -> list[Amount]:
    """Every amount in `clause`, in order, with its span. Positions refer to
    `clause` itself: masking preserves length."""
    return list(_scan(clause)[1])


def _unit_of(word: str | None) -> str:
    w = (word or "").lower()
    return "cents" if w in _CENT_UNITS else "dollars" if w in _DOLLAR_UNITS else ""


@lru_cache(maxsize=512)
def _scan(clause: str) -> tuple[str, tuple[Amount, ...]]:
    """(masked text, amounts) — one masking pass shared by every reader, and
    cached: the resolver and the validator read the same clauses per draft."""
    text = _mask_non_money(clause)
    found: list[Amount] = []
    lone_ones: list[Amount] = []
    consumed: list[tuple[int, int]] = []

    def _free(pos: int) -> bool:
        return not any(a <= pos < b for a, b in consumed)

    def _marked_before(pos: int) -> bool:
        return bool(_CURRENCY_BEFORE.search(text[:pos]))

    for m in _DOLLARS_AND_CENTS.finditer(text):
        found.append(Amount(int(m.group(1)) * 100 + int(m.group(2)), m.start(1), m.end(),
                            True, "dollars"))
        consumed.append(m.span())

    for m in _DIGIT_MULTIPLIED.finditer(text):
        if not _free(m.start(1)):
            continue
        cents = _multiplied_to_cents(m.group(1), m.group(2), m.group(3))
        if cents is not None:
            found.append(Amount(cents, m.start(1), m.end(), True, "dollars"))
        consumed.append(m.span())

    for m in _DIGIT_AMOUNT.finditer(text):
        if not _free(m.start(1)):
            continue
        marked = m.group(0).lstrip().startswith("$") or bool(m.group(3)) or _marked_before(m.start(1))
        found.append(Amount(_digit_run_to_cents(m.group(1), m.group(2), m.group(3)),
                            m.start(1), m.end(), marked, _unit_of(m.group(3))))

    # number-word runs — a maximal sequence of number words (optionally led by
    # "a"/"an"), possibly followed by a unit.
    tokens = [t for t in re.finditer(r"[A-Za-z]+", text) if _free(t.start())]
    word = lambda k: tokens[k].group(0).lower() if k < len(tokens) else ""
    i = 0
    while i < len(tokens):
        tok = word(i)
        is_run_start = tok in _NUMBER_VOCAB or (
            tok in ("a", "an") and word(i + 1) in ("hundred", "thousand", "grand")
        )
        if not is_run_start:
            i += 1
            continue
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
        unit = word(j)
        if value and unit in _NOT_MONEY_UNITS:
            value = None                          # "five pm", "ten shares"
        # A lone "one" is a PRONOUN only after a determiner ("the blue one",
        # "that one gets 50", "each one") and with no money word or connector
        # after it. "and john one", "and one to mom" are $1. (If nothing else in
        # the clause is an amount, even the pronoun reading yields $1 — below.)
        before = [t.group(0).lower() for t in tokens[max(0, i - 2):i]]
        lone_one = (run == ["one"]
                    and unit not in _DOLLAR_UNITS | _CENT_UNITS | {"k", "grand"}
                    and unit not in _CONNECTORS
                    and any(w in _DETERMINERS for w in before))
        if value:
            last = tokens[j - 1]
            marked = unit in _DOLLAR_UNITS | _CENT_UNITS | {"k", "grand"}
            if unit in ("k", "grand"):            # "two grand", "fifty k"
                cents = value * _MULTIPLIERS[unit] * 100
                last = tokens[j]
                j += 1
            else:
                cents = value if unit in _CENT_UNITS else value * 100
                if unit in _DOLLAR_UNITS | _CENT_UNITS:
                    last = tokens[j]
            amt = Amount(cents, tokens[i].start(), last.end(),
                         marked or _marked_before(tokens[i].start()),
                         _unit_of(unit) if unit in _DOLLAR_UNITS | _CENT_UNITS
                         else ("dollars" if marked else ""))
            (lone_ones if lone_one else found).append(amt)
        i = max(j, i + 1)

    # "the blue one", "that one": a lone "one" is a PRONOUN when anything else
    # in the clause is the amount — and $1 when nothing else is ("send john one").
    if not found:
        found.extend(lone_ones)
    return text, tuple(_merge_dollars_and_cents(text, sorted(found, key=lambda a: a.start)))


def _merge_dollars_and_cents(text: str, found: list[Amount]) -> list[Amount]:
    """"fifty dollars and twenty five cents" / "50 dollars 25 cents" is ONE
    amount, $50.25 — not a $50 and a $0.25 that could never be paid together."""
    out: list[Amount] = []
    for a in found:
        prev = out[-1] if out else None
        if (prev is not None and prev.unit == "dollars" and a.unit == "cents" and a.cents < 100
                and re.fullmatch(r"[\s,]*(?:and)?[\s,]*", text[prev.end:a.start], re.I)):
            out[-1] = Amount(prev.cents + a.cents, prev.start, a.end, True, "dollars")
        else:
            out.append(a)
    return out


def extract_literal_cents(clause: str) -> set[int]:
    """Every amount (in cents) derivable from `clause` by rule.

    Returns a SET so the caller can ask "is the literal_cents among the amounts
    this clause actually contains?" — the clause-localized check (brief §4.1).
    A literal that is globally derivable (it appears in another clause) but not
    in THIS leg's clause is not in this set, and that is the cross-clause swap
    the global check admitted.
    """
    return {a.cents for a in extract_amounts(clause)}


# --------------------------------------------------------------------------- rival amounts
# Only for deciding whether to ASK "$50 or $500?" — never for derivability,
# which stays inclusive. A number the user said is a RIVAL to the paid amount
# only if it reads as money: marked as money, ending the clause, followed by a
# connector ("50 to mom", "500 not 50"), or following a correction ("no, 500").
# A number followed by a noun is a quantity: "2 tickets", "10 apple shares".
_CONNECTORS = {"to", "from", "for", "and", "then", "or", "not", "no", "into", "via",
               "please", "now", "today", "tomorrow", "tonight", "later", "instead",
               "only", "each", "back", "sorry", "actually", "wait", "ok", "okay", "i",
               "out", "right", "asap", "thanks", "at", "on", "by", "with", "because",
               "since", "as", "so", "but", "uh", "um", "hmm", "er", "erm", "like", "well"}
_CORRECTIONS = {"no", "not", "actually", "sorry", "wait", "mean", "instead", "rather",
                "make", "uh", "um", "hmm", "oops"}
# A correction: a correction word followed, within two words, by an amount
# ("no wait 500", "actually make it 500", "sorry, 500"). Then EVERY amount in
# the clause is a candidate, whatever sits in between ("50 because I owe her,
# no wait 500"). "no rush", "actually fine" are not corrections: no amount follows.
_CORRECTION_WORD = re.compile(
    r"\b(?:no|not|actually|sorry|wait|i mean|make it|instead|rather|oops"
    r"|scratch that|change (?:it|that)(?: to)?)\b", re.I)
_GAP_TO_AMOUNT = re.compile(r"[\s,.!]*(?:[A-Za-z']+[\s,.!]+){0,2}$")


def _reads_as_money(text: str, a: Amount) -> bool:
    if a.marked:
        return True
    after = re.match(r"[\s,.!?]*([A-Za-z]+|\d)", text[a.end:])
    if after is None or after.group(1).lower() in _CONNECTORS:
        return True
    before = re.search(r"([A-Za-z]+)[\s,]*$", text[:a.start])
    return bool(before) and before.group(1).lower() in _CORRECTIONS


def money_occurrences(clause: str) -> list[int]:
    """Each amount SAID in `clause` that reads as money, repeats included — the
    candidates when the user may have said more than one ("50 no wait 500";
    "mom 20 and john 20, wait, 30"). Repeats count: saying 20 twice and then
    30 is three figures for two payments."""
    text, found = _scan(clause)
    if any(_GAP_TO_AMOUNT.match(text[m.end():a.start])
           for m in _CORRECTION_WORD.finditer(text) for a in found if a.start >= m.end()):
        return [a.cents for a in found]
    return [a.cents for a in found if _reads_as_money(text, a)]



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
