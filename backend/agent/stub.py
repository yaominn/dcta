"""
StubProvider — the offline stand-in for the LLM.  # MOCK

Used whenever settings.has_credentials is False (local dev, CI, and the
deployed demo before keys are wired). It sits BEHIND the same provider
interface as HunyuanProvider and returns JSON *text* exactly like a chat
model would, so the parser's generate -> validate -> retry loop is exercised
identically in both modes. Swapping stub -> live is one config change
(brief Section 8: provider interface), never a code change.

This is a deterministic rule engine, NOT a model, and it is deliberately
modest: it recognises the seeded demo vocabulary (payee nicknames, biller
names, tickers, account types — read out of the same sanitized context the
real model would receive), dollar amounts in digits or number words, and
"the rest"/"half of it" as symbolic amounts. Anything it cannot map goes to
`unresolved` rather than being guessed (brief 4.4) — the same contract the
system prompt imposes on the real model.
"""
from __future__ import annotations

import json
import re

from backend.agent import prompts
from backend.resolver import ACCOUNT_TYPE_SYNONYMS


class StubProvider:
    name = "stub"

    # ------------------------------------------------------------------ interface
    def complete(self, *, system: str, user: str) -> str:
        transcript = _extract_transcript(user)
        context = _extract_context(user)
        if system == prompts.contact_system_prompt():
            return json.dumps(_rules_contact_edit(transcript, context))
        plan = _rules_plan(transcript, context)
        return json.dumps(plan)


# --------------------------------------------------------------------------- prompt read-back
def _extract_transcript(user_prompt: str) -> str:
    """Lift the verbatim transcript out of the prompt (a real model just reads
    it; the stub needs it as a string)."""
    after = user_prompt.split(prompts.TRANSCRIPT_MARKER, 1)[1]
    for footer in (prompts.OUTPUT_FOOTER, prompts.CONTACT_OUTPUT_FOOTER):
        after = after.split(footer, 1)[0]
    return after.strip()


def _extract_context(user_prompt: str) -> dict:
    """Parse the sanitized context JSON back out of the prompt. The stub reads
    the SAME opaque view the real model would — never the raw rows."""
    try:
        after = user_prompt.split(prompts.CONTEXT_HEADER, 1)[1]
        blob = after.split("\n\n" + prompts.TRANSCRIPT_MARKER, 1)[0]
        return json.loads(blob)
    except (IndexError, json.JSONDecodeError):
        return {"payees": [], "billers": [], "account_types": [], "equities": []}


# --------------------------------------------------------------------------- number words
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


def _words_to_int(words: list[str]) -> int | None:
    """'five hundred' -> 500, 'two hundred fifty' -> 250, 'a hundred' -> 100."""
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


# --------------------------------------------------------------------------- amount extraction
_SYMBOLIC = [
    # (pattern, op) — "the rest" needs an earlier leg; handled in _rules_plan
    (re.compile(r"\b(the rest|whatever(?: is|'?s) left|the remainder|everything(?: else| left)?|all of it)\b"), "ALL"),
    (re.compile(r"\bhalf\b"), "HALF"),
]
_DIGIT_AMOUNT = re.compile(
    r"\$?\s*(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d{1,2}))?\s*(dollars?|bucks|cents?)?\b"
)


def _digit_to_cents(m: re.Match) -> int:
    """String composition only — NO float ever touches money (L2).
    "$500" / "500" / "500 dollars" -> 50000; "50.25" -> 5025; "50 cents" -> 50."""
    whole = int(m.group(1).replace(",", ""))
    frac = m.group(2)
    unit = m.group(3)
    if unit in ("cent", "cents"):
        return whole
    return whole * 100 + (int(frac.ljust(2, "0")) if frac else 0)


def _extract_amount(clause: str) -> tuple[dict | None, str]:
    """Find the amount in a clause. Returns (amount_dict|None, clause_with_span_removed).
    A symbolic amount is returned as {"after_leg": None, "op": ...} — the caller
    fills in the previous leg id (or routes to unresolved if there is none)."""
    for pat, op in _SYMBOLIC:
        m = pat.search(clause)
        if m:
            return {"after_leg": None, "op": op}, (clause[:m.start()] + clause[m.end():])

    m = _DIGIT_AMOUNT.search(clause)
    if m:
        return {"literal_cents": _digit_to_cents(m)}, (clause[:m.start()] + clause[m.end():])

    # number words — token scan over the ORIGINAL clause (offsets kept) so the
    # span removal preserves the casing the mention extraction relies on.
    words = list(re.finditer(r"[A-Za-z]+", clause))
    i = 0
    while i < len(words):
        tok = words[i].group(0).lower()
        is_run_start = tok in _NUMBER_VOCAB or (
            tok in ("a", "an") and i + 1 < len(words)
            and words[i + 1].group(0).lower() in ("hundred", "thousand")
        )
        if is_run_start:
            j = i
            run: list[str] = []
            while j < len(words):
                w = words[j].group(0).lower()
                if w in _NUMBER_VOCAB or (w in ("a", "an") and j == i):
                    run.append(w)
                    j += 1
                else:
                    break
            value = _words_to_int(run)
            if value:
                unit = words[j].group(0).lower() if j < len(words) else ""
                end = j + 1 if unit in ("dollar", "dollars", "bucks", "cent", "cents") else j
                cents = value if unit in ("cent", "cents") else value * 100
                span = (words[i].start(), words[end - 1].end())
                return {"literal_cents": cents}, clause[:span[0]] + " " + clause[span[1]:]
            i = max(j, i + 1)
        else:
            i += 1
    return None, clause


# --------------------------------------------------------------------------- mention extraction
def _find_mention(clause: str, candidates: list[str]) -> str | None:
    """Longest candidate appearing as a word phrase in the clause (case-insensitive),
    returned in the USER'S original casing (a mention is the user's words)."""
    best: tuple[int, re.Match] | None = None
    for cand in candidates:
        m = re.search(r"\b" + re.escape(cand) + r"\b", clause, re.I)
        if m and (best is None or len(cand) > best[0]):
            best = (len(cand), m)
    return best[1].group(0) if best else None


def _find_source_account(clause: str, account_types: list[str]) -> str:
    m = re.search(r"\b(?:from|out of)\s+([a-z ]+?)(?:\s+to\b|\s*$)", clause, re.I)
    if m:
        words = m.group(1).strip()
        for t in account_types:
            if re.search(r"\b" + re.escape(t) + r"\b", words, re.I):
                return t
        # The user NAMED an account by a word the context has no type for ("my
        # spending account", "from invest"): pass their words through, as the
        # real model does (prompt rule 5: "the account the user named"), and
        # let the resolver map it. The words come FROM the resolver's own map,
        # so the two cannot drift. A bare "my account" names nothing and still
        # means the default.
        if any(re.search(r"\b" + re.escape(w) + r"\b", words, re.I)
               for w in ACCOUNT_TYPE_SYNONYMS):
            return words
    for t in account_types:  # "savings account", "my joint"
        if re.search(r"\b" + re.escape(t) + r"\b", clause, re.I):
            return t
    return "default"


# --------------------------------------------------------------------------- the rule engine
def _rules_plan(transcript: str, context: dict) -> dict:
    clauses = [c.strip() for c in re.split(r"\bthen\b", transcript, flags=re.I) if c.strip()]
    nicknames = [p["nickname"] for p in context.get("payees", [])]
    biller_names = [b["name"] for b in context.get("billers", [])]
    tickers = context.get("equities", [])
    account_types = context.get("account_types", [])

    legs: list[dict] = []
    unresolved: list[str] = []

    for clause in clauses:
        amount, rest = _extract_amount(clause)
        source = _find_source_account(rest, account_types)
        leg_id = f"t{len(legs) + 1}"

        # classify + find the target mention
        biller = _find_mention(rest, biller_names)
        ticker = _find_mention(rest, tickers)
        payee = _find_mention(rest, nicknames)

        if biller or re.search(r"\bbill\b", rest, re.I):
            kind, target = "PAY_BILL", biller
        elif ticker or re.search(r"\b(buy|stock|shares?|equity)\b", rest, re.I):
            kind, target = "BUY_EQUITY", ticker
            if target is None:
                m = re.search(r"\bbuy\s+([a-z]+)", rest, re.I)
                target = m.group(1) if m else None
        elif payee or re.search(r"\b(pay|send|transfer|give)\b", rest, re.I):
            kind, target = "TRANSFER", payee
            if target is None:  # user named someone/something unknown -> resolver clarifies (4.4)
                m = re.search(r"\bto\s+([\w\- ]+)$", rest.strip(), re.I)
                target = m.group(1).strip() if m else None
        else:
            unresolved.append(f"could not understand: {clause!r}")
            continue

        if target is None:
            unresolved.append(f"target for: {clause!r}")
            continue
        if amount is None:
            unresolved.append(f"amount for: {clause!r}")
            continue

        if amount.get("after_leg") is None and "op" in amount:
            if not legs:  # "the rest" with no earlier leg to reference
                unresolved.append(f"'{clause.strip()}' needs an earlier leg")
                continue
            amount = {"after_leg": legs[-1]["id"], "op": amount["op"]}

        leg = {
            "id": leg_id,
            "type": kind,
            "source_account": {"mention": source},
            "amount": amount,
        }
        if kind == "BUY_EQUITY":
            leg["ticker"] = {"mention": target}
        else:
            leg["target"] = {"mention": target}
        legs.append(leg)

    if not legs and not unresolved:
        unresolved.append(f"could not understand: {transcript!r}")
    return {"plan": legs, "unresolved": unresolved}


# --------------------------------------------------------------------------- contact edits
# "rename John to Johnny", "change mom's number to 9123 4567",
# "update the phone number for landlord to +65 6123 0000". The new value is
# copied VERBATIM: normalising or validating a phone number is the resolver's
# job (deterministic code), not the parser's.
_C_FIELD = r"(?P<field>nick\s?name|name|phone(?:\s+number)?|mobile(?:\s+number)?|number|contact\s+number|handphone)"
_C_VERB = r"(?:please\s+)?(?:change|update|set|edit|correct|fix|make)"
_C_PATTERNS = [
    # rename <who> to/as <value>
    (re.compile(r"^(?:please\s+)?rename\s+(?P<who>.+?)\s+(?:to|as)\s+(?P<val>.+)$", re.I), "nickname"),
    # change <who>'s <field> to <value>
    (re.compile(_C_VERB + r"\s+(?:the\s+)?(?P<who>.+?)(?:'s|\u2019s|s')\s+" + _C_FIELD
                + r"\s+(?:to|as|into)\s+(?P<val>.+)$", re.I), None),
    # change the <field> of/for <who> to <value>
    (re.compile(_C_VERB + r"\s+(?:the\s+)?" + _C_FIELD + r"\s+(?:of|for)\s+(?P<who>.+?)"
                + r"\s+(?:to|as|into)\s+(?P<val>.+)$", re.I), None),
]


def _rules_contact_edit(transcript: str, context: dict) -> dict:
    nicknames = [p["nickname"] for p in context.get("payees", [])]
    edits: list[dict] = []
    unresolved: list[str] = []
    for clause in re.split(r"\bthen\b|;", transcript, flags=re.I):
        clause = clause.strip().rstrip(".!?").strip()
        if not clause:
            continue
        for pat, fixed_field in _C_PATTERNS:
            m = pat.search(clause)
            if not m:
                continue
            field_word = fixed_field or m.group("field").lower()
            field = "nickname" if "name" in field_word and "number" not in field_word else "phone"
            who = m.group("who").strip()
            who = _find_mention(who, nicknames) or who     # the user's words, never an id
            val = m.group("val").strip().strip("\"'\u201c\u201d")
            edits.append({"target": {"mention": who}, "field": field, "new_value": val[:64]})
            break
        else:
            unresolved.append(f"could not tell what to change in: {clause!r}")
    return {"edits": edits, "unresolved": unresolved}
