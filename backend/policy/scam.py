"""
Scam signals, two thresholds, and what they make the user do.

In the scams DBS worries about most, the REAL customer signs the payment while
being manipulated — "Mum, this is my new number", the "officer" who needs your
savings moved to a safe account. Passkeys, signatures and nonces do not help
there: the person approving IS the account holder. What helps is noticing the
pattern and slowing them down. So, before a draft can be signed
(docs/SCAM_DECISION_FLOW.md):

  ALWAYS      a NEVER RULE in the user's words (a safe account, an OTP, "for an
              investigation"...) -> BLOCK: nothing to sign, call the bank
  THRESHOLD 1 the FACTS score: amount, payee, time, account changes and earlier
              attempts (WEIGHTS; the amount facts together at most AMOUNT_MAX)
                facts < 3         PASS: sign as normal (a warning if there's one)
                facts 3-9.9       ASK what it's for (questions picked by the
                                  highest-scoring fact), then threshold 2
                facts 10+         BLOCK
  THRESHOLD 2 the WORDS score: the request and the answers, in 10 categories
              (word_score(), 0-8)
                words < 2, facts < 7      PASS
                words 2-5.9, or facts 7+  FAIL: DELAY (sign, then a wait before
                                          the money moves; can cancel), or
                                          HOLD_STEP_UP (+ a server hold, a phone
                                          code and typing the name) when words
                                          4+ or facts 7+
                words 6+                  BLOCK

Below threshold 1 the words add nothing (a warning sentence can still show).
HOLD_STEP_UP's phone code and typed name are both checked by the gateway,
not only the page.

DETERMINISTIC, NOT THE MODEL. Every signal here is a rule over the ledger and
the raw transcript. The scam-wording rules (new_contact.py's list, shared with
the add-a-contact flow) run on the transcript itself, outside the model: if the
model decided these flags, a prompt injection could switch them off. A signal
can only RAISE the score — nothing here approves anything or removes a
safeguard.

Every warning and question is a FIXED sentence written here (the card only
renders trusted text), chosen for what the signals point to.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from backend.data import destinations as _destinations
from backend.data.db import DB_PATH, connect
from backend.display import account_label, cents_to_display
from backend.policy.new_contact import Warning as _ContactWarning
from backend.policy.new_contact import scam_words as _contact_scam_words

WEIGHTS = {
    # threshold 1: the facts
    "FIRST_PAYMENT_TO_DESTINATION": 2,
    "RECENT_DESTINATION_CHANGE": 5,   # a changed number; a newly added contact: 3
    "LARGE_FIRST_PAYMENT": 3,         # amount
    "BALANCE_DRAIN": 3,               # amount
    "LARGE_SHARE": 2,                 # amount
    "LARGE_AMOUNT": 2,                # amount
    "ABOVE_USUAL_MAX": 2,             # amount
    "ABOVE_PAYEE_MAX": 2,             # amount
    "RAPID_MULTI_DESTINATION": 4,
    "RECENT_CREDENTIAL_CHANGE": 4,
    "FREEZE_TURNED_OFF": 4,
    "UNUSUAL_HOUR": 1,
    "DORMANT_ACCOUNT_WAKE": 2,
    "RETRY_AFTER_STOPPED": 3,         # earlier attempts (policy/attempts.py)
    "SMALLER_AFTER_STOPPED": 3,
    "REPEATED_STOPPED_ATTEMPTS": 3,   # 2 for two stopped attempts, 3 for more
    "SPLIT_PAYMENTS": 3,
    "ESCALATING_AMOUNTS": 2,
    "WARNINGS_IGNORED": 2,
    # threshold 2: the words
    "SOCIAL_ENGINEERING_LANGUAGE": 8,   # the most the words can add (WORDS_MAX)
}
AMOUNT_CODES = frozenset({"LARGE_FIRST_PAYMENT", "BALANCE_DRAIN", "LARGE_SHARE", "LARGE_AMOUNT",
                          "ABOVE_USUAL_MAX", "ABOVE_PAYEE_MAX"})
AMOUNT_MAX = 5                       # the amount facts together
WORDS_CODE = "SOCIAL_ENGINEERING_LANGUAGE"

LARGE_FIRST_CENTS = 100_000          # $1,000
DRAIN_PERCENT = 80
LARGE_SHARE_PERCENT = 50             # of the source account's balance
LARGE_AMOUNT_CENTS = 500_000         # $5,000, the default daily transfer limit
USUAL_MAX_FACTOR = 3                 # x the largest transfer in USUAL_WINDOW_S
USUAL_WINDOW_S = 90 * 86400
PAYEE_MAX_FACTOR = 3                 # x the most ever sent to this payee
RAPID_WINDOW_S = 30 * 60
RAPID_COUNT = 3
NEW_CONTACT_POINTS = 3               # RECENT_DESTINATION_CHANGE for a contact just added
FREEZE_RECENT_S = 24 * 3600
DORMANT_S = 90 * 86400
ATTEMPT_WINDOW_S = 24 * 3600         # retries, smaller amounts, repeated stops, splits
WEEK_S = 7 * 86400                   # escalating amounts, warnings ignored
SPLIT_TOTAL_CENTS = 100_000          # $1,000
SGT_OFFSET_S = 8 * 3600              # Singapore time, for UNUSUAL_HOUR

# The two thresholds (docs/SCAM_DECISION_FLOW.md).
FACTS_ASK_FROM = 3.0
FACTS_FAIL_FROM = 7.0                # fail even when the words pass
FACTS_CALL_BANK_FROM = 10.0
WORDS_FAIL_FROM = 2.0
WORDS_SERIOUS_FROM = 4.0             # a fail that also needs the phone code
WORDS_CALL_BANK_FROM = 6.0
RELEASE_DELAY_SECONDS = 60           # the wait after signing on a fail; 0: none

ALLOW, WARN, DELAY, HOLD, HOLD_STEP_UP, BLOCK = (
    "ALLOW", "WARN", "DELAY", "HOLD", "HOLD_STEP_UP", "BLOCK")
PASS, FAIL, CALL_BANK = "PASS", "FAIL", "CALL_BANK"
# HOLD (a server hold alone) is no longer chosen; kept so a draft from before
# still orders correctly.
_RANK = {ALLOW: 0, WARN: 1, DELAY: 2, HOLD: 3, HOLD_STEP_UP: 4, BLOCK: 5}


def stricter(a: str | None, b: str) -> str:
    """The stricter of two outcomes (None counts as ALLOW)."""
    return a if a is not None and _RANK[a] > _RANK[b] else b


def needs_hold(outcome: str | None) -> bool:
    return outcome in (HOLD, HOLD_STEP_UP)


def release_delay(outcome: str | None) -> int:
    """Seconds a signed payment waits before it runs: RELEASE_DELAY_SECONDS on a
    threshold-2 fail, else 0."""
    return RELEASE_DELAY_SECONDS if outcome in (DELAY, HOLD, HOLD_STEP_UP) else 0


def rose_past_drafted(drafted: str | None, fresh: str) -> bool:
    """True when the score NOW demands a hold, a phone code or a block that the
    draft, as the user saw it, never arranged (a passkey added since, more new
    payees paid since). The payment is refused — the user cancels and asks
    again, and the new draft shows the new safeguards — rather than run past
    friction the user never saw. (A new DELAY is simply applied at the
    gateway.) `drafted` None (never assessed): nothing to compare."""
    return (drafted is not None and (needs_hold(fresh) or fresh == BLOCK)
            and _RANK[fresh] > _RANK.get(drafted, 0))


# JavaScript's String.trim(): whitespace, and the byte-order mark that
# Python's str.strip() leaves in place.
_TRIM = re.compile(r"^[\s\ufeff]+|[\s\ufeff]+$")


def name_confirmed(typed: str | None, expected: str) -> bool:
    """HOLD_STEP_UP's type-the-payee's-name check, as the gateway enforces it.
    The same comparison as the card's (buildNameCheck in frontend/app.js) —
    trimmed, case-insensitive — so a name the card accepts is never refused."""
    return _TRIM.sub("", typed or "").lower() == expected.lower()


def asks_unasked(fresh, asked: bool) -> bool:
    """The score NOW reaches threshold 1, but the user was never asked (a fact
    appeared after drafting, e.g. a new passkey): refused like a rise, so the
    new draft asks."""
    return ASK_QUESTIONS and fresh.asks and not asked


def points_by_code(signals) -> dict[str, float]:
    """(code, weight) pairs -> the points each rule adds. Each code counts
    once, however many legs raised it (at its highest weight)."""
    by_code: dict[str, float] = {}
    for code, weight in signals:
        by_code[code] = max(by_code.get(code, 0), weight)
    return by_code


def facts_points(signals) -> float:
    """Threshold 1: every fact once, the amount facts together at most AMOUNT_MAX."""
    by = points_by_code(signals)
    amount = sum(p for c, p in by.items() if c in AMOUNT_CODES)
    other = sum(p for c, p in by.items() if c not in AMOUNT_CODES and c != WORDS_CODE)
    return other + min(AMOUNT_MAX, amount)


def decide(facts: float, words: float, never_rules) -> tuple[str, str]:
    """(decision, outcome) from the two thresholds."""
    if never_rules or facts >= FACTS_CALL_BANK_FROM:
        return CALL_BANK, BLOCK
    if facts < FACTS_ASK_FROM:
        return PASS, ALLOW
    if words >= WORDS_CALL_BANK_FROM:
        return CALL_BANK, BLOCK
    if words >= WORDS_FAIL_FROM or facts >= FACTS_FAIL_FROM:
        serious = words >= WORDS_SERIOUS_FROM or facts >= FACTS_FAIL_FROM
        return FAIL, HOLD_STEP_UP if serious else DELAY
    return PASS, ALLOW


# What each rule looks for, in the words the browser console prints.
_RULE_TEXT = {
    "FIRST_PAYMENT_TO_DESTINATION": "first payment to this person or number",
    "RECENT_DESTINATION_CHANGE": "number changed (5) or contact added (3) < {recent} h ago",
    "LARGE_FIRST_PAYMENT": f"first payment of ${LARGE_FIRST_CENTS // 100:,} or more",
    "BALANCE_DRAIN": f"sends {DRAIN_PERCENT}%+ of an account's balance",
    "LARGE_SHARE": f"sends {LARGE_SHARE_PERCENT}-{DRAIN_PERCENT - 1}% of an account's balance",
    "LARGE_AMOUNT": f"${LARGE_AMOUNT_CENTS // 100:,} or more",
    "ABOVE_USUAL_MAX": f"over {USUAL_MAX_FACTOR}x the largest transfer in 90 days",
    "ABOVE_PAYEE_MAX": f"over {PAYEE_MAX_FACTOR}x the most ever sent to this payee",
    "RAPID_MULTI_DESTINATION": f"{RAPID_COUNT}+ new people paid within {RAPID_WINDOW_S // 60} min",
    "RECENT_CREDENTIAL_CHANGE": "another passkey added < {cooling} h ago",
    "FREEZE_TURNED_OFF": "the freeze turned off < 24 h ago",
    "UNUSUAL_HOUR": "between midnight and 5am Singapore time",
    "DORMANT_ACCOUNT_WAKE": "no transfers for 90+ days, then someone new",
    "RETRY_AFTER_STOPPED": "a payment to this payee was stopped < 24 h ago",
    "SMALLER_AFTER_STOPPED": "less than a payment to this payee stopped < 24 h ago",
    "REPEATED_STOPPED_ATTEMPTS": "2+ stopped payment attempts < 24 h ago",
    "SPLIT_PAYMENTS": f"payments to a new payee < 24 h adding up to ${SPLIT_TOTAL_CENTS // 100:,}+",
    "ESCALATING_AMOUNTS": "3+ payments to one payee in 7 days, each bigger",
    "WARNINGS_IGNORED": "2+ warned payments sent in 7 days",
    "SOCIAL_ENGINEERING_LANGUAGE": "the user's words in 10 scam categories, strongest first "
                                   "at 100%, 80%, 64%... (at most 8); weighed from facts 3",
}


def breakdown(signals: list[dict], *, recent_change_hours: int = 24,
              cooling_hours: int = 12) -> list[dict]:
    """Every rule, the points it gave and why: the score itemised for the
    browser console (CONSOLE_DEBUG). `signals` as to_dict() lists them. With
    the amount cap, an extra row takes off what's over AMOUNT_MAX, so the
    points always sum to the score."""
    given = points_by_code((s["code"], s["weight"]) for s in signals)
    rows = [{"rule": code, "points": given.get(code, 0), "worth": WEIGHTS[code],
             "looks_for": text.format(recent=recent_change_hours, cooling=cooling_hours),
             "why": [s["detail"] for s in signals if s["code"] == code]}
            for code, text in _RULE_TEXT.items()]
    over = sum(given.get(c, 0) for c in AMOUNT_CODES) - AMOUNT_MAX
    if over > 0:
        rows.append({"rule": "AMOUNT_CAP", "points": -over, "worth": AMOUNT_MAX,
                     "looks_for": f"the amount facts count {AMOUNT_MAX} at most", "why": []})
    return rows


# --------------------------------------------------------------------------- the phrase rules
# ONE phrase list for the whole app: policy/new_contact.py's, graded info /
# strong / refuse. Here:
#   refuse-grade (a safe account, an official telling you to pay)  weight 4
#   strong (secrecy, "new number", guaranteed returns, pay-to-earn) weight 2
#   info (urgency, parcel/refund)                                   weight 0 —
#     common in ordinary requests ("pay mom 50 now"), so advisory only.
# Two rules are re-stated for PAYMENTS, because a payment request is not a
# contact form and here a refuse-grade phrase alone holds the payment:
#   official orders — an official, an instruction verb AND a money verb
#     ("the officer said I must pay", "police told me to transfer"), but not
#     "she asked me to book the court" or "Mas told me to pay him back";
#   pay-to-earn — the job scam's words, not a bare "commission" (an agent's
#     commission is a routine payment).
# Plus one rule new_contact.py doesn't need: text aimed at the app itself.
_PAYMENT_RESTATED = {"words_official_orders", "words_job_task"}
_OFFICIAL = (r"(?:police|(?<!my )officer|polis|MAS\s+(?:officer|staff|official)|monetary authority"
             r"|CPF\s+(?:board|officer|staff)|IRAS|ICA\s+(?:officer|staff)|interpol|government"
             r"|ministry|bank\s+(?:staff|officer)|investigator|inspector|caller)")
_OFFICIAL_ORDERS = re.compile(
    rf"\b{_OFFICIAL}\b[^.?!]{{0,50}}\b(?:said|says|told|asked|instructed|ordered|wants?|needs?)\b"
    rf"[^.?!]{{0,50}}\b(?:pay|transfer|send|move|withdraw)\b"
    rf"|\b(?:told|asked|instructed|ordered)\s+(?:me|us)\s+to\s+(?:pay|transfer|send|move)\b"
    rf"[^.?!]{{0,60}}\b{_OFFICIAL}\b", re.I)
_JOB_TASK = re.compile(
    r"\bpart[- ]time\s+job\b|\btask\s+(?:job|fee)\b|\btop[- ]?up\s+to\s+earn\b"
    r"|\b(?:earn|unlock|release|withdraw)\s+(?:my\s+|the\s+)?commission\b"
    r"|\bunlock\s+(?:the\s+|my\s+|more\s+)?tasks?\b|\bupgrade\s+my\s+account\b"
    r"|\brectify\s+(?:a|the|my)\s+mistake\b|\b(?:activation|training)\s+fee\b", re.I)
_INSTRUCTION_OVERRIDE = re.compile(
    r"ignore (?:all |the |any )?(?:previous|prior|above|earlier) instructions?"
    r"|disregard (?:the |all )?(?:previous|prior|above)\b|\bsystem prompt\b|\byou are now\b", re.I)
_PAYMENT_RULES = [
    (_OFFICIAL_ORDERS, "words_official_orders", "refuse",
     "An official seems to be telling you to pay someone. Real officers never ask you to "
     "transfer money — this is how government-impersonation scams work."),
    (_JOB_TASK, "words_job_task", "strong",
     "It sounds like a job that asks you to pay first. Real jobs don't make you transfer "
     "money to earn commission."),
    (_INSTRUCTION_OVERRIDE, "words_instruction_override", "strong",
     "Your request contained wording aimed at the app itself. Check every detail of the "
     "payment below."),
]
_HELPLINE = (" If someone is on the phone with you right now, hang up and call the "
             "ScamShield Helpline (1799).")
_GRADE = {"refuse": 2, "strong": 1, "info": 0}


def scan_transcript(transcript: str) -> list:
    """The phrase rules' matches on the user's own words (new_contact.Warning:
    code, text, weight), strongest first. Rules, never the model."""
    text = transcript or ""
    found = [w for w in _contact_scam_words(text) if w.code not in _PAYMENT_RESTATED]
    found += [_ContactWarning(code, message, weight)
              for pat, code, weight, message in _PAYMENT_RULES if pat.search(text)]
    return sorted(found, key=lambda w: -_GRADE.get(w.weight, 0))


# --------------------------------------------------------------------------- the word score
# The user's words, in 10 scam categories (plus one for wording aimed at the
# app), from how Singapore's banks, SPF and ScamShield describe scams. Each
# category scores its strongest phrase; urgency adds up word by word.
#
#   categories, strongest first:  100%, 80%, 64%, ... of their points
#                                 (each one 0.8x the one before)
#   total                         capped at WORDS_MAX (8)
#
# NEVER RULES: things no real bank or official ever asks for. One of them in
# the user's words (the request or what they said it's for) gives the payment
# the strictest safeguards whatever the score (NEVER_RULE_OUTCOME).
CATEGORIES = (
    # name, what it means, {phrase code: points}
    ("official", "An official or the bank directing the payment",
     {"words_official_orders": 4.0, "words_investigation": 4.0}),
    ("safe_account", "A \u201csafe account\u201d", {"words_safe_account": 4.0}),
    ("credentials", "OTPs, passwords, app installs or screen-sharing", {"words_credentials": 4.0}),
    ("secrecy", "Keeping it secret", {"words_hide_from_bank": 4.0, "words_secrecy": 3.0}),
    ("mule", "Receiving money to pass on", {"words_mule": 3.0}),
    ("investment", "An investment promise", {"words_investment": 2.5}),
    ("job", "A job that makes you pay first", {"words_job_task": 2.5}),
    ("contact", "A \u201cnew number\u201d or someone met online",
     {"words_new_number": 2.5, "words_online_contact": 2.5}),
    ("fee", "A fee before you receive something",
     {"words_upfront_fee": 2.0, "words_parcel_refund": 0.5}),
    ("pressure", "Being rushed or directed live", {"words_directed": 2.0}),   # + urgency words
    ("app", "Wording aimed at the app", {"words_instruction_override": 2.0}),
)
NEVER_RULES = frozenset({"words_official_orders", "words_investigation", "words_safe_account",
                         "words_credentials", "words_hide_from_bank", "words_mule"})
NEVER_RULE_OUTCOME = "HOLD_STEP_UP"
CATEGORY_FACTOR = 0.8                # each next category counts 0.8x the one before
WORDS_MAX = 8.0
# Urgency, inside "pressure": every word counts, repeats of the SAME word less
# ("hurry now hurry" > "hurry hurry"), shouting more. The category tops out at 3.
URGENT_WORD_POINTS = 0.75
REPEAT_FACTOR = 0.75
CAPITALS_POINTS = 1.0
EXCLAIM_POINTS = 0.5
PRESSURE_MAX = 3.0
RUSHED_WARNING_FROM = 2.0            # pressure points that earn the "rushed" warning
_URGENT_WORD = re.compile(
    r"\b(?:now|urgent(?:ly)?|immediately|asap|hurry|quick(?:ly)?|right\s+away"
    r"|as\s+soon\s+as\s+possible|before\s+it'?s\s+too\s+late)\b", re.I)

# Facts 3+ (threshold 1): the payment is not drafted until the user answers
# questions picked by the facts that scored highest, plus CALL_QUESTION. The
# answers are scored by the same word rules, can only ADD points, and are never
# sent to the model. A coached victim often says the quiet part here ("for an
# investigation", "an online friend", "he's still on the line").
ASK_QUESTIONS = True                 # False: score the request alone, never ask (tests)
PURPOSE_QUESTION = "What is this payment for?"
CALL_QUESTION = "Is anyone on a call or chat with you about it right now?"


def word_score(transcript: str, found=None) -> dict:
    """What the user's own words add, itemised (the browser console prints it).
    `found`: scan_transcript()'s matches, if already run. A rule, never the model."""
    text = transcript or ""
    found = scan_transcript(text) if found is None else found
    codes = {w.code for w in found}
    urgent, seen = [], {}
    for m in _URGENT_WORD.finditer(text):
        word = re.sub(r"\s+", " ", m.group(0).lower())
        k = seen[word] = seen.get(word, -1) + 1
        urgent.append((word, round(URGENT_WORD_POINTS * REPEAT_FACTOR ** k, 2)))
    capitals = CAPITALS_POINTS if any(m.group(0).isupper() and m.group(0).upper() != "ASAP"
                                      for m in _URGENT_WORD.finditer(text)) else 0.0
    exclaim = EXCLAIM_POINTS if "!!" in text else 0.0

    categories = []
    for name, label, weights in CATEGORIES:
        hits = [(c, p) for c, p in weights.items() if c in codes]
        score = max((p for _, p in hits), default=0.0)
        if name == "pressure":
            score = min(PRESSURE_MAX, score + sum(p for _, p in urgent) + capitals + exclaim)
        if score > 0:
            categories.append({"category": name, "label": label, "points": round(score, 2),
                               "codes": [c for c, _ in hits]})
    categories.sort(key=lambda c: -c["points"])
    total = 0.0
    for k, c in enumerate(categories):
        c["counts"] = round(CATEGORY_FACTOR ** k, 3)
        c["adds"] = round(c["points"] * c["counts"], 2)
        total += c["points"] * c["counts"]
    pressure = next((c["points"] for c in categories if c["category"] == "pressure"), 0.0)
    return {"categories": categories, "urgent_words": urgent, "capitals": capitals,
            "exclamations": exclaim, "pressure": pressure, "raw": round(total, 2),
            "points": round(min(WORDS_MAX, total), 1), "max": WORDS_MAX,
            "never_rules": sorted(codes & NEVER_RULES)}


def phrase_codes(found) -> list[str]:
    """The codes only — what the audit log and the console keep, never the words."""
    return [w.code for w in found]


def strong_codes(found) -> list[str]:
    """The matches that add risk (strong or refuse-grade), not advisory ones."""
    return [w.code for w in found if _GRADE.get(w.weight, 0) > 0]


def warning_for(found) -> str | None:
    """The one fixed warning for these matches — the most severe first."""
    top = next((w for w in found if _GRADE.get(w.weight, 0) > 0), None)
    if top is None:
        return None
    return top.text + (_HELPLINE if top.weight == "refuse" else "")


# --------------------------------------------------------------------------- the assessment
@dataclass(frozen=True)
class Signal:
    code: str
    weight: float                 # points (the word score can be fractional)
    detail: str
    leg: str | None = None
    ask: str | None = None        # the question this fact prompts (threshold 1)


@dataclass(frozen=True)
class ScamAssessment:
    draft_id: str
    signals: tuple[Signal, ...]
    score: float                  # facts + the words, when they were weighed
    outcome: str
    warnings: tuple[str, ...]
    phrase_codes: list = field(default_factory=list)   # phrase-rule codes, incl. advisory
    riskiest_payee: str | None = None                  # the transfer the risk points at
    confirm_name: str | None = None                    # HOLD_STEP_UP: the name to type
    # Every transfer leg to a destination never paid before: not only the first
    # leg per destination (that one alone carries the signal), so the reply
    # vouches for none of them.
    new_destination_legs: frozenset = frozenset()
    never_rules: tuple = ()                            # NEVER_RULES codes in the user's words
    facts: float = 0.0                                 # threshold 1
    words: float = 0.0                                 # threshold 2 (0 when not weighed)
    words_weighed: bool = False
    decision: str = PASS                               # PASS / FAIL / CALL_BANK
    asks: bool = False                                 # facts 3-9.9: ask before drafting
    questions: tuple = ()                              # what to ask, if it asks

    def to_dict(self) -> dict:
        return {"draft_id": self.draft_id, "score": self.score, "outcome": self.outcome,
                "facts": self.facts, "words": self.words, "words_weighed": self.words_weighed,
                "decision": self.decision,
                "signals": [{"code": s.code, "weight": s.weight, "detail": s.detail,
                             "leg": s.leg} for s in self.signals],
                "warnings": list(self.warnings), "phrase_codes": self.phrase_codes,
                "confirm_name": self.confirm_name,
                "release_delay_seconds": release_delay(self.outcome),
                "source": "rules (not the model)"}

    def to_audit(self) -> dict:
        """For the append-only audit log: codes, weights and the outcome — never
        the user's words, names or amounts (the TRANSCRIPT entry's rule: the
        log keeps what non-repudiation needs and nothing hard to redact).
        Points in TENTHS (4.7 -> 47): the chain's canonical JSON refuses floats,
        as it refuses them for money (int cents)."""
        return {"draft_id": self.draft_id, "score_tenths": _tenths(self.score),
                "facts_tenths": _tenths(self.facts), "words_tenths": _tenths(self.words),
                "decision": self.decision, "outcome": self.outcome,
                "signals_tenths": [[s.code, _tenths(s.weight)] for s in self.signals],
                "phrase_codes": list(self.phrase_codes), "source": "rules (not the model)"}


@dataclass
class ScamContext:
    now: int
    destinations: dict            # payee_id -> destinations.Destination (current)
    history: list[dict]           # {payee_id, leg_type, amount, ts, dest_version}
    balances: dict                # account id -> cents, BEFORE this plan
    credentials: list[int]        # created_at of the user's passkeys
    transcript: str = ""
    recent_change_s: int = 24 * 3600
    cooling_s: int = 12 * 3600
    asked_at: int | None = None   # when the user asked (UNUSUAL_HOUR); default: now
    attempts: list = field(default_factory=list)   # earlier attempts (policy/attempts.py)
    freeze_released_at: int | None = None          # when the freeze was last turned off


def _tenths(points: float) -> int:
    return int(round(points * 10))


def _ts(value) -> int:
    """Unix seconds. A naive ISO timestamp means UTC — the policy engine's rule
    for the same history rows, so both read a row as the same moment."""
    if isinstance(value, (int, float)):
        return int(value)
    try:
        dt = datetime.fromisoformat(str(value))
    except ValueError:
        return 0
    return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())


def _ago(seconds: int) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return "just now"
    for unit, size in (("day", 86400), ("hour", 3600), ("minute", 60)):
        if seconds >= size:
            n = seconds // size
            return f"{n} {unit}{'' if n == 1 else 's'} ago"
    return "just now"  # pragma: no cover


def _name(display: str) -> str:
    return (display or "").split(" ··")[0].strip() or display


def _clock(ts: int) -> str:
    """Singapore time, e.g. "2:10am"."""
    sec = (int(ts) + SGT_OFFSET_S) % 86400
    h, m = sec // 3600, sec % 3600 // 60
    return f"{h % 12 or 12}:{m:02d}{'am' if h < 12 else 'pm'}"


def _stopped(attempt: dict) -> bool:
    """An earlier attempt that met friction and didn't go ahead: blocked, or
    declined, cancelled or frozen after being asked, held or delayed."""
    return attempt.get("status") == "STOPPED" and bool(
        attempt.get("asked") or attempt.get("outcome") in (DELAY, HOLD, HOLD_STEP_UP, BLOCK))


def assess(plan, ctx: ScamContext, *, draft_id: str | None = None) -> ScamAssessment:
    """Score a resolved plan. Pure: every input is in `plan` and `ctx`."""
    facts: list[Signal] = []
    warnings: list[str] = []
    sent_out: dict[str, int] = {}      # account -> transferred to other people by this plan
    now = ctx.now
    history = [h for h in ctx.history if (h.get("leg_type") or "TRANSFER") == "TRANSFER"]
    stopped = [a for a in ctx.attempts if _stopped(a) and int(a["updated_at"]) >= now - ATTEMPT_WINDOW_S]

    def add(code, detail, *, leg=None, ask=None, weight=None):
        facts.append(Signal(code, WEIGHTS[code] if weight is None else weight, detail, leg, ask))

    def paid_before(payee_id: str, version: int, before: int | None = None) -> bool:
        return any(h.get("payee_id") == payee_id and (h.get("dest_version") or 1) == version
                   and (before is None or _ts(h.get("ts")) < before) for h in history)

    new_here: set[tuple[str, int]] = set()
    new_legs: set[str] = set()         # every transfer leg to a never-paid destination
    names: dict[str, str] = {}         # transfer leg id -> the payee's name
    large = False
    for leg in plan.plan:
        # Only money sent to other people drains an account the way a scam
        # does: "buy AAPL with the rest" moves the user's money to the user.
        if leg.type != "TRANSFER":
            continue
        amount = leg.amount_cents
        money = "$" + cents_to_display(amount)
        who = _name(leg.payee_display)
        names[leg.id] = who
        acct = account_label(leg.source_account)

        # --- amount
        balance = ctx.balances.get(leg.source_account, 0)      # before this plan
        before = sent_out.get(leg.source_account, 0)
        sent = sent_out[leg.source_account] = before + amount
        if balance > 0:
            pct = sent * 100 // balance
            share_ask = f"This is {pct}% of your {acct} balance. What is it for?"
            if before * 100 < balance * DRAIN_PERCENT <= sent * 100:
                add("BALANCE_DRAIN", f"${cents_to_display(sent)} is {pct}% of your {acct} balance",
                    leg=leg.id, ask=share_ask)
                warnings.append(f"This would take most of your {acct} balance. Scammers often "
                                f"push people to move everything at once.")
            elif (before * 100 < balance * LARGE_SHARE_PERCENT <= sent * 100
                  and sent * 100 < balance * DRAIN_PERCENT):
                add("LARGE_SHARE", f"${cents_to_display(sent)} is {pct}% of your {acct} balance",
                    leg=leg.id, ask=share_ask)
                large = True
        if amount >= LARGE_AMOUNT_CENTS:
            add("LARGE_AMOUNT", f"{money} is ${LARGE_AMOUNT_CENTS // 100:,} or more", leg=leg.id,
                ask="This is more than you usually send. What is it for?")
            large = True
        recent90 = [int(h.get("amount") or 0) for h in history if _ts(h.get("ts")) >= now - USUAL_WINDOW_S]
        if recent90 and amount > USUAL_MAX_FACTOR * max(recent90):
            add("ABOVE_USUAL_MAX", f"{money} is over {USUAL_MAX_FACTOR}x your largest transfer "
                                   f"in 90 days", leg=leg.id,
                ask="This is more than you usually send. What is it for?")
            large = True
        to_payee = [h for h in history if h.get("payee_id") == leg.payee_id]
        if to_payee and amount > PAYEE_MAX_FACTOR * max(int(h.get("amount") or 0) for h in to_payee):
            add("ABOVE_PAYEE_MAX", f"{money} is over {PAYEE_MAX_FACTOR}x the most you've sent {who}",
                leg=leg.id, ask=f"This is more than you've ever sent {who}. What's it for this time?")
            large = True

        # --- payee
        dest = ctx.destinations.get(leg.payee_id)
        version = leg.destination_version or (dest.version if dest else 1)
        never_paid = not paid_before(leg.payee_id, version)
        if never_paid:
            new_legs.add(leg.id)
        if never_paid and (leg.payee_id, version) not in new_here:
            new_here.add((leg.payee_id, version))
            add("FIRST_PAYMENT_TO_DESTINATION",
                f"no earlier payment to {who} at {leg.destination_masked or 'this destination'}",
                leg=leg.id, ask=f"How do you know {who}, and how did you get their number?")
            if amount >= LARGE_FIRST_CENTS:
                add("LARGE_FIRST_PAYMENT", f"{money} as a first payment to {who}", leg=leg.id,
                    ask=f"This is your first payment to {who}, and it's {money}. What is it for?")
        if dest and dest.changed_at and now - int(dest.changed_at) < ctx.recent_change_s:
            ago = _ago(now - int(dest.changed_at))
            added = dest.version == 1
            # A changed number is the "Hi Mum, new number" scam: with a first
            # payment to it (2) it reaches FACTS_FAIL_FROM, however calm the answer.
            add("RECENT_DESTINATION_CHANGE",
                f"{who} was {'added' if added else 'given a new number'} {ago}", leg=leg.id,
                weight=NEW_CONTACT_POINTS if added else None,
                ask=(f"You added {who} {ago}. How did you meet them?" if added else
                     f"{who}'s number changed {ago}. Did you check the new number by calling "
                     f"them on their old one?"))
            warnings.insert(0, (
                f"{who} was only added as a contact {ago}. Scammers often ask to be paid "
                f"as a “new contact”. Check with {who} on a number you already know."
                if added else
                f"{who}'s PayNow number was changed {ago}. Scammers often pretend to be "
                f"friends or family with a “new number”. Call {who} on a number you "
                f"already know before continuing."))

        # --- this payee's recent history
        day = [h for h in to_payee if _ts(h.get("ts")) >= now - ATTEMPT_WINDOW_S]
        if to_payee and day and min(_ts(h.get("ts")) for h in to_payee) >= now - ATTEMPT_WINDOW_S:
            total = sum(int(h.get("amount") or 0) for h in day) + amount
            if total >= SPLIT_TOTAL_CENTS:
                add("SPLIT_PAYMENTS", f"${cents_to_display(total)} to {who} today, in parts",
                    leg=leg.id, ask=f"You've sent {who} ${cents_to_display(total)} today in "
                                    f"parts. Has someone asked you to split it?")
                warnings.append(f"You're sending {who} money in parts. Splitting a payment "
                                f"doesn't make it any safer.")
        week = sorted((h for h in to_payee if _ts(h.get("ts")) >= now - WEEK_S),
                      key=lambda h: _ts(h.get("ts")))
        amounts = [int(h.get("amount") or 0) for h in week] + [amount]
        if len(amounts) >= 3 and all(a < b for a, b in zip(amounts, amounts[1:])):
            add("ESCALATING_AMOUNTS", f"{len(amounts)} payments to {who} this week, each bigger",
                leg=leg.id, ask=f"You've paid {who} {len(amounts)} times this week, each more "
                                f"than before. Are you being asked to pay more to get money back?")
            warnings.append(f"Each payment to {who} this week has been bigger than the last. Job "
                            f"and investment scams often look like this.")
        mine = [a for a in stopped if a.get("payee_id") == leg.payee_id]
        if mine:
            last = max(int(a["updated_at"]) for a in mine)
            add("RETRY_AFTER_STOPPED", f"a payment to {who} was stopped {_ago(now - last)}",
                leg=leg.id, ask=f"You stopped a payment to {who} {_ago(now - last)}. What's "
                                f"changed since then?")
            warnings.append(f"A payment to {who} was stopped {_ago(now - last)}. If someone is "
                            f"asking you to try again, it's very likely a scam.")
            if any(int(a["amount"]) > amount for a in mine):
                add("SMALLER_AFTER_STOPPED", f"{money} is less than the stopped payment to {who}",
                    leg=leg.id, ask=f"This is less than the payment to {who} that was stopped. "
                                    f"Has someone asked you to try a smaller amount?")
                warnings.append("This is less than a payment that was stopped. Scammers try "
                                "smaller amounts to get past checks.")

    transfers = bool(names)
    if large:
        warnings.append("This is a large payment for you. Check you know who you're paying "
                        "and why.")

    # --- across the whole plan
    window_start = now - RAPID_WINDOW_S
    recent_new = {(h["payee_id"], h.get("dest_version") or 1) for h in history
                  if h.get("payee_id") and _ts(h.get("ts")) >= window_start
                  and not paid_before(h["payee_id"], h.get("dest_version") or 1, _ts(h.get("ts")))}
    fan_out = len(recent_new | new_here)
    if new_here and fan_out >= RAPID_COUNT:
        add("RAPID_MULTI_DESTINATION", f"{fan_out} new destinations paid within 30 minutes",
            ask=f"You've paid {fan_out} new people in the last half hour. Is someone telling "
                f"you who to pay?")
        warnings.append("You've paid several new people in the last half hour. Scams that "
                        "move money quickly often look like this.")
    if len(ctx.credentials) > 1 and now - max(ctx.credentials) < ctx.cooling_s:
        ago = _ago(now - max(ctx.credentials))
        add("RECENT_CREDENTIAL_CHANGE", f"a new passkey was added {ago}",
            ask=f"A new device was added to your account {ago}. Was that you?")
        warnings.append("A new device was added to your account recently. If that wasn't "
                        "you, cancel this and freeze your payments.")
    if ctx.freeze_released_at and now - int(ctx.freeze_released_at) < FREEZE_RECENT_S:
        ago = _ago(now - int(ctx.freeze_released_at))
        add("FREEZE_TURNED_OFF", f"the freeze was turned off {ago}",
            ask=f"You turned off your freeze {ago}. Did anyone ask you to?")
        warnings.append("You turned off your freeze recently. If someone asked you to, freeze "
                        "your payments again now.")
    asked_at = ctx.asked_at or now
    if transfers and (asked_at + SGT_OFFSET_S) % 86400 < 5 * 3600:
        add("UNUSUAL_HOUR", "between midnight and 5am",
            ask=f"It's {_clock(asked_at)}. Is someone asking you to do this right now?")
    if (new_here and history
            and not any(_ts(h.get("ts")) >= now - DORMANT_S for h in history)):
        add("DORMANT_ACCOUNT_WAKE", "no transfers for 90+ days, then someone new",
            ask="You haven't sent money in a while. What is this payment for?")
        warnings.append("You haven't sent money in a while. Check you know who you're paying.")
    stopped_drafts = {a["draft_id"] for a in stopped}
    if len(stopped_drafts) >= 2:
        add("REPEATED_STOPPED_ATTEMPTS", f"{len(stopped_drafts)} payment attempts stopped in "
                                         f"the last day", weight=min(3, len(stopped_drafts)),
            ask="Several payments were stopped in the last day. Is someone asking you to keep "
                "trying?")
        warnings.append("Several payments were stopped today. If someone keeps asking you to "
                        "try again, stop and call your bank.")
    warned_sent = {a["draft_id"] for a in ctx.attempts
                   if a.get("status") == "SENT" and int(a["updated_at"]) >= now - WEEK_S
                   and a.get("outcome") in (WARN, DELAY, HOLD, HOLD_STEP_UP)}
    if len(warned_sent) >= 2:
        add("WARNINGS_IGNORED", f"{len(warned_sent)} warned payments sent in the last 7 days")

    # --- threshold 1, the words, threshold 2
    facts_score = round(facts_points((f.code, f.weight) for f in facts), 1)
    found = scan_transcript(ctx.transcript)
    words = word_score(ctx.transcript, found)
    never = tuple(words["never_rules"])
    weighed = facts_score >= FACTS_ASK_FROM or bool(never)
    words_points = words["points"] if weighed else 0.0
    decision, outcome = decide(facts_score, words_points, never)

    signals = list(facts)
    if weighed and words["points"] > 0:
        parts = [f"{c['category']} {c['points']:g}x{c['counts']:g}" for c in words["categories"]]
        signals.append(Signal(WORDS_CODE, words["points"],
                              "your words: " + " + ".join(parts) + f" = {words['raw']:g}"
                              + (f", capped at {WORDS_MAX:g}" if words["raw"] > WORDS_MAX else "")
                              + (" (never rule: " + ", ".join(never) + ")" if never else "")))
    if strong_codes(found):
        warnings.insert(0, warning_for(found))       # a phrase warning shows even unweighed
    if weighed and words["pressure"] >= RUSHED_WARNING_FROM:
        warnings.append("You're being rushed. Scammers push people to pay before they can stop "
                        "and check. If someone is hurrying you, take a minute and call them on a "
                        "number you already know.")
    if not warnings and new_here:
        large_first = any(f.code == "LARGE_FIRST_PAYMENT" for f in facts)
        warnings.append(f"This is your first payment to this destination"
                        f"{', and a large one' if large_first else ''}. Check the number below "
                        f"is the one you expect.")
    if outcome == ALLOW and warnings:
        outcome = WARN                                # a warning to read, no other friction

    asks = (FACTS_ASK_FROM <= facts_score < FACTS_CALL_BANK_FROM and not never
            and decision != CALL_BANK)
    questions: tuple = ()
    if asks:
        # The highest-scoring fact's question, and a tied one about a different
        # kind of fact (two amount facts would both ask "what is it for?").
        askable = sorted((f for f in facts if f.ask), key=lambda f: -f.weight)
        top: list[Signal] = []
        for f in askable:
            kind = "amount" if f.code in AMOUNT_CODES else f.code
            if f.weight == askable[0].weight and kind not in {
                    "amount" if t.code in AMOUNT_CODES else t.code for t in top}:
                top.append(f)
        questions = (tuple(dict.fromkeys(f.ask for f in top[:2])) or (PURPOSE_QUESTION,)) \
            + (CALL_QUESTION,)

    # HOLD_STEP_UP: type the name of the payee the risk points at, not simply
    # the first one in the plan (plan order breaks a tie).
    leg_risk: dict[str, float] = {}
    for sig in signals:
        if sig.leg in names:
            leg_risk[sig.leg] = leg_risk.get(sig.leg, 0) + sig.weight
    riskiest = names[max(names, key=lambda k: leg_risk.get(k, 0))] if names else None
    return ScamAssessment(
        draft_id=draft_id or plan.draft_id, signals=tuple(signals),
        score=round(facts_score + words_points, 1), outcome=outcome,
        warnings=tuple(dict.fromkeys(warnings)) if outcome != ALLOW else (),
        phrase_codes=phrase_codes(found),
        riskiest_payee=riskiest, confirm_name=riskiest if outcome == HOLD_STEP_UP else None,
        new_destination_legs=frozenset(new_legs), never_rules=never,
        facts=facts_score, words=words_points, words_weighed=weighed, decision=decision,
        asks=asks, questions=questions)


def reassess(plan, user_id: str, *, db_path=None, now: int, transcript: str = "",
             recent_change_hours: int = 24, cooling_hours: int = 12,
             draft_id: str | None = None) -> ScamAssessment:
    """Score `plan` against the ledger as it is NOW. The one entry point for the
    draft pipeline, the signing-challenge check and the gateway, so the three
    cannot drift. The hour judged is when the plan was drafted (its signed
    created_at): waiting out a hold past midnight doesn't make it riskier.
    `draft_id`: this draft's own earlier rows don't count as earlier attempts."""
    ctx = load_scam_context(user_id, db_path=db_path, now=now, transcript=transcript,
                            recent_change_hours=recent_change_hours, cooling_hours=cooling_hours,
                            draft_id=draft_id or getattr(plan, "draft_id", None))
    ctx.asked_at = getattr(plan, "created_at", None) or now
    return assess(plan, ctx, draft_id=draft_id)


# --------------------------------------------------------------------------- the ledger's view
def load_scam_context(user_id: str, *, db_path=None, now: int, transcript: str = "",
                      recent_change_hours: int = 24, cooling_hours: int = 12,
                      draft_id: str | None = None) -> ScamContext:
    from backend.policy import attempts as _attempts
    conn = connect(db_path or DB_PATH)
    try:
        dests = _destinations.for_user(conn, user_id)
        history = [dict(r) for r in conn.execute(
            "SELECT payee_id, leg_type, amount, ts, dest_version FROM transaction_history "
            "WHERE user_id=?", (user_id,))]
        balances = {r["id"]: r["balance"] for r in conn.execute(
            "SELECT id, balance FROM accounts WHERE user_id=?", (user_id,))}
        creds = [int(r["created_at"] or 0) for r in conn.execute(
            "SELECT created_at FROM webauthn_credentials WHERE user_id=?", (user_id,))]
        row = conn.execute("SELECT released_at FROM kill_switch WHERE user_id=?",
                           (user_id,)).fetchone()
    finally:
        conn.close()
    return ScamContext(now=now, destinations=dests, history=history, balances=balances,
                       credentials=creds, transcript=transcript,
                       recent_change_s=recent_change_hours * 3600, cooling_s=cooling_hours * 3600,
                       attempts=_attempts.recent(user_id, since=now - WEEK_S,
                                                 exclude_draft=draft_id, db_path=db_path),
                       freeze_released_at=int(row["released_at"]) if row and row["released_at"]
                       else None)
