"""
Scam signals, a risk score, and what it makes the user do.

In the scams DBS worries about most, the REAL customer signs the payment while
being manipulated — "Mum, this is my new number", the "officer" who needs your
savings moved to a safe account. Passkeys, signatures and nonces do not help
there: the person approving IS the account holder. What helps is noticing the
pattern and slowing them down. So, before a draft can be signed:

    signal                          rule (demo thresholds)                    weight
    FIRST_PAYMENT_TO_DESTINATION    no earlier transfer to this destination     2
                                    VERSION (a new number is a new destination)
    RECENT_DESTINATION_CHANGE       destination changed/added < 24 h ago         3
    LARGE_FIRST_PAYMENT             first payment AND >= $1,000                  3
    BALANCE_DRAIN                   >= 80% of the source account's balance       3
    RAPID_MULTI_DESTINATION         >= 3 new destinations paid within 30 min     4
    RECENT_CREDENTIAL_CHANGE        a passkey added < 12 h ago (not the first)   4
    SOCIAL_ENGINEERING_LANGUAGE     scam wording in the user's own request       2
                                    (a "safe account" / an official's orders: 4)
    UNUSUAL_HOUR                    00:00-05:00 Singapore time, first payment    1

    score 0-1  ALLOW          normal passkey signing
          2-3  WARN           a scam-type-specific warning on the card
          4-6  HOLD           + a SERVER-enforced hold (backend/policy/safety.py)
          >=7  HOLD_STEP_UP   + a code on the phone, + typing the payee's name

DETERMINISTIC, NOT THE MODEL. Every signal here is a rule over the ledger and
the raw transcript. The scam-wording rules (new_contact.py's list, shared with
the add-a-contact flow) run on the transcript itself, outside the model: if the model decided these flags, a
prompt injection could switch them off. A signal can only RAISE the score —
nothing here approves anything or removes a safeguard. The phrase flags are
ADVISORY evidence, not a security boundary: they add friction, they never
decide a payment is safe.

Every warning is a FIXED sentence written here (the card only renders trusted
text), chosen for the kind of scam the signals point to.
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
    "FIRST_PAYMENT_TO_DESTINATION": 2,
    "RECENT_DESTINATION_CHANGE": 3,
    "LARGE_FIRST_PAYMENT": 3,
    "BALANCE_DRAIN": 3,
    "RAPID_MULTI_DESTINATION": 4,
    "RECENT_CREDENTIAL_CHANGE": 4,
    "SOCIAL_ENGINEERING_LANGUAGE": 2,
    "UNUSUAL_HOUR": 1,
}
REFUSE_PHRASE_WEIGHT = 4             # SOCIAL_ENGINEERING_LANGUAGE for a refuse-grade phrase
LARGE_FIRST_CENTS = 100_000          # $1,000
DRAIN_PERCENT = 80
RAPID_WINDOW_S = 30 * 60
RAPID_COUNT = 3
SGT_OFFSET_S = 8 * 3600              # Singapore time, for UNUSUAL_HOUR

ALLOW, WARN, HOLD, HOLD_STEP_UP = "ALLOW", "WARN", "HOLD", "HOLD_STEP_UP"


_RANK = {ALLOW: 0, WARN: 1, HOLD: 2, HOLD_STEP_UP: 3}


def stricter(a: str | None, b: str) -> str:
    """The stricter of two outcomes (None counts as ALLOW)."""
    return a if a is not None and _RANK[a] > _RANK[b] else b


def needs_hold(outcome: str | None) -> bool:
    return outcome in (HOLD, HOLD_STEP_UP)


def rose_past_drafted(drafted: str | None, fresh: str) -> bool:
    """True when the score NOW demands a hold or a phone code that the draft,
    as the user saw it, never arranged (a passkey added since, more new payees
    paid since). The payment is refused — the user cancels and asks again, and
    the new draft shows the new safeguards — rather than run past friction the
    user never saw. `drafted` None (never assessed): nothing to compare."""
    return (drafted is not None and needs_hold(fresh)
            and _RANK[fresh] > _RANK.get(drafted, 0))


def outcome_for(score: int) -> str:
    if score >= 7:
        return HOLD_STEP_UP
    if score >= 4:
        return HOLD
    if score >= 2:
        return WARN
    return ALLOW


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
    r"|\b(?:earn|unlock|release|withdraw)\s+(?:my\s+|the\s+)?commission\b", re.I)
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
    weight: int
    detail: str
    leg: str | None = None


@dataclass(frozen=True)
class ScamAssessment:
    draft_id: str
    signals: tuple[Signal, ...]
    score: int
    outcome: str
    warnings: tuple[str, ...]
    phrase_codes: list = field(default_factory=list)   # phrase-rule codes, incl. advisory
    confirm_name: str | None = None                    # HOLD_STEP_UP: the name to type

    def to_dict(self) -> dict:
        return {"draft_id": self.draft_id, "score": self.score, "outcome": self.outcome,
                "signals": [{"code": s.code, "weight": s.weight, "detail": s.detail,
                             "leg": s.leg} for s in self.signals],
                "warnings": list(self.warnings), "phrase_codes": self.phrase_codes,
                "confirm_name": self.confirm_name, "source": "rules (not the model)"}

    def to_audit(self) -> dict:
        """For the append-only audit log: codes, weights and the outcome — never
        the user's words, names or amounts (the TRANSCRIPT entry's rule: the
        log keeps what non-repudiation needs and nothing hard to redact)."""
        return {"draft_id": self.draft_id, "score": self.score, "outcome": self.outcome,
                "signals": [[s.code, s.weight] for s in self.signals],
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


def assess(plan, ctx: ScamContext, *, draft_id: str | None = None) -> ScamAssessment:
    """Score a resolved plan. Pure: every input is in `plan` and `ctx`."""
    signals: list[Signal] = []
    warnings: list[str] = []
    balances = dict(ctx.balances)

    def paid_before(payee_id: str, version: int, before: int | None = None) -> bool:
        return any(h.get("payee_id") == payee_id and (h.get("dest_version") or 1) == version
                   and (before is None or _ts(h.get("ts")) < before)
                   for h in ctx.history if (h.get("leg_type") or "TRANSFER") == "TRANSFER")

    new_here: set[tuple[str, int]] = set()
    confirm_name = None
    for leg in plan.plan:
        balance = balances.get(leg.source_account, 0)
        if balance > 0 and leg.amount_cents * 100 >= balance * DRAIN_PERCENT:
            signals.append(Signal("BALANCE_DRAIN", WEIGHTS["BALANCE_DRAIN"],
                                  f"${cents_to_display(leg.amount_cents)} is "
                                  f"{leg.amount_cents * 100 // balance}% of your "
                                  f"{account_label(leg.source_account)} balance", leg.id))
            warnings.append(f"This would take most of your {account_label(leg.source_account)} "
                            f"balance. Scammers often push people to move everything at once.")
        balances[leg.source_account] = balance - leg.amount_cents
        if leg.type != "TRANSFER":
            continue

        who = _name(leg.payee_display)
        dest = ctx.destinations.get(leg.payee_id)
        version = leg.destination_version or (dest.version if dest else 1)
        first = not paid_before(leg.payee_id, version) and (leg.payee_id, version) not in new_here
        if first:
            new_here.add((leg.payee_id, version))
            signals.append(Signal("FIRST_PAYMENT_TO_DESTINATION",
                                  WEIGHTS["FIRST_PAYMENT_TO_DESTINATION"],
                                  f"no earlier payment to {who} at "
                                  f"{leg.destination_masked or 'this destination'}", leg.id))
            if leg.amount_cents >= LARGE_FIRST_CENTS:
                signals.append(Signal("LARGE_FIRST_PAYMENT", WEIGHTS["LARGE_FIRST_PAYMENT"],
                                      f"${cents_to_display(leg.amount_cents)} as a first payment "
                                      f"to {who}", leg.id))
            if ((ctx.asked_at or ctx.now) + SGT_OFFSET_S) % 86400 < 5 * 3600:
                signals.append(Signal("UNUSUAL_HOUR", WEIGHTS["UNUSUAL_HOUR"],
                                      "a first payment between midnight and 5am", leg.id))
        if dest and dest.changed_at and ctx.now - int(dest.changed_at) < ctx.recent_change_s:
            ago = _ago(ctx.now - int(dest.changed_at))
            added = dest.version == 1
            signals.append(Signal("RECENT_DESTINATION_CHANGE", WEIGHTS["RECENT_DESTINATION_CHANGE"],
                                  f"{who} was {'added' if added else 'given a new number'} {ago}",
                                  leg.id))
            warnings.insert(0, (
                f"{who} was only added as a contact {ago}. Scammers often ask to be paid "
                f"as a “new contact”. Check with {who} on a number you already know."
                if added else
                f"{who}'s PayNow number was changed {ago}. Scammers often pretend to be "
                f"friends or family with a “new number”. Call {who} on a number you "
                f"already know before continuing."))
        confirm_name = confirm_name or who

    # Rapid fan-out: new destinations paid within the window, plus this plan's.
    window_start = ctx.now - RAPID_WINDOW_S
    recent_new = {(h["payee_id"], h.get("dest_version") or 1) for h in ctx.history
                  if (h.get("leg_type") or "TRANSFER") == "TRANSFER" and h.get("payee_id")
                  and _ts(h.get("ts")) >= window_start
                  and not paid_before(h["payee_id"], h.get("dest_version") or 1, _ts(h.get("ts")))}
    fan_out = len(recent_new | new_here)
    if new_here and fan_out >= RAPID_COUNT:
        signals.append(Signal("RAPID_MULTI_DESTINATION", WEIGHTS["RAPID_MULTI_DESTINATION"],
                              f"{fan_out} new destinations paid within 30 minutes"))
        warnings.append("You've paid several new people in the last half hour. Scams that "
                        "move money quickly often look like this.")

    if len(ctx.credentials) > 1 and ctx.now - max(ctx.credentials) < ctx.cooling_s:
        signals.append(Signal("RECENT_CREDENTIAL_CHANGE", WEIGHTS["RECENT_CREDENTIAL_CHANGE"],
                              f"a new passkey was added {_ago(ctx.now - max(ctx.credentials))}"))
        warnings.append("A new device was added to your account recently. If that wasn't "
                        "you, cancel this and freeze your payments.")

    found = scan_transcript(ctx.transcript)
    strong = strong_codes(found)
    if strong:
        weight = (REFUSE_PHRASE_WEIGHT if any(w.weight == "refuse" for w in found)
                  else WEIGHTS["SOCIAL_ENGINEERING_LANGUAGE"])
        signals.append(Signal("SOCIAL_ENGINEERING_LANGUAGE", weight,
                              "your request has scam wording: " + ", ".join(strong)))
        warnings.insert(0, warning_for(found))

    # Each code counts once, however many legs raised it (at its highest weight).
    by_code: dict[str, int] = {}
    for sig in signals:
        by_code[sig.code] = max(by_code.get(sig.code, 0), sig.weight)
    score = sum(by_code.values())
    outcome = outcome_for(score)
    if outcome == WARN and not warnings and new_here:
        warnings.append("This is your first payment to this destination. Check the number "
                        "below is the one you expect.")
    return ScamAssessment(
        draft_id=draft_id or plan.draft_id, signals=tuple(signals), score=score,
        outcome=outcome, warnings=tuple(dict.fromkeys(warnings)) if outcome != ALLOW else (),
        phrase_codes=phrase_codes(found),
        confirm_name=confirm_name if outcome == HOLD_STEP_UP else None)


def reassess(plan, user_id: str, *, db_path=None, now: int, transcript: str = "",
             recent_change_hours: int = 24, cooling_hours: int = 12,
             draft_id: str | None = None) -> ScamAssessment:
    """Score `plan` against the ledger as it is NOW. The one entry point for the
    draft pipeline, the signing-challenge check and the gateway, so the three
    cannot drift. The hour judged is when the plan was drafted (its signed
    created_at): waiting out a hold past midnight doesn't make it riskier."""
    ctx = load_scam_context(user_id, db_path=db_path, now=now, transcript=transcript,
                            recent_change_hours=recent_change_hours, cooling_hours=cooling_hours)
    ctx.asked_at = getattr(plan, "created_at", None) or now
    return assess(plan, ctx, draft_id=draft_id)


# --------------------------------------------------------------------------- the ledger's view
def load_scam_context(user_id: str, *, db_path=None, now: int, transcript: str = "",
                      recent_change_hours: int = 24, cooling_hours: int = 12) -> ScamContext:
    conn = connect(db_path or DB_PATH)
    try:
        payee_ids = [r["id"] for r in conn.execute("SELECT id FROM payees WHERE user_id=?",
                                                   (user_id,))]
        dests = {pid: _destinations.current(conn, pid) for pid in payee_ids}
        history = [dict(r) for r in conn.execute(
            "SELECT payee_id, leg_type, amount, ts, dest_version FROM transaction_history "
            "WHERE user_id=?", (user_id,))]
        balances = {r["id"]: r["balance"] for r in conn.execute(
            "SELECT id, balance FROM accounts WHERE user_id=?", (user_id,))}
        creds = [int(r["created_at"] or 0) for r in conn.execute(
            "SELECT created_at FROM webauthn_credentials WHERE user_id=?", (user_id,))]
    finally:
        conn.close()
    return ScamContext(now=now, destinations=dests, history=history, balances=balances,
                       credentials=creds, transcript=transcript,
                       recent_change_s=recent_change_hours * 3600, cooling_s=cooling_hours * 3600)
