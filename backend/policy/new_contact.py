"""
Risk rules for adding a new contact. Pure and deterministic, like engine.py.

Adding a payee is the step just before most scam payments: "Hi Mum, this is my
new number", the officer who needs your savings moved to a "safe account", the
job that pays commission once you top up. So before a new contact is drafted
these rules decide which safeguards it needs — or that it should not be added.

THE LADDER (what the user must do before the contact exists):

    STANDARD   biometric only                                   no warning signs
    CODE       + a code on their phone (out of band)            one mild sign
    HOLD       + code + payments to the contact held for        a strong sign, two
               NEW_CONTACT_HOLD_MINUTES after it is added       mild ones, or the
                                                                LLM says "high"
    REFUSE     nothing is added; the page says why and          a reported number,
               points to the ScamShield helpline                a "safe account", an
                                                                official giving orders

WHERE THE LLM FITS. The deterministic rules set the FLOOR. The LLM's scam
assessment arrives here as plain data (a risk word and signal codes — this
module cannot import backend/agent/, the import-boundary test forbids it) and
can only RAISE the rung: "medium" means at least CODE, "high" means at least
HOLD. It can never lower one, and on its own it cannot refuse: a refusal needs
a deterministic reason, or the LLM's "high" AGREEING with scam wording the rules
found that has no innocent reading (secrecy, guaranteed returns, pay-to-earn). If the LLM could not be asked, the rung is at least CODE — a missing
check fails towards more care, not less.

Every warning is a FIXED sentence written here, never model text: these are
what the confirmation card shows, and the card only renders trusted text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# MOCK: a stand-in for a scam-number feed (ScamShield in Singapore). A real
# deployment would query the feed; the demo needs one number that trips it.
REPORTED_NUMBERS = frozenset({"+65 8888 1234", "+65 9999 1234"})
REPORTED_REASON = "this number has been reported for scams"


def _international_digits(phone: str | None) -> str:
    """"+65 8888 1234", "6588881234" and "8888 1234" -> "6588881234". Eight
    digits are a local Singapore number (resolver/contacts.normalize_phone)."""
    digits = re.sub(r"\D", "", phone or "")
    return "65" + digits if len(digits) == 8 else digits


_REPORTED_DIGITS = frozenset(_international_digits(n) for n in REPORTED_NUMBERS)


def is_reported(phone: str | None) -> bool:
    """Whether this number is on the scam-number feed, however it is written.
    Asked wherever a number can become a destination — adding a contact,
    changing one's number — and again before every payment: the feed changes,
    so a contact saved last month can be reported today."""
    return _international_digits(phone) in _REPORTED_DIGITS


LARGE_PENDING_CENTS = 100_000      # $1,000: a first payment this big is a strong sign
# Wording with no innocent reading when saving a payee. Together with the LLM's
# "high" it refuses the contact. "New number" or "urgent" are NOT here: people
# do change numbers and do need things quickly — those get the hold instead.
_REFUSE_IF_AI_AGREES = frozenset({"words_secrecy", "words_investment", "words_job_task"})
RECENT_ADDS_LIMIT = 2              # contacts added in the last 24h before this one

STANDARD, CODE, HOLD, REFUSE = "STANDARD", "CODE", "HOLD", "REFUSE"
_SAFEGUARDS = {
    STANDARD: ("BIOMETRIC",),
    CODE: ("BIOMETRIC", "PHONE_CODE"),
    HOLD: ("BIOMETRIC", "PHONE_CODE", "HOLD"),
    REFUSE: (),
}


@dataclass(frozen=True)
class Warning:
    """One reason for care. `weight`: info (a mild sign), strong, refuse, or ai
    (the LLM's opinion — shown, but weighed through the LLM's risk word)."""
    code: str
    text: str
    weight: str


@dataclass(frozen=True)
class NewContactFacts:
    """Everything the rules look at, already fetched. Built by main.py."""
    nickname: str
    phone: str                                   # normalised, "+65 9123 4567"
    existing: list[dict] = field(default_factory=list)   # [{nickname, phone}]
    added_last_24h: int = 0
    conversation: str = ""                       # everything the user said for this
    pending_cents: int | None = None             # a payment waiting for this contact
    for_payment: bool = False                    # added in the middle of a payment


@dataclass(frozen=True)
class ContactDecision:
    rung: str                                    # STANDARD | CODE | HOLD | REFUSE
    warnings: tuple[Warning, ...]
    hold_minutes: int
    ai_risk: str                                 # low | medium | high | unavailable

    @property
    def refused(self) -> bool:
        return self.rung == REFUSE

    @property
    def safeguards(self) -> tuple[str, ...]:
        return _SAFEGUARDS[self.rung]

    def to_audit_payload(self, draft_id: str) -> dict:
        return {"draft_id": draft_id, "kind": "contact_add", "rung": self.rung,
                "ai_risk": self.ai_risk, "hold_minutes": self.hold_minutes,
                "warnings": [w.code for w in self.warnings]}


# --------------------------------------------------------------------------- what the user said
# Conservative on purpose: supporting evidence, not a classifier. Each pattern
# is a phrase a scam script uses and an ordinary "add Bob, 9123 4567" does not.
_WORDS: list[tuple[str, str, re.Pattern, str]] = [
    # --- things no real bank or official ever asks for (docs/SCAM_WORD_WEIGHTS.md):
    #     refuse-grade here, and a payment that mentions one gets the strictest
    #     safeguards (policy/scam.py NEVER_RULES)
    ("words_safe_account", "refuse", re.compile(
        r"\b(safe|safety|secure|holding|protected|verification)\s+accounts?\b"
        r"|\bprotect\s+(?:my|your|our|the)\s+(?:money|savings|funds)\b"
        r"|\bfor\s+safe[- ]?keeping\b|\bkeep\s+my\s+(?:money|savings|funds)\s+safe\b", re.I),
     "You mentioned a “safe account”. No bank, police officer or government agency will "
     "ever ask you to move money to one to protect it — this is a scam."),
    ("words_official_orders", "refuse", re.compile(
        r"\b(police|officer|polis|mas|monetary authority|cpf|iras|ica|interpol|court|"
        r"government|ministry|minlaw|bank staff|bank officer)\b[^.?!]{0,60}"
        r"\b(told|asked|instructed|ordered|wants?|needs?|said)\s+(?:me|us)\b"
        r"|\b(told|asked|instructed|ordered)\s+(?:me|us)\b[^.?!]{0,60}"
        r"\b(police|officer|polis|mas|cpf|iras|ica|interpol|court|government|ministry)\b", re.I),
     "An official seems to be telling you to pay someone. Real officers never ask "
     "you to transfer money — this is how government-impersonation scams work."),
    ("words_investigation", "refuse", re.compile(
        r"\b(?:for|assist(?:ing)?\s+(?:with|in))\s+(?:an?\s+|the\s+|their\s+|police\s+)?investigations?\b"
        r"|\bunder\s+investigation\b|\bmoney\s+laundering\b"
        r"|\bprove\s+(?:my|our|his|her|their)\s+innocence\b|\bfinancial\s+inspection\b"
        r"|\b(?:call|line)\s+(?:was\s+)?transferred\s+to\s+(?:the\s+|an?\s+)?"
        r"(?:police|mas|officer|investigator)\b", re.I),
     "Banks, the police and government agencies never ask you to move money as part "
     "of an investigation, and a bank never transfers your call to the police."),
    ("words_credentials", "refuse", re.compile(
        r"\botp\b|\bone[- ]time\s+(?:password|pin|code)\b|\bmy\s+(?:pin|password|login)\b"
        r"|\btoken\s+approval\b|\bapprove\s+(?:the\s+|my\s+)?(?:digital\s+)?token\b"
        r"|\banydesk\b|\bteamviewer\b|\bscreen[- ]?shar(?:e|ing)\b|\bremote\s+(?:access|control)\b"
        r"|\binstall\s+(?:an?|the|this|their)\s+app\b|\bapk\b|\bplay\s+protect\b", re.I),
     "No real bank or official asks for your OTP, PIN or token approval, asks you to "
     "install an app, or asks to share your screen."),
    ("words_hide_from_bank", "refuse", re.compile(
        r"\b(?:don'?t|do\s+not|never|not\s+to)\s+tell\s+(?:the|my)\s+bank\b"
        r"|\bbank\s+(?:is|are)\s+in\s+on\s+it\b|\bkeep\s+(?:it|this)\s+from\s+(?:the|my)\s+bank\b"
        r"|\blie\s+to\s+the\s+bank\b", re.I),
     "You've been told not to tell the bank. Scammers say this so nobody can stop the "
     "payment — the bank is on your side."),
    # --- strong signs
    ("words_mule", "strong", re.compile(
        r"\breceive\s+(?:the\s+|some\s+)?(?:money|funds|payments?)\s+(?:and|then)\s+"
        r"(?:send|transfer|forward|pass|move)\b|\bforward\s+(?:the|this|that)\s+(?:money|funds|payment)\b"
        r"|\buse\s+my\s+(?:bank\s+)?account\s+(?:for|to\s+receive)\b"
        r"|\b(?:rent|sell|lend)\s+(?:out\s+)?my\s+(?:bank\s+)?account\b"
        r"|\bpass\s+(?:it|the\s+money)\s+on\b", re.I),
     "Receiving money and passing it on for someone is how scammers launder money. "
     "Your account is for your own use only — this can be a crime."),
    ("words_secrecy", "strong", re.compile(
        r"\b(don'?t|do not|never)\s+tell\b|\bkeep\s+(?:it|this)\s+(?:a\s+)?secret\b"
        r"|\bbetween\s+(?:you and me|us)\b|\bnobody\s+(?:can|must|should)\s+know\b"
        r"|\bnon[- ]disclosure\b|\bnda\b", re.I),
     "You've been asked to keep this secret. Scammers ask for secrecy so nobody "
     "can warn you."),
    ("words_directed", "strong", re.compile(
        r"\bdon'?t\s+hang\s+up\b|\bstill\s+on\s+the\s+(?:line|phone|call)\b"
        r"|\b(?:he|she|they)\s*(?:'s|'re|is|are)\s+(?:still\s+)?(?:on\s+the\s+(?:line|phone|call)"
        r"|waiting\s+for\s+me)\b|\btold\s+me\s+what\s+to\s+say\b", re.I),
     "Someone seems to be directing you right now. Hang up, then call your bank or "
     "1799 on a number you look up yourself."),
    ("words_new_number", "strong", re.compile(
        r"\bnew\s+(?:phone\s+)?number\b|\bchanged\s+(?:my|his|her|their)\s+number\b"
        r"|\blost\s+(?:my|his|her|their)\s+phone\b|\bphone\s+(?:is\s+)?broken\b"
        r"|\bguess\s+who\b", re.I),
     "A “new number” is the classic opening of family-impersonation scams. "
     "Call them on the number you already have to check it's really them."),
    ("words_online_contact", "strong", re.compile(
        r"\bonline\s+(?:friend|boyfriend|girlfriend|partner)\b|\bmet\s+(?:him|her|them)\s+online\b"
        r"|\bnever\s+met\s+(?:him|her|them)\b"
        r"|\b(?:boyfriend|girlfriend|fianc[eé]e?|partner)\s+(?:overseas|abroad)\b"
        r"|\bproof\s+of\s+(?:my|our)\s+love\b|\bdating\s+app\b", re.I),
     "You may only know this person online. Scammers build a relationship, then ask "
     "for money — check who they are before you pay."),
    ("words_investment", "strong", re.compile(
        r"\bguaranteed\b|\b(?:high|fixed|daily)\s+returns?\b|\bcrypto\b|\bbitcoin\b|\busdt\b"
        r"|\btrading\s+platform\b|\bdouble\s+(?:my|your)\s+money\b"
        r"|\b(?:withdrawal\s+fee|fee\s+to\s+withdraw|tax(?:es)?\s+to\s+withdraw)\b"
        r"|\brelease\s+(?:my\s+|the\s+)?profits?\b|\btrading\s+signals?\b"
        r"|\binvestment\s+(?:group|lessons?|class|community)\b", re.I),
     "It involves an investment promise. Guaranteed or unusually high returns, or a fee "
     "to withdraw your profits, are hallmarks of investment scams."),
    ("words_job_task", "strong", re.compile(
        r"\b(?:commission|part[- ]time\s+job|task\s+(?:job|fee)|top[- ]?up\s+to\s+earn)\b"
        r"|\bunlock\s+(?:the\s+|my\s+|more\s+)?tasks?\b|\bupgrade\s+my\s+account\b"
        r"|\brectify\s+(?:a|the|my)\s+mistake\b|\b(?:activation|training)\s+fee\b", re.I),
     "It sounds like a job that asks you to pay first. Real jobs don't make you "
     "transfer money to earn commission."),
    ("words_upfront_fee", "strong", re.compile(
        r"\b(?:processing|admin(?:istrative)?|release|clearance|handling)\s+fees?\b"
        r"|\bcustoms\s+(?:fee|charge|duty|tax)\b|\bre-?delivery\s+fee\b"
        r"|\bloan\s+(?:approval|activation|processing)\b"
        r"|\bclaim\s+(?:my|the)\s+(?:prize|reward|winnings)\b"
        r"|\bwon\s+(?:a|the)\s+(?:prize|lottery|lucky\s+draw)\b"
        r"|\brecover\s+my\s+(?:money|funds|losses)\b|\bfund\s+recovery\b", re.I),
     "You're being asked to pay a fee before you receive something (a loan, a prize, a "
     "parcel or lost money). Real ones don't work that way."),
    # --- mild signs
    ("words_urgency", "info", re.compile(
        r"\burgent(?:ly)?\b|\bright\s+now\b|\bimmediately\b|\basap\b"
        r"|\bas\s+soon\s+as\s+possible\b|\bbefore\s+it'?s\s+too\s+late\b", re.I),
     "The request sounds rushed. Scammers create time pressure so you don't stop "
     "to check."),
    ("words_parcel_refund", "info", re.compile(
        r"\b(?:parcel|customs|delivery\s+fee|refund|tax\s+rebate)\b", re.I),
     "It mentions a parcel, a fee or a refund — a common lure."),
]


def scam_words(text: str) -> list[Warning]:
    return [Warning(code, message, weight) for code, weight, pat, message in _WORDS
            if pat.search(text or "")]


# --------------------------------------------------------------------------- the LLM's view
_AI_TEXT = {
    "urgency": "The request sounds rushed.",
    "secrecy": "Someone wants this kept secret.",
    "impersonation_family": "It may be someone pretending to be family or a friend.",
    "impersonation_official": "It may be someone pretending to be an official or the bank.",
    "safe_account": "It looks like a “safe account” request.",
    "investment_promise": "It involves a promised investment return.",
    "job_or_task": "It looks like a pay-to-earn job.",
    "parcel_or_refund": "It mentions a parcel, fee or refund.",
    "romance": "It may be someone you've only met online.",
    "third_party_instructions": "Someone else seems to be telling you what to do.",
}


def ai_warnings(signals: list[str]) -> list[Warning]:
    """The LLM's signal codes, as fixed sentences. Unknown codes are dropped
    (the schema already refuses them; this is the belt to that brace)."""
    return [Warning("ai_" + s, "Scam check: " + _AI_TEXT[s], "ai")
            for s in dict.fromkeys(signals) if s in _AI_TEXT]


# --------------------------------------------------------------------------- the rules
def _display(cents: int) -> str:
    from backend.display import cents_to_display
    return "$" + cents_to_display(cents)


def rule_warnings(f: NewContactFacts) -> list[Warning]:
    out: list[Warning] = []
    if is_reported(f.phone):
        out.append(Warning("reported_number",
                           "This number has been reported for scams. Don't send money to it.",
                           "refuse"))
    same_name = [c for c in f.existing
                 if c["nickname"].strip().lower() == f.nickname.strip().lower()
                 and (c.get("phone") or "") != f.phone]
    if same_name:
        out.append(Warning(
            "name_clash",
            f"You already have a contact called {same_name[0]['nickname']} with a "
            "different number. Scammers pretend to be someone you know on a new "
            "number — call the number you already have to check.", "strong"))
    if f.added_last_24h >= RECENT_ADDS_LIMIT:
        out.append(Warning(
            "many_new_contacts",
            f"You've added {f.added_last_24h} new contacts in the last 24 hours. Paying "
            "several new people in a short time is a common scam pattern.", "strong"))
    if f.pending_cents is not None and f.pending_cents >= LARGE_PENDING_CENTS:
        out.append(Warning(
            "large_first_payment",
            f"You're about to send {_display(f.pending_cents)} to someone you've never "
            "paid before.", "strong"))
    elif f.for_payment:
        out.append(Warning(
            "new_for_payment",
            "You're adding them so you can pay them right away. Make sure you know "
            "who they are.", "info"))
    if not f.phone.startswith("+65 "):
        out.append(Warning("overseas_number",
                           "It's an overseas number. Most scam calls and messages come "
                           "from overseas numbers.", "info"))
    return out + scam_words(f.conversation)


def decide(f: NewContactFacts, *, ai_risk: str | None, ai_signals: list[str],
           hold_minutes: int) -> ContactDecision:
    """The rung for this contact. `ai_risk` is None when the LLM could not be
    asked; that counts as a reason for care, never as "low"."""
    rules = rule_warnings(f)
    ai = ai_risk if ai_risk in ("low", "medium", "high") else "unavailable"
    warnings = rules + ai_warnings(ai_signals if ai != "unavailable" else [])

    refuse = any(w.weight == "refuse" for w in rules) or (
        ai == "high" and any(w.code in _REFUSE_IF_AI_AGREES for w in rules))
    strong = sum(w.weight == "strong" for w in rules)
    info = sum(w.weight == "info" for w in rules)

    if refuse:
        rung = REFUSE
    elif strong or info >= 2 or ai == "high":
        rung = HOLD
    elif info or ai in ("medium", "unavailable"):
        rung = CODE
    else:
        rung = STANDARD
    return ContactDecision(rung=rung, warnings=tuple(warnings),
                           hold_minutes=hold_minutes if rung == HOLD else 0, ai_risk=ai)


def required_at_gateway(nickname: str, phone: str) -> str | None:
    """What the gateway re-derives from the payload alone, whatever the draft
    store says: a reported number is never added, however it was signed."""
    if is_reported(phone):
        return REPORTED_REASON
    return None
