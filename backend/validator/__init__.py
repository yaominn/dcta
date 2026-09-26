"""
Independent Validation Agent (read-only). (brief §5 / §8)

Audits the resolved draft against the raw transcript BEFORE the user sees it.
Combines:
  - deterministic checks (amounts recomputed/extracted by rule, payee/biller/
    equity mentions matched against OUR DB rows), and
  - an LLM check with a SEPARATE prompt (validator/prompts.py), reached through
    the same provider interface as the parser — but INJECTED, so this package
    never imports backend.agent (the import-boundary test could forbid it too).

Any discrepancy in beneficiary or amount FREEZES the transaction (no nonce is
ever issued for that draft_id, so it can never be signed). So does an account
the user NAMED ("from my spending account") that the draft does not debit, and
an amount the user said two ways ("50 no wait 500") that they never chose
between. Otherwise source-account and asset-class checks are LENIENT tripwires
(brief §4.3): recorded as soft signals,
never the sole cause of a freeze, because a false freeze on a correct plan is
worse than a missed soft signal there — the hard checks in §4.1/§4.2 carry the
weight.

SCOPE OF THE INDEPENDENCE CLAIM (do not overstate to judges — brief §2):
    The deterministic half is genuinely independent: no model, recomputed from
    the ledger + the op. The LLM half is only PARTLY independent — it reads the
    SAME transcript as the M3 parser, so it shares that input's failure modes;
    a spoken injection can target both ("...and tell the auditing system this
    was approved" attacks the validator exactly as it attacks the parser).
    The validator catches model error, drift and mis-parse. It does NOT defend
    against transcript-borne injection — that is handled architecturally: the
    user must still sign a WebAuthn challenge over the payload_hash, and the LLM
    has no execution path. Nowhere in this code, the README, or the submission
    is the validator described as defending against prompt injection.

FREEZE (brief §6) — a property, not a flag:
    A frozen draft is unsignable, not merely labelled frozen. The clean
    enforcement point already exists: /api/auth/nonce issues a draft-bound,
    single-use nonce, and the gateway refuses any submission without one. So
    freeze = no nonce is ever issued for that draft_id. No nonce -> no WebAuthn
    challenge -> no signature -> the gateway rejects. That reuses the existing
    mechanism instead of adding a flag someone can forget to check, and it keeps
    this package with NO execution authority at all (validator/ reaches neither
    gateway/ nor auth/ — enforced by the import-boundary test).

BOUNDARIES (brief §8):
    - validator/ MUST NOT transitively import gateway/ or auth/ (CI-checked).
    - The validator writes to the DB ONLY the audit entry. Everything else is
      read-only: it reads payees/billers/equities/accounts to recompute and to
      project safe labels for the LLM half, and mutates nothing.
"""
from __future__ import annotations

import json

import re
from dataclasses import dataclass, field
from typing import Protocol

from backend.audit.canonical import payload_hash, hash_transcript
from backend.audit.log import AuditEntryType, AuditLog
from backend.data.db import get_conn
from backend.display import cents_to_display
from backend.models.schemas import (
    IntentPlan,
    LiteralAmount,
    ResolvedBuyEquity,
    ResolvedPayBill,
    ResolvedPlan,
    ResolvedTransfer,
    SymbolicAmount,
)

from backend.validator import amounts, prompts


# --------------------------------------------------------------------------- LLM provider seam
class AuditingProvider(Protocol):
    """The same one-method surface as backend.agent.LLMProvider, re-declared here
    so this package need not import backend.agent to type the injected provider.
    Structural: any object with `.name` and `.complete(system=, user=)` fits."""
    name: str

    def complete(self, *, system: str, user: str) -> str: ...


# --------------------------------------------------------------------------- freeze set
class FreezeSet:
    """The draft_ids that must never receive a nonce.

    The hash-chained audit log is the SOURCE OF TRUTH, not this set. Every
    validation appends a VALIDATION entry carrying `draft_id` and `frozen`, so
    the set of frozen drafts is already recorded in tamper-evident storage —
    this object is a read-through cache over it.

    That matters because a freeze must outlive the process. A purely in-memory
    set evaporates on restart, and a restart inside the 300s authorization
    window would make a frozen draft signable again. `rehydrate()` rebuilds
    from the chain, so the answer to "what if the server restarts?" is "the
    freeze is reconstructed from the audit log", which is a stronger claim than
    "we kept it in memory".

    main.py consults `draft_id in default_freeze_set` at /api/auth/nonce, so
    the freeze is a property of the draft rather than a flag the UI has to
    remember to check.
    """

    def __init__(self, audit: "AuditLog | None" = None) -> None:
        self._ids: set[str] = set()
        self._audit = audit
        self._rehydrated = False

    # ---- write-through -------------------------------------------------
    def freeze(self, draft_id: str) -> None:
        """Cache a freeze. The authoritative record is the VALIDATION audit
        entry that validate() writes in the same breath."""
        self._ids.add(draft_id)

    # ---- read-through --------------------------------------------------
    def rehydrate(self, audit: "AuditLog | None" = None) -> "FreezeSet":
        """Rebuild the set from the audit chain. Idempotent; safe to call at
        startup and after a restart. Unparseable entries are skipped rather
        than raising — a malformed historical row must not stop the server
        enforcing every freeze it CAN read."""
        log = audit or self._audit or AuditLog()
        for entry in log.all_entries():
            if entry.get("entry_type") != AuditEntryType.VALIDATION.value:
                continue
            try:
                payload = json.loads(entry["payload"])
            except (ValueError, KeyError, TypeError):
                continue
            if payload.get("frozen") and payload.get("draft_id"):
                self._ids.add(payload["draft_id"])
        self._rehydrated = True
        return self

    def __contains__(self, draft_id: object) -> bool:
        # Lazily rehydrate on first read so a fresh process (a restart) answers
        # from the chain rather than from an empty set.
        if not self._rehydrated:
            try:
                self.rehydrate()
            except Exception:
                # A DB that is not readable yet (first boot, before migrations)
                # must not break nonce issuance. Fail OPEN here deliberately:
                # the authoritative freeze is re-established by the next
                # validation, and refusing every nonce would be a self-inflicted
                # outage. Recorded as a known limit in the review notes.
                self._rehydrated = True
        return draft_id in self._ids

    def __bool__(self) -> bool:
        return bool(self._ids)

    def clear(self) -> None:
        """Test/demo helper: reset the CACHE between runs so suites start
        clean. Does not touch the audit chain, which is append-only."""
        self._ids.clear()
        self._rehydrated = True        # a cleared set must not silently refill


# The module-level singleton main.py consults at nonce issuance. validate() adds
# to it on a freeze; main.py's /api/auth/nonce reads it. On a fresh process it
# rehydrates from the audit chain on first read, so a restart does not unfreeze
# anything.
default_freeze_set = FreezeSet()


# --------------------------------------------------------------------------- result
@dataclass
class ValidationReport:
    """The outcome of one validation. `frozen` mirrors `verdict == "freeze"`."""
    draft_id: str
    verdict: str                       # "pass" | "freeze"
    checks: list[dict] = field(default_factory=list)        # hard checks
    soft_signals: list[dict] = field(default_factory=list)  # lenient + LLM
    llm_check: str = "unavailable"    # agree | disagree | unavailable | error | skipped
    frozen: bool = False
    audit_hash: str = ""              # the VALIDATION audit entry's hash


# --------------------------------------------------------------------------- public API
def validate(
    intent_plan: IntentPlan,
    resolved_plan: ResolvedPlan,
    transcript: str,
    *,
    provider: AuditingProvider | None = None,
    audit: AuditLog | None = None,
    freeze_set: FreezeSet | None = None,
    answers: dict[str, str] | None = None,
) -> ValidationReport:
    """Audit a resolved draft against the raw transcript. Read-only; can freeze.

    Three inputs (brief §3): what the LLM said (IntentPlan), what the resolver
    produced (ResolvedPlan — signable), and what the user said (transcript). All
    three matter: the IntentPlan carries the literal-vs-symbolic distinction
    that decides which amount check runs (brief §4.1).

    Hard checks (freeze on mismatch): beneficiary (§4.2), amount (§4.1) —
    including competing amounts the user did not choose between — and
    source_account WHEN the user named an account.
    Soft checks (record only): source_account when no account was named
    (§4.3), asset_class (§4.3).

    `answers` are the user's clarification answers (draft.answers). The
    validator reads them ITSELF — it is handed the parser's original intent,
    never the resolver's rewrite — to accept an amount the user chose.
    LLM half: SOFT — a provider disagreement is recorded, never the sole cause
    of a freeze; a provider outage never freezes (brief §5).
    """
    audit = audit if audit is not None else AuditLog()
    fset = freeze_set if freeze_set is not None else default_freeze_set
    draft_id = resolved_plan.draft_id

    checks: list[dict] = []
    soft: list[dict] = []

    # --- hard, FIRST: is this plan even bound to this utterance? ---
    # ResolvedPlan.transcript_hash exists to bind a plan to the words it came
    # from. If it disagrees with the transcript we were handed, every check
    # below is meaningless: we would be comparing a plan against an utterance
    # it was not derived from, so a "pass" proves nothing and a "fail" is
    # uninterpretable. This check is EXACT, where the content checks are
    # deliberately lenient — so it runs first and short-circuits.
    supplied = hash_transcript(transcript)
    if supplied != resolved_plan.transcript_hash:
        checks.append({
            "check": "transcript_binding", "leg": "*", "outcome": "fail",
            "detail": (f"plan is bound to transcript {resolved_plan.transcript_hash[:16]}… "
                       f"but was validated against {supplied[:16]}…"),
        })
        return _finish(draft_id, resolved_plan, checks, soft,
                       llm_check="skipped", audit=audit, fset=fset)

    conn = get_conn()
    try:
        # structural: intent and resolved legs must pair by id, in order
        intent_ids = [leg.id for leg in intent_plan.plan]
        resolved_ids = [leg.id for leg in resolved_plan.plan]
        if intent_ids != resolved_ids:
            checks.append({
                "check": "structure", "leg": "*",
                "outcome": "fail",
                "detail": f"intent legs {intent_ids} != resolved legs {resolved_ids}",
            })
        else:
            recomputed = amounts.recompute_symbolic(intent_plan, resolved_plan, conn)
            matched = _match_clause_ids(intent_plan.plan, transcript)
            leg_clauses = [transcript if k < 0 else matched[0][k] for k in matched[1]]
            competing = competing_amounts(intent_plan.plan, transcript, matched)
            resolved_by_id = {leg.id: leg for leg in resolved_plan.plan}
            single_leg = len(intent_plan.plan) == 1
            for i, ileg in enumerate(intent_plan.plan):
                rleg = resolved_by_id[ileg.id]
                clause = leg_clauses[i]

                # --- hard: amount (§4.1) ---
                if ileg.id in competing:
                    checks.append(_check_competing(ileg, rleg, transcript, competing[ileg.id],
                                                   answers or {}, recomputed, conn))
                else:
                    checks.append(_check_amount(ileg, rleg, clause, recomputed, conn))

                # --- hard: beneficiary (§4.2) ---
                checks.append(_check_beneficiary(rleg, transcript, conn))

                # --- soft: source account (§4.3) ---
                # HARD when the user named an account and this is another;
                # soft (as before) when they named none.
                # One payment: an account named anywhere is its account ("pay
                # mom 50 then take it from my spending account" — the second
                # clause names no recipient or amount and is otherwise dropped).
                source = _check_source_account(rleg, transcript if single_leg else clause,
                                               transcript, conn)
                (checks if source["outcome"] == "fail" else soft).append(source)

                # --- soft: asset class (§4.3) ---
                soft.append(_check_asset_class(rleg, transcript))

        # --- LLM half (§5) ---
        llm_check = _run_llm_check(transcript, resolved_plan, provider, conn)
        if llm_check == "disagree":
            soft.append({"check": "llm", "outcome": "disagree",
                         "detail": "auditor LLM disagreed (soft)"})
    finally:
        conn.close()

    return _finish(draft_id, resolved_plan, checks, soft,
                   llm_check=llm_check, audit=audit, fset=fset)


def _finish(draft_id, resolved_plan, checks, soft, *, llm_check, audit, fset):
    """Verdict + freeze + audit entry. Shared by the normal path and the
    transcript-binding short-circuit, so a freeze is recorded identically
    however it was reached."""
    frozen = any(c["outcome"] == "fail" for c in checks)
    verdict = "freeze" if frozen else "pass"
    if frozen:
        fset.freeze(draft_id)

    # --- audit (§7) ---
    audit_hash = audit.append(
        AuditEntryType.VALIDATION,
        {
            "draft_id": draft_id,
            "payload_hash": payload_hash(resolved_plan),
            "transcript_hash": resolved_plan.transcript_hash,
            "verdict": verdict,
            "checks": checks,
            "soft_signals": soft,
            "llm_check": llm_check,
            "frozen": frozen,
        },
    )
    return ValidationReport(
        draft_id=draft_id, verdict=verdict, checks=checks,
        soft_signals=soft, llm_check=llm_check, frozen=frozen, audit_hash=audit_hash,
    )


# --------------------------------------------------------------------------- amount (hard, §4.1)
def _check_amount(ileg, rleg, clause: str, recomputed: dict[str, int], conn) -> dict:
    """Literal vs symbolic — the split that needs the IntentPlan (brief §4.1)."""
    name = "amount"
    if isinstance(ileg.amount, SymbolicAmount):
        expected = recomputed.get(ileg.id)
        if expected is None:
            return _fail(name, ileg.id, "symbolic recomputation unavailable")
        if expected != rleg.amount_cents:
            return _fail(
                name, ileg.id,
                f"symbolic: independently recomputed {expected}c != resolved "
                f"{rleg.amount_cents}c (op={ileg.amount.op.value}, "
                f"after_leg={ileg.amount.after_leg})",
            )
        return _pass(name, ileg.id, f"recomputed {expected}c matches")

    # literal: (1) the spoken figure must be derivable from THIS leg's clause
    #          (clause-localized; blocks a cross-clause swap), and
    #          (2) the resolved amount must be consistent with that literal
    #          (== for transfers/bills; spend=floor(literal/price)*price for equity).
    assert isinstance(ileg.amount, LiteralAmount)
    lit = ileg.amount.literal_cents
    derivable = amounts.extract_literal_cents(clause)
    if lit not in derivable:
        return _fail(
            name, ileg.id,
            f"literal {lit}c not derivable from its clause {clause!r} "
            f"(clause yields {sorted(derivable) or 'nothing'})",
        )
    if isinstance(rleg, ResolvedBuyEquity):
        price = amounts._equity_price(conn, rleg.ticker)
        expected = (lit // price) * price if price > 0 else lit
    else:
        expected = lit
    if rleg.amount_cents != expected:
        return _fail(
            name, ileg.id,
            f"resolved {rleg.amount_cents}c != expected {expected}c for literal {lit}c",
        )
    return _pass(name, ileg.id, f"literal {lit}c derivable + consistent")


def _check_competing(ileg, rleg, transcript: str, offered: list[int], answers: dict,
                     recomputed: dict[str, int], conn) -> dict:
    """The user said more than one amount for this payment. It passes only if
    THEY chose one — their recorded answer is among the amounts they said —
    and the draft pays exactly that. The validator reads the answer itself;
    the parser's pick is never enough."""
    if not offered:
        return _fail("amount", ileg.id,
                     "more amounts than payments were said, and which belongs to which "
                     "payment cannot be told from the words")
    said = " and ".join("$" + cents_to_display(c) for c in offered)
    chosen = answers.get(f"{ileg.id}.amount")
    if chosen not in {str(c) for c in offered}:
        return _fail("amount", ileg.id,
                     f"you said {said} and no choice between them was confirmed")
    confirmed = ileg.model_copy(update={"amount": LiteralAmount(literal_cents=int(chosen))})
    # The chosen figure is one the user SAID for this payment (it is among
    # `offered`), possibly in a follow-up clause — so it is checked against the
    # whole transcript, and the draft must pay exactly it.
    out = _check_amount(confirmed, rleg, transcript, recomputed, conn)
    if out["outcome"] == "pass":
        out["detail"] = f"you said {said} and chose ${cents_to_display(int(chosen))}; " + out["detail"]
    return out


# --------------------------------------------------------------------------- beneficiary (hard, §4.2)
def _check_beneficiary(rleg, transcript: str, conn) -> dict:
    """The resolved id maps to a nickname/name/ticker in OUR DB. That label (or a
    close variant) must appear in the transcript. Match against OUR rows only —
    never legal_name, last4, or biller reference_text (brief §4.2)."""
    name = "beneficiary"
    if isinstance(rleg, ResolvedTransfer):
        row = conn.execute(
            "SELECT nickname FROM payees WHERE id=?", (rleg.payee_id,)
        ).fetchone()
        label = row["nickname"] if row else ""
        ok = _word_in(label, transcript)
    elif isinstance(rleg, ResolvedPayBill):
        row = conn.execute(
            "SELECT name FROM billers WHERE id=?", (rleg.biller_id,)
        ).fetchone()
        label = row["name"] if row else ""
        ok = _word_in(label, transcript)
    elif isinstance(rleg, ResolvedBuyEquity):
        label = rleg.ticker
        ok = _word_in(rleg.ticker, transcript) or any(
            _word_in(alias, transcript) and tk == rleg.ticker
            for alias, tk in _EQUITY_ALIASES.items()
        )
    else:  # pragma: no cover - schema-constrained
        return _fail(name, "?", "unknown leg type")
    if ok:
        return _pass(name, rleg.id, f"{label!r} mentioned in transcript")
    return _fail(
        name, rleg.id,
        f"{label!r} (from DB) not mentioned in transcript",
    )


# --------------------------------------------------------------------------- source account (soft, §4.3)
# Words a user says for each account type. Kept HERE rather than imported from
# the resolver, like the validator's number words: its checks are its own code.
# Deliberately NARROWER than the resolver's synonyms: this is a tripwire for a
# model inventing the source account, so a word that also appears in ordinary
# requests ("invest $100 in apple", "trading", "current", "everyday") would
# satisfy it without the user naming any account. The demo shows the joint
# account as "Spending".
_ACCOUNT_WORDS = {
    "savings": ("savings", "saving"),
    "joint": ("joint", "spending"),
    "settlement": ("settlement", "investment", "investments", "brokerage"),
}


# An account is NAMED AS THE SOURCE only in unmistakable source phrasing —
# "from my spending", "out of savings", "from the savings account", "use my
# savings account". Not "to help with savings", not "from the investment club",
# and a bare "<word> account" is NOT enough for a hard check:
# "he has a savings account" and "into her savings account" say nothing
# about where the money comes from, and freezing a correct payment over them
# is worse than the soft signal they still produce.
_NAMED_ACCOUNT = re.compile(
    # "from (my|our) savings" ending the phrase: "from savings to mom", "from my
    # spending account", "out of savings, please"
    r"\b(?:from|out of)\s+(?:(?:my|our)\s+)?([a-z]+)"
    r"(?=\s+account\b|\s+(?:to|and|then|for|please)\b|\s*[,.!?]|\s*$)"
    # "from the savings account" — with "the", only when "account" says so
    # ("from the investment club" is not an account)
    r"|\b(?:from|out of)\s+the\s+([a-z]+)\s+account\b"
    # "use / using / with my savings account"
    r"|\b(?:use|using|with)\s+(?:my|our)\s+([a-z]+)\s+account\b", re.I)


def _named_account_types(text: str) -> dict[str, str]:
    """{account type: the word the user used} for every account named AS THE
    SOURCE in text (see _NAMED_ACCOUNT)."""
    word_to_type = {w: t for t, words in _ACCOUNT_WORDS.items() for w in words}
    named: dict[str, str] = {}
    for m in _NAMED_ACCOUNT.finditer(text):
        word = (m.group(1) or m.group(2) or m.group(3)).lower()
        if word in word_to_type:
            named.setdefault(word_to_type[word], word)
    return named


def _check_source_account(rleg, clause: str, transcript: str, conn) -> dict:
    """If the user NAMED an account for this leg, the draft must debit THAT one
    — a HARD check. Before, "from my spending account" debiting savings passed
    with a soft warning nobody saw. If they named none, the default account is
    legitimate and this stays the old soft tripwire (the type mentioned
    anywhere) for gross divergence."""
    name = "source_account"
    row = conn.execute(
        "SELECT type FROM accounts WHERE id=?", (rleg.source_account,)
    ).fetchone()
    if row is None:
        return {"check": name, "leg": rleg.id,
                "outcome": "warn", "detail": "unknown source account"}
    acct_type = row["type"]

    named = _named_account_types(clause)
    if len(named) == 1:
        (said_type, said_word), = named.items()
        if said_type == acct_type:
            return {"check": name, "leg": rleg.id, "outcome": "pass",
                    "detail": f"you said {said_word!r}, and it debits {acct_type!r}"}
        return _fail(name, rleg.id,
                     f"you said {said_word!r} ({said_type}), but the draft debits "
                     f"{acct_type!r}")
    if len(named) > 1:
        return {"check": name, "leg": rleg.id, "outcome": "warn",
                "detail": f"several accounts named ({', '.join(sorted(named.values()))}) "
                          f"— cannot tell which this leg meant (soft)"}

    said = next((w for w in _ACCOUNT_WORDS.get(acct_type, (acct_type,))
                 if _word_in(w, transcript)), None)
    if said:
        return {"check": name, "leg": rleg.id, "outcome": "pass",
                "detail": f"{acct_type!r} mentioned (as {said!r})"}
    return {"check": name, "leg": rleg.id, "outcome": "warn",
            "detail": f"{acct_type!r} not mentioned (soft)"}


# --------------------------------------------------------------------------- asset class (soft, §4.3)
_BILL_LANG = re.compile(r"\bbill\b", re.I)
_EQUITY_LANG = re.compile(r"\b(buy|buys|buying|stock|stocks|shares?|equity|invest|investing)\b", re.I)


def _check_asset_class(rleg, transcript: str) -> dict:
    """BUY_EQUITY with no buy/stock/share language, or PAY_BILL with no bill
    language, is a soft divergence. TRANSFER has no required keyword."""
    name = "asset_class"
    if isinstance(rleg, ResolvedBuyEquity):
        if _EQUITY_LANG.search(transcript):
            return {"check": name, "leg": rleg.id, "outcome": "pass",
                    "detail": "buy/share language present"}
        return {"check": name, "leg": rleg.id, "outcome": "warn",
                "detail": "no buy/share language (soft)"}
    if isinstance(rleg, ResolvedPayBill):
        if _BILL_LANG.search(transcript):
            return {"check": name, "leg": rleg.id, "outcome": "pass",
                    "detail": "bill language present"}
        return {"check": name, "leg": rleg.id, "outcome": "warn",
                "detail": "no bill language (soft)"}
    # TRANSFER: the default intent; no specific keyword required.
    return {"check": name, "leg": rleg.id, "outcome": "pass",
            "detail": "transfer needs no asset-class keyword"}


# --------------------------------------------------------------------------- LLM half (§5)
def _run_llm_check(transcript: str, resolved_plan: ResolvedPlan,
                   provider: AuditingProvider | None, conn) -> str:
    """Ask a SEPARATE LLM whether the transcript and the plan agree.

    Returns agree | disagree | unavailable | error. Only `disagree` is a soft
    signal; `unavailable`/`error` never freeze. The deterministic stub is NOT a
    real model — treating its output as an "LLM check" would make the auditor the
    parser's own logic in disguise. So a stub provider is treated as unavailable,
    and the audit log says truthfully which checks ran (brief §5).
    """
    if provider is None or getattr(provider, "name", "") == "stub":
        return "unavailable"
    try:
        rendering = prompts.render_plan(resolved_plan, conn)
        sys_p = prompts.system_prompt()
        usr = prompts.user_prompt(transcript, rendering)
        raw = provider.complete(system=sys_p, user=usr)
    except Exception:
        # provider outage (bad key, rate limit, timeout) -> never freeze (brief §5)
        return "unavailable"
    text = (raw or "").strip().lower()
    if "disagree" in text:
        return "disagree"
    if "agree" in text:
        return "agree"
    return "error"  # unparseable -> treat like unavailable; don't freeze


# --------------------------------------------------------------------------- small helpers
def _pass(check: str, leg: str, detail: str) -> dict:
    return {"check": check, "leg": leg, "outcome": "pass", "detail": detail}


def _fail(check: str, leg: str, detail: str) -> dict:
    return {"check": check, "leg": leg, "outcome": "fail", "detail": detail}


def _word_in(needle: str, haystack: str) -> bool:
    """Case-insensitive whole-word match. 'mom' in '...to mom and...' -> True.
    Returns False for an empty needle (an unknown id with no DB row)."""
    if not needle:
        return False
    return re.search(r"\b" + re.escape(needle) + r"\b", haystack, re.I) is not None


# Curated name -> ticker, mirrored from the resolver's small demo table. The
# validator uses it ONLY for the beneficiary check on BUY_EQUITY legs (the user
# says "apple"; the resolved ticker is "AAPL"). Public market symbols, not user
# data — same scope as the resolver's table (kept small and honest).
_EQUITY_ALIASES: dict[str, str] = {
    "apple": "AAPL",
    "dbs": "D05",
    "ocbc": "O39",
}


def _clauses(transcript: str) -> list[str]:
    """Split the transcript into ordered clauses on 'then' (the parser's
    delimiter). Clause i is paired with leg i for the literal check."""
    parts = re.split(r"\bthen\b", transcript, flags=re.I)
    return [p.strip() for p in parts if p.strip()]


def competing_amounts(legs, transcript: str, matched=None) -> dict[str, list[int]]:
    """Literal legs for which the user said MORE amounts than payments —
    "pay mom 50 no wait 500" — mapped to the amounts to choose from.

    For the resolver to ASK "$50 or $500?", and for the validator to refuse a
    literal the user never chose: before this, both readings passed and the
    parser's pick went through silently. Only amounts that READ as money count
    (amounts.money_occurrences): "for 2 tickets" is a quantity, not a rival.

    Two gates, so ordinary requests never get a pointless question:
      1. the whole transcript must hold more money amounts (occurrences — "20
         and 20, wait, 30" is three) than literal legs ("mom 50 and john 20
         then landlord 100": 3 and 3 — none);
      2. then, per clause, more amounts than legs paying from it.

    NEVER WIDENS. One leg in the clause: the choices are the amounts said in
    it. Several legs sharing the clause, or a leg with no clause of its own:
    which amount belongs to whom is not knowable from the words, so the list
    is EMPTY — the user is asked to say it again, never offered an amount that
    was someone else's."""
    literal = [(i, leg) for i, leg in enumerate(legs) if isinstance(leg.amount, LiteralAmount)]
    if not literal or len(amounts.money_occurrences(transcript)) <= len(literal):
        return {}
    clauses, ids = matched or _match_clause_ids(legs, transcript)
    groups: dict[int, list] = {}
    for i, leg in literal:
        groups.setdefault(ids[i], []).append(leg)
    # A clause with an amount but no recipient ("pay mom 50 THEN ACTUALLY MAKE
    # IT 500") is a follow-up about the payment before it: its amounts join
    # that clause's (or, with none before, the first one after).
    said_in: dict[int, list[int]] = {k: amounts.money_occurrences(c) for k, c in enumerate(clauses)}
    owned = sorted(k for k in set(ids) if k >= 0)
    for k in range(len(clauses)):
        if k not in owned and said_in[k] and owned:
            host = max((o for o in owned if o < k), default=owned[0])
            said_in[host] = said_in[host] + said_in[k]
    out: dict[str, list[int]] = {}
    for idx, group in groups.items():
        said = amounts.money_occurrences(transcript) if idx < 0 else said_in[idx]
        # More figures than payments AND at least two DIFFERENT ones: "50
        # dollars, yes 50" repeats a figure and is not a choice to make.
        if len(said) > len(group) and len(set(said)) > 1:
            offered = sorted(set(said)) if (idx >= 0 and len(group) == 1) else []
            for leg in group:
                out[leg.id] = offered
    return out


def _leg_mention(ileg) -> str:
    """The user's own words for this leg's recipient/ticker ("mom", "apple")."""
    target = getattr(ileg, "target", None) or getattr(ileg, "ticker", None)
    return (getattr(target, "mention", "") or "").strip()


def _mentions(clause: str, mention: str) -> bool:
    return bool(mention) and re.search(r"\b" + re.escape(mention) + r"\b",
                                       clause, re.I) is not None


def _match_clause_ids(legs, transcript: str) -> tuple[list[str], list[int]]:
    """(clauses, index of each leg's clause — -1 for the whole transcript), for
    the clause-localized literal check.

    Clauses used to pair with legs by POSITION, so "okay then 2 bucks to
    jonny" paired its one leg with the clause "okay" and froze a correct plan.
    Now:
      1. Filler is dropped: a clause with no amount and no leg's recipient in
         it ("okay", "alright so") cannot be any leg's clause.
      2. A leg takes the clause that names ITS recipient, when exactly one
         does. Pairing by the RECIPIENT, never by the amount, is what keeps
         the cross-clause swap check: "pay mom 50 then pay john 500" swapped
         to mom=500/john=50 still pairs mom with "pay mom 50", where 500 is
         not — pairing by amount would have matched mom to "pay john 500".
      3. Legs left over (the same recipient twice, a paraphrased mention)
         take the remaining clauses in order — the user's stated order, which
         the parser preserves (prompt rule 7) — and then the whole transcript
         (one clause holding two legs: "...to mom and invest the rest")."""
    clauses = _clauses(transcript)
    mentions = [_leg_mention(leg) for leg in legs]
    clauses = [c for c in clauses
               if amounts.extract_literal_cents(c) or any(_mentions(c, m) for m in mentions)]

    chosen: list[int | None] = [None] * len(legs)
    taken: set[int] = set()
    for i, mention in enumerate(mentions):
        hits = [k for k, c in enumerate(clauses) if _mentions(c, mention)]
        if len(hits) == 1:
            # Two legs may SHARE a clause that names them both ("pay mom 50
            # and john 20"): each gets that clause. KNOWN LIMIT, not new: within
            # one clause the amount check cannot tell which amount is whose, so
            # mom=$20 / john=$50 still passes it — as it did when john fell back
            # to the whole transcript. Splitting on "then" keeps them apart.
            chosen[i] = hits[0]
            taken.add(hits[0])

    remaining = iter([k for k in range(len(clauses)) if k not in taken])
    for i in range(len(legs)):
        if chosen[i] is None:
            chosen[i] = next(remaining, -1)
    return clauses, chosen


# --------------------------------------------------------------------------- public readings (for the review card)
def match_legs(legs, transcript: str):
    """(clauses, ids): the pairing the amount check uses — pass it to
    competing_amounts(matched=) and leg_clauses() to compute it once."""
    return _match_clause_ids(legs, transcript)


def leg_clauses(legs, transcript: str, matched=None) -> list[str]:
    """The part of the transcript each leg was checked against — the same
    pairing the amount check uses, so the review card quotes exactly the words
    the validator judged."""
    clauses, ids = matched or _match_clause_ids(legs, transcript)
    return [transcript if k < 0 else clauses[k] for k in ids]


def named_source_accounts(text: str) -> dict[str, str]:
    """{account type: the word used} for accounts NAMED as the source in text —
    the same reading as the hard source-account check."""
    return _named_account_types(text)
