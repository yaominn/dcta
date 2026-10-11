"""
What the assistant SAYS about a draft, and where each field came from.

Two outputs for a ready payment draft:

  reply     — a conversational message: the payment, plus what the assistant
              worked out that the user did not say (how it compares with what
              they usually send this person, what's left afterwards, which
              account was defaulted, what a calculated amount came to, why an
              extra check is needed).
  evidence  — per leg, where each field came from: a QUOTE of the user's own
              words, "calculated", "chosen", or "default".

NOT an LLM. This text sits beside the card the user approves, so it must never
be able to disagree with it: an LLM reply could be steered by injected text
(the booby-trapped biller in the red-team demo) into "don't worry, it's only
$5" while the card says $5,000. Every number and name here comes from the
resolved plan, the ledger, or the transcript — the same checked data as the
card — in short, direct sentences.

Quotes are cut from the TRANSCRIPT, not from the parser's IntentPlan: the
parser's "mention" is its claim about what the user said; the transcript is
what they said. A field whose words cannot be found is reported as such,
never papered over.

Cosmetic by nature: the pipeline treats a failure here as "no narration", never
as a failed draft (see main._pipeline).
"""
from __future__ import annotations

import re

from backend.display import account_label, cents_to_display
from backend.models.schemas import IntentPlan, ResolvedPlan, SymbolicAmount
from backend.policy.engine import ANOMALY_MULTIPLE, _median_cents
from backend.resolver import ACCOUNT_TYPE_SYNONYMS, names_an_account
from backend.validator import (competing_amounts, leg_clauses, match_legs,
                               named_source_accounts)
from backend.validator.amounts import extract_amounts

_COUNT = {2: "Two", 3: "Three", 4: "Four", 5: "Five"}


def _money(cents: int) -> str:
    return "$" + cents_to_display(cents)


def _name(display: str) -> str:
    """"Mom ··3310" -> "Mom": the person, for conversation."""
    return display.split(" ··")[0].strip() or display


def _quote(text: str, words: str | None) -> str | None:
    """The user's own words for `words` in `text`, in their casing — or None."""
    if not words:
        return None
    m = re.search(r"\b" + re.escape(words) + r"\b", text, re.I)
    return m.group(0) if m else None


def _recipient(ileg, rleg) -> tuple[str, str | None]:
    """(what to call it, the parser's mention of it)."""
    if rleg.type == "TRANSFER":
        return _name(rleg.payee_display), ileg.target.mention
    if rleg.type == "PAY_BILL":
        return rleg.biller_display, ileg.target.mention
    return rleg.ticker, ileg.ticker.mention


def _source_evidence(ileg, text: str, account_type: str | None) -> dict:
    """Named (with the user's word) or defaulted — by the RESOLVER's own rule
    on the parser's mention, not by re-guessing from phrasing. The quote is the
    word for THIS leg's account; if the user named several ("from savings, no,
    from spending"), it is the one that matches the account debited."""
    if isinstance(ileg.amount, SymbolicAmount):
        return {"kind": "derived", "text": "same account as the payment before"}
    mention = ileg.source_account.mention
    if not names_an_account(mention):
        return {"kind": "default"}
    named = named_source_accounts(text)
    if account_type and account_type in named:
        return {"kind": "said", "quote": named[account_type]}
    words = [w for w, t in ACCOUNT_TYPE_SYNONYMS.items() if t == account_type]
    quote = next((q for q in (_quote(text, w) for w in words + [account_type, mention]) if q), None)
    return {"kind": "said", "quote": quote} if quote else {"kind": "not_found"}


def narrate(intent: IntentPlan, resolved: ResolvedPlan, transcript: str, *,
            accounts: dict[str, dict], history: list[dict],
            answers: dict[str, str] | None = None,
            extra_check: bool = False, hold_seconds: int | None = None,
            new_destination_legs: frozenset[str] = frozenset()) -> dict:
    """The assistant's reply and per-leg evidence for a READY payment draft.

    accounts: account id -> {"type", "balance"} BEFORE this plan (the ledger).
    history:  the user's past payments ({payee_id, amount}), for "usual".
    new_destination_legs: every transfer leg to a destination never paid before
              (a new payee, or one paid before at a different number).
    """
    answers = answers or {}
    matched = match_legs(intent.plan, transcript)
    clauses = leg_clauses(intent.plan, transcript, matched)
    competing = competing_amounts(intent.plan, transcript, matched)
    single = len(intent.plan) == 1
    resolved_by_id = {leg.id: leg for leg in resolved.plan}
    after = {a: row["balance"] for a, row in accounts.items()}

    evidence: dict[str, dict] = {}
    phrases: list[str] = []
    notes: list[str] = []          # what the assistant knows about each payment
    defaults: list[str] = []       # what it filled in — said after, so it reads naturally
    for i, ileg in enumerate(intent.plan):
        rleg = resolved_by_id[ileg.id]
        clause = clauses[i]
        acct = account_label(rleg.source_account)
        after[rleg.source_account] = after.get(rleg.source_account, 0) - rleg.amount_cents
        who, mention = _recipient(ileg, rleg)

        # --- amount: said, chosen, or calculated
        if isinstance(ileg.amount, SymbolicAmount):
            what = "the rest" if ileg.amount.op.value == "ALL" else "half"
            base = resolved_by_id.get(ileg.amount.after_leg)
            src = account_label(base.source_account) if base else acct
            amount_ev = {"kind": "calculated", "text": f"{what} of what's left in {src}"}
            notes.append(f"{_money(rleg.amount_cents)} is {what} of {src}.")
        else:
            chosen = answers.get(f"{ileg.id}.amount")
            is_chosen = ileg.id in competing and chosen in {str(c) for c in competing[ileg.id]}
            said = int(chosen) if is_chosen else ileg.amount.literal_cents
            quote = next((clause[a.start:a.end].strip() for a in extract_amounts(clause)
                          if a.cents == said), None)
            if is_chosen:
                amount_ev = {"kind": "chosen", "quote": quote,
                             "text": "you chose it from " + " or ".join(
                                 _money(c) for c in competing[ileg.id])}
                others = [_money(c) for c in competing[ileg.id] if c != rleg.amount_cents]
                notes.append(f"You chose {_money(rleg.amount_cents)} over {' and '.join(others)}.")
            elif quote:
                amount_ev = {"kind": "said", "quote": quote}
            else:
                amount_ev = {"kind": "not_found"}

        # --- recipient: the user's words for it, from the transcript
        to_quote = _quote(clause, mention) or _quote(clause, who)
        to_ev = {"kind": "said", "quote": to_quote} if to_quote else {"kind": "not_found"}

        # --- source account
        acct_type = (accounts.get(rleg.source_account) or {}).get("type")
        from_ev = _source_evidence(ileg, transcript if single else clause, acct_type)
        if from_ev["kind"] == "default":
            # There is no "amend by voice": the way to change it is Cancel and
            # ask again — so that is what the reply says.
            note = f"No account named, so I used {acct} — cancel to change."
            if note not in defaults:
                defaults.append(note)

        evidence[ileg.id] = {"amount": amount_ev, "to": to_ev, "from": from_ev}

        # --- the phrase for this leg, and what the assistant knows about it
        if rleg.type == "BUY_EQUITY":
            phrases.append(f"about {rleg.estimated_shares} {who} shares at "
                           f"{_money(rleg.estimated_fill_price_cents)} — "
                           f"{_money(rleg.amount_cents)} from {acct}")
            continue
        phrases.append(f"{_money(rleg.amount_cents)} to {who} from {acct}")
        if rleg.type != "TRANSFER":
            continue
        # The policy engine's own median and threshold, so "N× usual" in the
        # reply is exactly the fact that triggers (or doesn't) the extra check.
        usual = _median_cents([int(h["amount"]) for h in history
                               if h.get("payee_id") == rleg.payee_id])
        if usual is None:
            notes.append(f"First payment to {who}.")
        elif rleg.id in new_destination_legs:
            # Paid before, but never at this number. "In line with what you
            # usually send" would vouch for the very payment the scam warning
            # is about — the new-number scam.
            notes.append(f"First payment to {who} at this number.")
            if usual > 0 and rleg.amount_cents >= usual * ANOMALY_MULTIPLE:
                notes.append(f"Far more than your usual {_money(usual)} to {who}.")
        elif usual <= 0:
            pass                                   # no meaningful comparison
        elif rleg.amount_cents >= usual * ANOMALY_MULTIPLE:
            notes.append(f"About {rleg.amount_cents // usual}× your usual {_money(usual)} to {who}.")
        elif rleg.amount_cents >= usual * 2:
            notes.append(f"More than your usual {_money(usual)} to {who}.")
        elif rleg.amount_cents * 2 <= usual:
            notes.append(f"Less than your usual {_money(usual)} to {who}.")
        else:
            notes.append(f"Your usual amount for {who}.")

    head = (f"{phrases[0]}." if single else
            f"{_COUNT.get(len(phrases), len(phrases))} payments: "
            + "; then ".join(phrases) + ".")
    notes.extend(defaults)
    touched = list(dict.fromkeys(leg.source_account for leg in resolved.plan))
    left = " and ".join(f"{_money(after[a])} in {account_label(a)}" for a in touched)
    notes.append(f"Leaves {left}.")
    if hold_seconds:
        notes.append(f"On hold for {hold_seconds} seconds — cancel any time.")
    if extra_check:
        notes.append("I've texted you a code.")
    return {"reply": " ".join([head] + notes), "evidence": evidence}
