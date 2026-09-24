"""
Opaque-ID prompt context — the sanitizer. (brief 4.3, layer 2)

Two classes of untrusted input, never to be conflated:

  - USER SPEECH (the transcript) — untrusted but *authorized*. The user says
    "mom", not payee_17, so it cannot be ID-ified. It enters the prompt as-is
    and is defended by schema-constrained output (layer 3).
  - STORED THIRD-PARTY DATA — payee legal names, account last4s, biller
    reference text. Untrusted *and unauthorized*. An attacker who poisons a
    biller reference must never reach the model. This module is the ONLY
    sanctioned path from stored rows to prompt context, and it drops those
    fields by construction (it never copies them).

What the LLM is allowed to ground on (brief Section 7 note):

  - payees:   {id, nickname}   — the user's OWN nickname is what they'd say
  - billers:  {id, name}       — the display handle; reference_text is dropped
  - accounts: [type, ...]      — vocabulary only: no ids, no balances
  - equities: [ticker, ...]    — public market symbols, not user data

Everything else (legal_name, last4, reference_text, account ids/aliases,
balances) stays server-side for the resolver (M4).

The injection tripwire (layer 4) scans the stored fields we are about to
drop and returns flags for logging. It is documented as the WEAKEST layer:
it protects nothing by itself — the fields never reach the prompt regardless
— it exists so an injection attempt is NOTICED and auditable.

Pure functions, DB-free: main.py fetches rows and passes plain dicts in, so
this module is trivially testable and backend/agent/ stays import-light.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


# --------------------------------------------------------------------------- tripwire (layer 4 — weakest)
# Patterns that mark a stored field as an attempted prompt injection. Kept
# deliberately small and obvious; this is a tripwire for the audit log, not a
# boundary (the boundary is that the field never enters the prompt at all).
_INJECTION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("instruction-override", re.compile(
        r"\b(ignore|disregard|forget)\b[^.]{0,40}\b(instructions?|rules?|prompt)\b", re.I)),
    ("role-hijack", re.compile(
        r"\b(you are now|act as|system prompt|new persona|developer mode)\b", re.I)),
    ("money-movement", re.compile(
        r"\b(transfer|send|wire|pay)\b[^.]{0,30}\$\s*[\d,]", re.I)),
]


def scan_stored_text(text: str) -> list[str]:
    """Return the labels of any injection patterns found in a stored field."""
    return [label for label, pat in _INJECTION_PATTERNS if pat.search(text)]


# --------------------------------------------------------------------------- prompt context
@dataclass
class PromptContext:
    """The ONLY stored-data view the LLM ever sees. Serializing this (and the
    prompts built from it) must never leak a dropped field — the M3 tests pin
    that property against the seeded injection row."""
    payees: list[dict] = field(default_factory=list)        # [{id, nickname}]
    billers: list[dict] = field(default_factory=list)       # [{id, name}]
    account_types: list[str] = field(default_factory=list)  # ["savings", ...]
    tickers: list[str] = field(default_factory=list)        # ["AAPL", ...]
    flags: list[str] = field(default_factory=list)          # tripwire hits, for logging

    def to_prompt_json(self) -> dict:
        """The exact structure embedded in the user prompt. Keep keys stable —
        the stub provider (and the tests) read this back out of the prompt."""
        return {
            "payees": self.payees,
            "billers": self.billers,
            "account_types": self.account_types,
            "equities": self.tickers,
        }


def build_context(*, payees: list[dict], billers: list[dict],
                  accounts: list[dict], equities: list[dict]) -> PromptContext:
    """Project raw DB rows into the opaque-ID prompt view.

    Each projection copies ONLY the sanctioned fields — an attacker-controlled
    value cannot ride along inside a row we were handed, because we never copy
    the row. Tripwire flags name the row id + pattern label, e.g.
    "biller_07:instruction-override".
    """
    ctx = PromptContext()

    for p in payees:
        ctx.payees.append({"id": p["id"], "nickname": p["nickname"]})

    for b in billers:
        ctx.billers.append({"id": b["id"], "name": b["name"]})
        # reference_text is the classic poisoned field (seeded biller_07); the
        # biller display name is stored third-party data too — scan both.
        for field_name in ("reference_text", "name"):
            value = b.get(field_name) or ""
            for label in scan_stored_text(value):
                ctx.flags.append(f"{b['id']}:{field_name}:{label}")

    for a in accounts:
        t = a["type"]
        if t not in ctx.account_types:
            ctx.account_types.append(t)

    for e in equities:
        ctx.tickers.append(e["ticker"])

    return ctx
