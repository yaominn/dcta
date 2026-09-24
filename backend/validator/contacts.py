"""
Independent validation of a contact change. (Same role as validate(), M6.)

Read-only. Recomputes, from the transcript and OUR DB, what the resolver
claims, and freezes the draft (no nonce -> unsignable) on any mismatch:

  - transcript binding   the change was derived from THIS utterance
  - target               the payee being edited is one the user named (their
                         current nickname is in the transcript) or picked from
                         a clarifying question
  - new value            the new name / number is actually in what the user
                         said — a compromised resolver (or model) cannot swap
                         Mom's new number for an attacker's

Deliberately does NOT reuse the resolver's normaliser: an independent check
that calls the code it is checking is not independent. It has its own, simpler
digit extraction.
"""
from __future__ import annotations

import re

from backend.audit.canonical import hash_transcript
from backend.audit.log import AuditLog
from backend.data.db import connect, get_conn
from backend.models.contacts import ContactEditPlan, ResolvedContactChange
from backend.validator import (FreezeSet, ValidationReport, _fail, _finish, _pass,
                               _word_in, default_freeze_set)

_WORD_DIGITS = {"zero": "0", "oh": "0", "o": "0", "one": "1", "two": "2", "three": "3",
                "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8",
                "nine": "9"}


def _digit_stream(text: str) -> str:
    """Every digit the user said, in order, spoken or typed."""
    out, mult = [], 1
    for tok in re.findall(r"\d|[a-z]+", text.lower()):
        if tok in ("double", "triple"):
            mult = 2 if tok == "double" else 3
            continue
        d = tok if tok.isdigit() else _WORD_DIGITS.get(tok)
        if d is not None:
            out.append(d * mult)
        mult = 1
    return "".join(out)


def validate_contact_change(intent: ContactEditPlan, change: ResolvedContactChange,
                            transcript: str, *, answers: dict[str, str] | None = None,
                            audit: AuditLog, freeze_set: FreezeSet | None = None,
                            db_path=None) -> ValidationReport:
    fset = freeze_set if freeze_set is not None else default_freeze_set
    answered_ids = set((answers or {}).values())
    checks: list[dict] = []

    if hash_transcript(transcript) != change.transcript_hash:
        checks.append(_fail("transcript_binding", "*",
                            "the change is not bound to this transcript"))
        return _finish(change.draft_id, change, checks, [], llm_check="skipped",
                       audit=audit, fset=fset)
    checks.append(_pass("transcript_binding", "*", "bound to this transcript"))
    if len(intent.edits) != len(change.edits):
        checks.append(_fail("edit_count", "*",
                            f"{len(intent.edits)} edit(s) asked for, "
                            f"{len(change.edits)} drafted"))

    digits_said = _digit_stream(transcript)
    conn = connect(db_path) if db_path else get_conn()
    try:
        for i, e in enumerate(change.edits, start=1):
            leg = f"e{i}"
            row = conn.execute("SELECT nickname FROM payees WHERE id=?", (e.payee_id,)).fetchone()
            nickname = row["nickname"] if row else ""
            if _word_in(nickname, transcript) or e.payee_id in answered_ids:
                checks.append(_pass("target", leg, f"{nickname!r} was named or chosen"))
            else:
                checks.append(_fail("target", leg,
                                    f"{nickname or e.payee_id!r} was neither named nor chosen"))

            if e.field == "phone":
                national = re.sub(r"\D", "", e.new_value)
                if e.new_value.startswith("+65 "):
                    national = national[2:]
                ok = bool(national) and national in digits_said
                detail = f"number {e.new_value} {'is' if ok else 'is NOT'} in what was said"
            else:
                ok = _word_in(" ".join(e.new_value.split()), " ".join(transcript.split()))
                detail = f"name {e.new_value!r} {'is' if ok else 'is NOT'} in what was said"
            checks.append((_pass if ok else _fail)("new_value", leg, detail))
    finally:
        conn.close()

    return _finish(change.draft_id, change, checks, [], llm_check="skipped",
                   audit=audit, fset=fset)
