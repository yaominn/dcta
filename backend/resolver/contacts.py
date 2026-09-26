"""
Deterministic resolution of a contact edit. (Same rules as payments, M4.)

ContactEditPlan (mentions + the user's words) -> ResolvedContactChange
(concrete payee ids, validated + normalised values), or one Clarify question.

  - WHO: the payee mention goes through the SAME 0 / 1 / 2+ matcher payments
    use (_pick / _match), so "rename John" asks which John, and an answer can
    only name a row the mention justifies.
  - WHAT: the new value is validated here, by rule, never trusted from the
    model. A phone number must normalise to a real-looking number; a nickname
    is restricted to letters, digits, spaces and . ' - — a nickname is shown
    to the LLM in every later prompt, so a "nickname" like
    "ignore previous instructions: ..." is refused at the door.
  - Nothing is written. This produces a draft; the gateway applies it only
    with the user's signature.

LLM-free by construction: this module sits under backend/resolver/, which the
import-boundary test forbids from reaching backend/agent/.
"""
from __future__ import annotations

import re
import time
import uuid
from dataclasses import dataclass

from backend.audit.canonical import hash_transcript
from backend.data.db import connect, get_conn
from backend.models.contacts import (ContactAddPlan, ContactEditPlan,
                                     ResolvedContactChange, ResolvedContactEdit)
from backend.models.schemas import MAX_AUTH_WINDOW_S
from backend.resolver import Clarify, _match, _pick

NICKNAME_MAX = 32
_NICKNAME_OK = re.compile(r"^[A-Za-z][A-Za-z0-9 .'\-]*$")
_DIGIT_WORDS = {"zero": "0", "oh": "0", "o": "0", "one": "1", "two": "2", "three": "3",
                "four": "4", "five": "5", "six": "6", "seven": "7", "eight": "8",
                "nine": "9"}
_MULTIPLIERS = {"double": 2, "triple": 3}


@dataclass
class ResolvedChange:
    """A complete, canonical, signable contact change."""
    change: ResolvedContactChange


class InvalidValue(ValueError):
    """A new value that fails validation. The message is read to the user."""


# --------------------------------------------------------------------------- values
def normalize_phone(raw: str) -> str:
    """'9123 4567' / '+65 9123-4567' / 'nine one two three four five six seven'
    -> '+65 9123 4567'. Singapore numbers are 8 digits starting 3, 6, 8 or 9;
    anything else must be in +<country code> international form. Raises
    InvalidValue otherwise — a question, never a guess."""
    text = raw.strip().lower()
    # Spoken digits ("nine one two ... double eight") -> digits.
    out, mult = [], 1
    for tok in re.findall(r"\+|\d+|[a-z]+", text):
        if tok in _MULTIPLIERS:
            mult = _MULTIPLIERS[tok]
            continue
        if tok in _DIGIT_WORDS:
            out.append(_DIGIT_WORDS[tok] * mult)
        elif tok.isdigit():
            out.append(tok[0] * mult + tok[1:])          # "double 8" -> "88"
        elif tok in ("+", "plus"):
            out.append("+")
        else:
            raise InvalidValue(f"{raw!r} doesn't look like a phone number")
        mult = 1
    s = "".join(out)
    if s.count("+") > 1 or ("+" in s and not s.startswith("+")):
        raise InvalidValue(f"{raw!r} doesn't look like a phone number")

    digits = s.lstrip("+")
    if s.startswith("+65") or (not s.startswith("+") and digits.startswith("65") and len(digits) == 10):
        digits = digits[2:]
        s = digits
    if not s.startswith("+"):
        if len(digits) == 8 and digits[0] in "3689":
            return f"+65 {digits[:4]} {digits[4:]}"
        raise InvalidValue(f"{raw!r} isn't a valid Singapore number — it should be "
                           "8 digits starting with 3, 6, 8 or 9")
    if not 8 <= len(digits) <= 15:
        raise InvalidValue(f"{raw!r} doesn't look like a phone number")
    return "+" + digits


def normalize_nickname(raw: str) -> str:
    """Collapse spaces, title-case an all-lower-case name ('mum' -> 'Mum'), and
    refuse anything outside the allowed characters."""
    name = " ".join(raw.split())
    if not name:
        raise InvalidValue("the new name is empty")
    if len(name) > NICKNAME_MAX:
        raise InvalidValue(f"names can be at most {NICKNAME_MAX} characters")
    if not _NICKNAME_OK.match(name):
        raise InvalidValue(f"{raw!r} can't be used as a name — use letters, "
                           "numbers, spaces, and . ' - only")
    return name.title() if name == name.lower() else name


# --------------------------------------------------------------------------- resolve
def resolve_contact_edit(plan: ContactEditPlan, *, transcript: str, user_id: str,
                         draft_id: str | None = None, answers: dict[str, str] | None = None,
                         db_path=None, now: int | None = None):
    """-> ResolvedChange | Clarify. Deterministic; reads the DB, writes nothing."""
    answers = answers or {}
    draft_id = draft_id or uuid.uuid4().hex
    if not plan.edits:
        return Clarify(
            question="What would you like to change — a contact's name or their phone number?",
            field="edits", kind="empty", choices=[], resume_state={})

    conn = connect(db_path) if db_path else get_conn()
    try:
        rows = conn.execute(
            "SELECT id, nickname, last4, phone FROM payees WHERE user_id=?", (user_id,)
        ).fetchall()
        resolved: list[ResolvedContactEdit] = []
        for i, e in enumerate(plan.edits, start=1):
            field = f"e{i}.target"
            row = _pick(
                _match(rows, e.target.mention, "nickname"), e.target.mention, "payee",
                field, {}, answers,
                display=lambda r: f"{r['nickname']} ··{r['last4']}",
                value=lambda r: r,
                ident=lambda r: r["id"],
                fallback=rows,
            )
            if isinstance(row, Clarify):
                return row
            try:
                new = (normalize_phone(e.new_value) if e.field == "phone"
                       else normalize_nickname(e.new_value))
            except InvalidValue as exc:
                what = "phone number" if e.field == "phone" else "name"
                return Clarify(
                    question=f"Sorry, {exc}. What's the new {what} for {row['nickname']}?",
                    field=f"e{i}.new_value", kind=f"invalid_{e.field}", choices=[],
                    resume_state={})
            old = (row["phone"] or "") if e.field == "phone" else row["nickname"]
            if new == old:
                return Clarify(
                    question=f"{row['nickname']}'s {'phone number' if e.field == 'phone' else 'name'} "
                             f"is already {new}. What would you like to change it to?",
                    field=f"e{i}.new_value", kind="unchanged", choices=[], resume_state={})
            resolved.append(ResolvedContactEdit(
                payee_id=row["id"], payee_display=f"{row['nickname']} ··{row['last4']}",
                field=e.field, old_value=old, new_value=new))
    finally:
        conn.close()

    now = int(time.time()) if now is None else now
    try:
        change = ResolvedContactChange(
            draft_id=draft_id, edits=resolved, transcript_hash=hash_transcript(transcript),
            created_at=now, expires_at=now + MAX_AUTH_WINDOW_S)
    except ValueError:
        return Clarify(question="You asked to change the same thing twice — which value "
                                "did you mean?", field="edits", kind="duplicate",
                       choices=[], resume_state={})
    return ResolvedChange(change=change)


# --------------------------------------------------------------------------- adding a contact
@dataclass
class NewContact:
    """A validated, normalised new contact — not yet a signable payload: which
    safeguards it needs is policy's call (backend/policy/new_contact.py)."""
    nickname: str
    phone: str
    last4: str

    @property
    def display(self) -> str:
        return f"{self.nickname} \u00b7\u00b7{self.last4}"


def resolve_contact_add(plan: ContactAddPlan, *, user_id: str, name_hint: str | None = None,
                        db_path=None):
    """-> NewContact | Clarify. Deterministic; reads the DB, writes nothing.

    `name_hint` is the name the user already gave (the payee a payment named
    that matched no contact); the parser's own reading wins when it has one."""
    c = plan.contact
    raw_name = (c.nickname or name_hint or "").strip()
    if not raw_name:
        return Clarify(question="What should I call this new contact?",
                       field="contact.nickname", kind="need_name", choices=[],
                       resume_state={})
    try:
        nickname = normalize_nickname(raw_name)
    except InvalidValue as exc:
        return Clarify(question=f"Sorry, {exc}. What should I call this contact?",
                       field="contact.nickname", kind="invalid_nickname", choices=[],
                       resume_state={})
    if not (c.phone or "").strip():
        return Clarify(question=f"What's {nickname}'s mobile number? It's where "
                                "payments to them will go.",
                       field="contact.phone", kind="need_phone", choices=[],
                       resume_state={}, unknown_mention=nickname)
    try:
        phone = normalize_phone(c.phone)
    except InvalidValue as exc:
        return Clarify(question=f"Sorry, {exc}. What's {nickname}'s mobile number?",
                       field="contact.phone", kind="invalid_phone", choices=[],
                       resume_state={}, unknown_mention=nickname)

    conn = connect(db_path) if db_path else get_conn()
    try:
        taken = conn.execute(
            "SELECT nickname, last4 FROM payees WHERE user_id=? AND phone=?",
            (user_id, phone)).fetchone()
    finally:
        conn.close()
    if taken is not None:
        # Not a second contact for one number: two names for the same
        # destination is how a payment ends up somewhere the user didn't mean.
        return Clarify(question=f"That number is already saved as {taken['nickname']} "
                                f"\u00b7\u00b7{taken['last4']}, so there's nothing to add. "
                                f"You can pay them by that name.",
                       field="contact.phone", kind="phone_exists", choices=[],
                       resume_state={})
    return NewContact(nickname=nickname, phone=phone, last4=re.sub(r"\D", "", phone)[-4:])
