"""
Contact schemas: renaming a payee, changing their phone number, or adding a
new one (with the LLM's advisory scam read, ScamAssessment).

A SEPARATE contract from schemas.py, which is frozen v1 and describes money
movement. Nothing here changes a payment schema; these follow the same rules:

  - ContactEditPlan is what the LLM emits: MENTIONS only (who the user named)
    and the new value in the user's words. No payee id anywhere, so a model
    cannot name a row.
  - ResolvedContactChange is what gets displayed, hashed and SIGNED. It carries
    the old value as well as the new one: the user approves "Mom's phone
    +65 9123 3310 -> +65 8765 4321", and the gateway applies it only if the
    stored value is still the old one (no lost update, no silent overwrite of a
    change made since the draft was shown).

Why a phone number is signed like a payment: in Singapore a phone number is a
PayNow proxy — changing a payee's number changes where money sent to them goes.
Rewriting a contact's details is the classic account-takeover step before a
payment, so it gets the same draft -> review -> biometric path.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from backend.models.schemas import MAX_AUTH_WINDOW_S, MentionTarget

ContactField = Literal["nickname", "phone"]
MAX_EDITS = 5


class ContactEditIntent(BaseModel):
    """One edit, as the LLM understood it: whose contact, which field, and the
    new value in the user's own words (validated and normalised later)."""
    model_config = ConfigDict(extra="forbid")
    target: MentionTarget
    field: ContactField
    new_value: str = Field(min_length=1, max_length=64)


class ContactEditPlan(BaseModel):
    """Top-level LLM output for a contact edit. An empty list is valid: it is
    how the parser says "I couldn't tell what to change" (-> a question)."""
    model_config = ConfigDict(extra="forbid")
    edits: list[ContactEditIntent] = Field(default_factory=list, max_length=MAX_EDITS)
    unresolved: list[str] = Field(default_factory=list)


class ResolvedContactEdit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    payee_id: str
    payee_display: str        # "Mom ··3310" — from OUR DB, never from the LLM
    field: ContactField
    old_value: str            # "" when the contact had no phone on file
    new_value: str            # validated + normalised ("+65 8765 4321", "Mum")


class ResolvedContactChange(BaseModel):
    """The canonical payload that gets hashed and signed for a contact edit.
    Same binding as ResolvedPlan: draft_id (the nonce binds to it), the
    transcript it came from, and a time bound inside what the user signs."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    kind: Literal["CONTACT_EDIT"] = "CONTACT_EDIT"
    draft_id: str
    edits: list[ResolvedContactEdit] = Field(min_length=1, max_length=MAX_EDITS)
    transcript_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: int
    expires_at: int

    @model_validator(mode="after")
    def _check(self):
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MAX_AUTH_WINDOW_S:
            raise ValueError(f"authorization window exceeds {MAX_AUTH_WINDOW_S}s")
        keys = [(e.payee_id, e.field) for e in self.edits]
        if len(keys) != len(set(keys)):
            raise ValueError("the same field of the same contact is edited twice")
        return self


# --------------------------------------------------------------------------- adding a contact
# Adding a payee is the step before most scam payments ("Hi Mum, new number",
# the "safe account", the job that pays commission once you transfer in). So a
# new contact takes the same road as money: the LLM drafts, deterministic rules
# set the floor of safeguards, the user signs, the gateway writes it.

class NewContactIntent(BaseModel):
    """The new contact as the LLM understood it: the name and the number in the
    user's OWN words. Either may be missing (-> a question). Both are validated
    and normalised by the resolver; nothing here is trusted."""
    model_config = ConfigDict(extra="forbid")
    nickname: str | None = Field(default=None, max_length=64)
    phone: str | None = Field(default=None, max_length=64)


class ContactAddPlan(BaseModel):
    """Top-level LLM output for "add Bob, his number is 9123 4567"."""
    model_config = ConfigDict(extra="forbid")
    contact: NewContactIntent = Field(default_factory=NewContactIntent)
    unresolved: list[str] = Field(default_factory=list)


# What the LLM may say about scam risk. A closed vocabulary: the page renders a
# FIXED sentence per signal (backend/policy/new_contact.py), never model text.
ScamSignal = Literal[
    "urgency", "secrecy", "impersonation_family", "impersonation_official",
    "safe_account", "investment_promise", "job_or_task", "parcel_or_refund",
    "romance", "third_party_instructions",
]


class ScamAssessment(BaseModel):
    """The LLM's read of the conversation. ADVISORY: it can add safeguards,
    never remove one, and on its own it cannot refuse a contact. `reason` is
    kept for the trace (/data) and is never shown on the card."""
    model_config = ConfigDict(extra="forbid")
    risk: Literal["low", "medium", "high"]
    signals: list[ScamSignal] = Field(default_factory=list, max_length=10)
    reason: str = Field(default="", max_length=300)


Safeguard = Literal["BIOMETRIC", "PHONE_CODE", "HOLD"]
MAX_HOLD_MINUTES = 7 * 24 * 60


class ResolvedContactAdd(BaseModel):
    """The canonical payload that gets hashed and signed to add a contact.

    The safeguards are INSIDE what the user signs: they approve "add Bob ··4567,
    with a phone code and a 12-hour payment hold", and the warnings they were
    shown are bound too (codes, not text), so the signature also records that
    they were told. The gateway will not apply a payload whose safeguards the
    server did not decide (DraftStore.executable compares it byte for byte)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    kind: Literal["CONTACT_ADD"] = "CONTACT_ADD"
    draft_id: str
    user_id: str
    nickname: str = Field(min_length=1, max_length=32)
    phone: str = Field(pattern=r"^\+\d[\d ]{6,20}$")
    payee_display: str                      # "Bob ··4567", built from these values
    safeguards: list[Safeguard] = Field(min_length=1)
    hold_minutes: int = Field(ge=0, le=MAX_HOLD_MINUTES)
    warnings: list[str] = Field(default_factory=list, max_length=20)
    transcript_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    created_at: int
    expires_at: int

    @model_validator(mode="after")
    def _check(self):
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MAX_AUTH_WINDOW_S:
            raise ValueError(f"authorization window exceeds {MAX_AUTH_WINDOW_S}s")
        if "BIOMETRIC" not in self.safeguards:
            raise ValueError("every new contact needs the user's biometric")
        if len(set(self.safeguards)) != len(self.safeguards):
            raise ValueError("a safeguard is listed twice")
        if ("HOLD" in self.safeguards) != (self.hold_minutes > 0):
            raise ValueError("a HOLD safeguard needs hold_minutes > 0, and only then")
        for w in self.warnings:
            if not re.fullmatch(r"[a-z_]{2,40}", w):
                raise ValueError(f"bad warning code {w!r}")
        return self
