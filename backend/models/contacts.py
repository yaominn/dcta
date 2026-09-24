"""
Contact-edit schemas: renaming a payee or changing their phone number.

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
