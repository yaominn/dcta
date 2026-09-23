"""
Frozen v1 transaction schemas — the cross-team contract. (brief Section 7)

DO NOT change without team sign-off. Anything that touches these shapes
affects all three workstreams (agent, resolver, gateway/audit).

Two schemas, and the gap between them IS the security model:

  - IntentPlan   : what the LLM emits. Mentions + symbolic amounts only.
                   No payee_id, no account numbers, no computed money.
  - ResolvedPlan : what the resolver produces; canonicalized -> hashed -> signed.
                   Concrete payee_id, concrete amounts, whole share counts.

Security properties baked into the shapes (say this to the judges):
  1. The LLM schema has NO payee_id field -> a prompt-injected model cannot
     pick a payee; only the deterministic resolver can.            (brief 4.3, layer 3)
  2. The LLM schema has NO arithmetic -> "whatever is left" is a symbolic
     {ref, op} token the resolver computes against the ledger.     (brief 4.1)
  3. The signed payload is the ResolvedPlan, never the raw LLM output. (brief 4.5/7)
  4. extra="forbid" on every model -> an LLM that invents a field is rejected.
  5. Money is int cents from DB to signed payload. The `_cents` suffix stops
     anyone reintroducing a float. canonical_json RAISES on any float, so a
     float can never silently enter a signed payload (no hash collisions).
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field


# --------------------------------------------------------------------------- enums
class IntentType(str, Enum):
    """The ONLY intent types the LLM may emit. Adding one is a schema change."""
    TRANSFER = "TRANSFER"
    PAY_BILL = "PAY_BILL"
    BUY_EQUITY = "BUY_EQUITY"


class AmountOp(str, Enum):
    """Operations the symbolic resolver understands. Anything else -> UNRESOLVED."""
    ALL = "ALL"      # the entire referenced balance ("whatever is left")
    HALF = "HALF"    # half of the referenced balance ("half of it")


class LegStatus(str, Enum):
    """Runtime execution status. NOT part of the signed payload — logged in the
    audit chain separately. You sign the intent, not the outcome."""
    PENDING = "PENDING"
    BLOCKED = "BLOCKED"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"


# --------------------------------------------------------------------------- LLM OUTPUT
class LiteralAmount(BaseModel):
    """A concrete amount the user stated. e.g. {"literal_cents": 50000} ($500.00)

    Money is integer minor units (cents). Never float — floats cannot be
    canonicalized deterministically across languages (Python f'{2.675:.2f}'='2.67',
    JS (2.675).toFixed(2)='2.68'), which produces hash collisions."""
    model_config = ConfigDict(extra="forbid")
    literal_cents: int = Field(gt=0)


class SymbolicAmount(BaseModel):
    """A symbolic reference the resolver computes. e.g.
    {"ref": "acct_savings.balance_after:t1", "op": "ALL"}
    The LLM never does arithmetic — it only emits the ref + op."""
    model_config = ConfigDict(extra="forbid")
    ref: str = Field(description="grammar: <account_alias>.balance_after:<leg_id>")
    op: AmountOp


# Plain union: the two shapes share no required fields, so Pydantic resolves
# unambiguously (a literal has `literal`, a symbolic has `ref`+`op`).
Amount = Union[LiteralAmount, SymbolicAmount]


class MentionTarget(BaseModel):
    """Raw text the user said — e.g. {"mention": "mom"}.
    The LLM emits the MENTION; the resolver maps it to a payee_id.
    There is intentionally NO payee_id field here."""
    model_config = ConfigDict(extra="forbid")
    mention: str


class _BaseIntent(BaseModel):
    """Shared fields across all intent variants."""
    model_config = ConfigDict(extra="forbid")
    id: str = Field(description="leg id, e.g. 't1' — referenced by symbolic amounts")
    source_account: str = Field(description="account alias, e.g. 'acct_savings'")


class TransferIntent(_BaseIntent):
    type: Literal["TRANSFER"] = "TRANSFER"
    target: MentionTarget
    amount: Amount


class PayBillIntent(_BaseIntent):
    type: Literal["PAY_BILL"] = "PAY_BILL"
    target: MentionTarget
    amount: Amount


class BuyEquityIntent(_BaseIntent):
    type: Literal["BUY_EQUITY"] = "BUY_EQUITY"
    ticker: str = Field(description="e.g. 'AAPL'")
    amount: Amount


# Discriminated union on `type`: a TRANSFER must have target, a BUY_EQUITY must
# have ticker. An intent carrying the wrong fields is rejected at validation.
Intent = Annotated[
    Union[TransferIntent, PayBillIntent, BuyEquityIntent],
    Field(discriminator="type"),
]


class IntentPlan(BaseModel):
    """Top-level LLM output. Matches brief Section 7 exactly."""
    model_config = ConfigDict(extra="forbid")
    plan: list[Intent]
    unresolved: list[str] = Field(
        default_factory=list,
        description="fields the LLM could not determine; MUST NOT be guessed",
    )


# --------------------------------------------------------------------------- RESOLVED PLAN (signed)
class ResolvedTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["TRANSFER"] = "TRANSFER"
    source_account: str
    payee_id: str            # resolver mapped the mention -> concrete id
    payee_display: str       # safe label for the overlay (user nickname)
    amount_cents: int = Field(gt=0)   # concrete, computed by the resolver


class ResolvedPayBill(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["PAY_BILL"] = "PAY_BILL"
    source_account: str
    biller_id: str
    biller_display: str
    amount_cents: int = Field(gt=0)


class ResolvedBuyEquity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["BUY_EQUITY"] = "BUY_EQUITY"
    source_account: str
    ticker: str
    amount_cents: int = Field(gt=0)             # dollars allocated, in cents
    estimated_shares: int      # WHOLE shares only (floor) -> the demo's 32 shares
    estimated_fill_price_cents: int             # per-share price, in cents


ResolvedIntent = Annotated[
    Union[ResolvedTransfer, ResolvedPayBill, ResolvedBuyEquity],
    Field(discriminator="type"),
]


class ResolvedPlan(BaseModel):
    """The canonical payload that gets hashed + signed.

    NO leg_status here on purpose: execution outcome is runtime state and is
    logged in the audit chain separately. The signature binds the *intent*
    the user approved, not the eventual outcome."""
    model_config = ConfigDict(extra="forbid")
    draft_id: str            # server-issued; the WebAuthn nonce binds to THIS (brief 4.5)
    plan: list[ResolvedIntent]
    created_at: str          # ISO-8601 UTC, fixed format for deterministic canonicalization
