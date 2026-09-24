"""
Frozen v1 transaction schemas — the cross-team contract. (brief Section 7)

DO NOT change without team sign-off. Anything that touches these shapes
affects all three workstreams (agent, resolver, gateway/audit).

Two schemas, and the gap between them IS the security model:

  - IntentPlan   : what the LLM emits. Mentions + symbolic amounts only.
                   No payee_id, no account ids, no tickers, no computed money —
                   every cross-reference is a mention the resolver maps (L3).
  - ResolvedPlan : what the resolver produces; canonicalized -> hashed -> signed.
                   Concrete payee_id, concrete amounts, whole share counts.

Security properties baked into the shapes (say this to the judges):
  1. The LLM schema has NO identifier fields: no payee_id, no account id, no
     bare ticker — source_account and ticker are MENTIONS the resolver maps
     (L3). A prompt-injected model cannot pick a payee/account/equity directly;
     only the deterministic resolver can.                       (brief 4.3, layer 3)
  2. The LLM schema has NO arithmetic -> "whatever is left" is a symbolic
     {after_leg, op} token; the account is DERIVED from the referenced leg's
     own source_account, so the ref can never contradict the leg.  (brief 4.1)
  3. The signed payload is the ResolvedPlan, never the raw LLM output. (brief 4.5/7)
  4. extra="forbid" on every model -> an LLM that invents a field is rejected.
  5. Money is int cents from DB to signed payload. The `_cents` suffix stops
     anyone reintroducing a float. canonical_json RAISES on any float, so a
     float can never silently enter a signed payload (no hash collisions).
"""
from __future__ import annotations

from enum import Enum
from typing import Annotated, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, model_validator


# The authorization window is part of the SIGNED contract: changing this bound
# changes what is acceptable to sign. It lives with the schema (not config.py)
# for the same reason schema_version does — it is a contract-level property,
# not a deployment setting. 300s = an approval is minutes-scale, not open-ended.
MAX_AUTH_WINDOW_S = 300

# Cross-language hash-safety ceiling. JS numbers are IEEE-754 doubles: integers
# above 2^53 lose precision in JS but not Python, so the two canonicalizers
# would produce different bytes -> a payload_hash mismatch in the exact field
# the binding-constraint test exists to prove matches. Bounding amount_cents
# here makes the byte-identical guarantee unconditional rather than incidental
# (fails closed on the mismatch either way, but the guarantee should not depend
# on the value staying small by accident). M5's payment limits sit far below.
MAX_AMOUNT_CENTS = 2**53 - 1


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
    """A symbolic reference the resolver computes. The LLM never does
    arithmetic — it names a leg, and deterministic code does the rest.
    e.g. {"after_leg": "t1", "op": "ALL"} ("whatever is left after t1").

    There is intentionally no account field: the account is DERIVED from the
    referenced leg's own (already resolved) source_account, so a ref can never
    disagree with the leg it depends on. Making the account UNREPRESENTABLE
    (rather than detecting a mismatch) is the same enforce-the-property move
    as extra="forbid" and the float guard. Supersedes the brief's Section 7
    "ref" grammar, which embedded an account alias and predates L3."""
    model_config = ConfigDict(extra="forbid")
    after_leg: str = Field(description="leg id whose post-execution balance to use, e.g. 't1'")
    op: AmountOp


# Plain union: the two shapes share no required fields, so Pydantic resolves
# unambiguously (a literal has `literal_cents`, a symbolic has `after_leg`+`op`).
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
    # L3: the source account is a MENTION (e.g. {"mention":"savings"}), not an
    # account alias/id. The resolver maps the mention to the concrete account
    # (acct_savings). The LLM cannot name which account to debit directly —
    # mirrors "no payee_id". A bare alias string is rejected at validation.
    source_account: MentionTarget = Field(
        description="account the user mentioned, e.g. {mention:'savings'}; "
                    "resolver maps to the concrete account id",
    )


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
    # L3: the equity is a MENTION (e.g. {"mention":"AAPL"} or {"mention":"Apple"}),
    # not a bare ticker string. The resolver validates it maps to a known
    # equity in the DB and fetches its price. A bare ticker string is rejected.
    ticker: MentionTarget = Field(
        description="equity the user mentioned, e.g. {mention:'AAPL'}; "
                    "resolver validates it maps to a known equity",
    )
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
    # An EMPTY plan is valid here on purpose: it is how the parser says "I
    # understood no intent", with `unresolved` carrying what to ask about. That
    # drives the clarify loop. The no-empty constraint belongs on ResolvedPlan
    # (what gets signed), not here — see ResolvedPlan.plan.
    plan: list[Intent]
    unresolved: list[str] = Field(
        default_factory=list,
        description="fields the LLM could not determine; MUST NOT be guessed",
    )

    @model_validator(mode="after")
    def _check_symbolic_refs(self):
        """A symbolic amount may only reference an EARLIER leg in the same
        plan. A ref to a leg that doesn't exist, to the referencing leg itself,
        or to a later leg (forward/circular) is rejected at construction — the
        contradiction cannot be expressed, rather than detected downstream.
        M4's resolver implements the computation; the schema pins the
        well-formedness now, before any consumer exists.

        R1: leg ids must be UNIQUE, checked first. The reference check below
        uses ids.index(), which returns only the FIRST match — so with a
        duplicate id, `[t1, t2->t1, t1]` passes: ids.index("t1") == 0 and
        0 >= 1 is False, while the second t1 sits AFTER t2 and has not
        executed. That is the forward reference this validator exists to
        reject, reachable through a duplicate. Uniqueness first makes the
        index lookup unambiguous, so the check below means what it says."""
        ids = [leg.id for leg in self.plan]
        if len(ids) != len(set(ids)):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            raise ValueError(f"duplicate leg ids: {dupes} — leg ids must be unique")
        for i, leg in enumerate(self.plan):
            amt = leg.amount
            if isinstance(amt, SymbolicAmount):
                if amt.after_leg not in ids:
                    raise ValueError(
                        f"leg {leg.id!r}: after_leg {amt.after_leg!r} is not a leg in this plan"
                    )
                if ids.index(amt.after_leg) >= i:
                    raise ValueError(
                        f"leg {leg.id!r}: after_leg {amt.after_leg!r} must reference "
                        "an earlier leg"
                    )
        return self


# --------------------------------------------------------------------------- RESOLVED PLAN (signed)
class ResolvedTransfer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["TRANSFER"] = "TRANSFER"
    source_account: str
    payee_id: str            # resolver mapped the mention -> concrete id
    payee_display: str       # safe label for the overlay (user nickname)
    amount_cents: int = Field(gt=0, le=MAX_AMOUNT_CENTS)   # concrete, computed by the resolver


class ResolvedPayBill(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["PAY_BILL"] = "PAY_BILL"
    source_account: str
    biller_id: str
    biller_display: str
    amount_cents: int = Field(gt=0, le=MAX_AMOUNT_CENTS)


class ResolvedBuyEquity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    type: Literal["BUY_EQUITY"] = "BUY_EQUITY"
    source_account: str
    ticker: str
    amount_cents: int = Field(gt=0, le=MAX_AMOUNT_CENTS)            # dollars allocated, in cents
    estimated_shares: int      # WHOLE shares only (floor) -> the demo's 32 shares
    estimated_fill_price_cents: int             # per-share price, in cents


ResolvedIntent = Annotated[
    Union[ResolvedTransfer, ResolvedPayBill, ResolvedBuyEquity],
    Field(discriminator="type"),
]


class ResolvedPlan(BaseModel):
    """The canonical payload that gets hashed + signed.

    The signature binds FOUR things, not three: identity (the WebAuthn key),
    intent (the legs), the full payload (every field below), AND the origin
    utterance (transcript_hash). Without transcript_hash the signature proved
    the user approved *a plan* but not that the plan came from anything they
    said; with it, non-repudiation covers the spoken intent itself.

    NO leg_status here on purpose: execution outcome is runtime state and is
    logged in the audit chain separately. The signature binds the *intent*
    the user approved, not the eventual outcome.

    Field notes:
      - schema_version is a Literal, not a plain str: any future change is an
        explicit, reviewable edit, and old audit entries stay interpretable.
      - transcript_hash has NO default: a plan cannot be built without binding
        it to a transcript. Pattern-locked to a 64-char hex sha256.
      - created_at / expires_at are Unix-seconds UTC integers, not ISO strings
        (same class of problem as the float-money bug L2: a free-form ISO
        string leaves format drift — Z vs +00:00, microseconds or not — inside
        a hashed field). Integers have one representation in every language.
      - expires_at puts the time bound INSIDE what the user signed. The 120s
        nonce TTL is server-side state; an expiry in the payload is part of the
        authorization itself. gateway.submit() enforces it, first, cheaply,
        before consuming any state. The window itself is enforced AT
        CONSTRUCTION (created_at < expires_at <= created_at + MAX_AUTH_WINDOW_S),
        so a malformed timestamp can never be signed in the first place — the
        same enforce-the-property philosophy as the float guard in canonical.py
        and the import-boundary test.
    """
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1"] = "1"
    draft_id: str            # server-issued; the WebAuthn nonce binds to THIS (brief 4.5)
    # R2: a signed authorization must move something. An empty ResolvedPlan
    # renders an overlay with no legs and asks the user for a biometric
    # signature over an authorization to do nothing — a valid signature, a
    # valid audit entry, and a meaningless consent. Unlike IntentPlan (where
    # empty legitimately means "nothing understood, go clarify"), nothing
    # downstream of here has anything to clarify: this object exists only to
    # be displayed, signed and executed.
    plan: list[ResolvedIntent] = Field(min_length=1)
    transcript_hash: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        description="sha256 of the raw UTF-8 transcript this plan was derived from",
    )
    created_at: int         # Unix seconds UTC — one representation, no string drift
    expires_at: int         # Unix seconds UTC — checked first in gateway.submit()

    @model_validator(mode="after")
    def _check_window(self):
        """N1+N2: the authorization window is bounded by construction, not just
        asserted. An inverted window (expires_at <= created_at, e.g. an approval
        that ended before it began) and an open-ended window (e.g. a ten-year
        approval) are both rejected here, so neither can be signed. The runtime
        expiry check in gateway.submit() is still what rejects an authorization
        whose (valid) window has since elapsed; this validator guarantees the
        window was well-formed to begin with."""
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be after created_at")
        if self.expires_at - self.created_at > MAX_AUTH_WINDOW_S:
            raise ValueError(
                f"authorization window {self.expires_at - self.created_at}s exceeds "
                f"{MAX_AUTH_WINDOW_S}s: an approval is time-bounded by construction"
            )
        return self
