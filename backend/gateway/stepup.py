"""
Out-of-band step-up confirmation. (brief 4.5 / demo scenario 3)

The anomaly rule (M5) ESCALATES rather than blocks: $5,000 to a payee this user
only ever sends $50 is allowed, but only after an extra confirmation. Until this
module existed that escalation was a status line — the overlay still enabled the
sign button, and the gateway treated REQUIRE_EXTRA_CONFIRMATION exactly like
ALLOW. An escalation nothing enforces is a warning, not a control.

WHY OUT-OF-BAND, and not a second button on the overlay:

    The biometric signs a blind hash, so "what you see is what you sign" rests
    on the overlay rendering honestly — a client-integrity assumption. A second
    confirmation shown by the SAME overlay inherits that assumption. The code
    here is delivered on a separate channel (the user's phone), and the message
    carrying it describes the transaction from the SERVER'S copy of the plan.
    A compromised renderer can lie about the amount on screen; it cannot change
    what the text message says. That is the gap the out-of-band channel closes.

WHAT A CONFIRMATION BINDS TO: (draft_id, payload_hash). Confirming a draft and
then swapping its plan changes the payload hash, and the confirmation no longer
matches. It is enforced in gateway.submit(), after policy re-evaluation, so a
payload assembled by hand and posted straight to the gateway needs it too.

# MOCK: the "phone" is SimulatedPhone, an in-memory inbox served at /phone for
        the demo. A deployment would send an SMS or a push notification; the
        store, the binding and the enforcement are unchanged by that swap.

Demo-scale in-memory storage, like NonceStore. Losing it on restart fails
CLOSED: the user is asked to confirm again, nothing is silently approved.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field

CODE_DIGITS = 6
MAX_ATTEMPTS = 3


class StepUpError(Exception):
    """Raised on a failed confirm(). Message is human-readable for the overlay."""

    def __init__(self, message: str, *, attempts_left: int = 0):
        super().__init__(message)
        self.attempts_left = attempts_left


def _digest(code: str) -> str:
    # Stored hashed: the store is not the channel, and has no reason to be
    # able to display a code it has already sent.
    return hashlib.sha256(code.encode()).hexdigest()


@dataclass
class _Challenge:
    payload_hash: str
    code_digest: str
    issued_at: float
    attempts: int = 0
    confirmed: bool = False
    used: bool = False


class StepUpStore:
    def __init__(self, ttl_seconds: int = 300):
        self.ttl = ttl_seconds
        self._store: dict[str, _Challenge] = {}

    def issue(self, draft_id: str, payload_hash: str) -> str:
        """Mint a fresh code for this exact payload. Re-issuing for the same
        draft replaces the previous challenge (a re-resolved plan has a new
        payload hash, so the old code must not carry over)."""
        code = f"{secrets.randbelow(10 ** CODE_DIGITS):0{CODE_DIGITS}d}"
        self._store[draft_id] = _Challenge(payload_hash=payload_hash,
                                           code_digest=_digest(code),
                                           issued_at=time.time())
        return code

    def pending(self, draft_id: str) -> bool:
        rec = self._store.get(draft_id)
        return rec is not None and not rec.confirmed and not self._expired(rec)

    def confirm(self, draft_id: str, code: str) -> None:
        """Check the code. Wrong codes are counted; the third burns the
        challenge, so six digits cannot be walked. Raises StepUpError."""
        rec = self._store.get(draft_id)
        if rec is None or rec.used:
            raise StepUpError("no confirmation is pending for this draft")
        if self._expired(rec):
            raise StepUpError("the confirmation code has expired")
        if rec.confirmed:
            return
        if rec.attempts >= MAX_ATTEMPTS:
            raise StepUpError("too many wrong codes; start the request again")
        if not hmac.compare_digest(rec.code_digest, _digest(code.strip())):
            rec.attempts += 1
            left = MAX_ATTEMPTS - rec.attempts
            raise StepUpError(
                "that code is not right" if left else
                "too many wrong codes; start the request again",
                attempts_left=left)
        rec.confirmed = True

    def is_confirmed(self, draft_id: str, payload_hash: str) -> bool:
        """The gateway's check: confirmed, unexpired, unused, and for THIS
        payload — a confirmation cannot be moved onto a different plan."""
        rec = self._store.get(draft_id)
        return (rec is not None and rec.confirmed and not rec.used
                and not self._expired(rec)
                and hmac.compare_digest(rec.payload_hash, payload_hash))

    def consume(self, draft_id: str) -> None:
        """Called after execution: one confirmation authorizes one execution."""
        rec = self._store.get(draft_id)
        if rec is not None:
            rec.used = True

    def _expired(self, rec: _Challenge) -> bool:
        return time.time() - rec.issued_at > self.ttl


@dataclass
class SimulatedPhone:
    """# MOCK: the user's registered device. Holds the messages an SMS gateway
    would have delivered, so the demo can show the second channel on a second
    screen. Nothing on the confirmation overlay reads from here."""
    _inbox: dict[str, list[dict]] = field(default_factory=dict)

    def deliver(self, user_id: str, text: str) -> None:
        self._inbox.setdefault(user_id, []).append(
            {"text": text, "sent_at": int(time.time())})

    def messages(self, user_id: str) -> list[dict]:
        return list(reversed(self._inbox.get(user_id, [])))

    def clear(self) -> None:
        self._inbox.clear()
