"""
The execution gateway — the one chokepoint funds pass through.
(brief Section 4.2: accepts only (payload, signature); 4.5: verifies signature,
payload hash and nonce; 4.1: sequential execution, stop at first failure.)

submit() verifies, in order:
  1. expiry   — now > expires_at -> reject EXPIRED. Checked FIRST: cheap, and it
                consumes no state (the nonce stays usable for a fresh, unexpired
                resubmission of the same draft). The time bound lives INSIDE the
                signed payload, so an expired authorization is the user's own
                consent expiring — not server-side bookkeeping.
  2. nonce    — draft-bound, fresh, single-use (swap-after-approval & replay blocked)
  3. signature — over the canonical challenge hash, against a registered public key
  4. policy   — M5: KYC, limits, velocity, anomaly, re-evaluated HERE against the
                ledger. Checking policy before the overlay is UX; checking it
                here is enforcement. A caller who assembled or replayed a signed
                payload would otherwise bypass every limit, which would make the
                policy engine advisory. The gateway is the one place funds pass
                through, so it is the one place a limit can be a limit.
                A plan policy ESCALATES (anomaly) additionally needs an
                out-of-band confirmation of this exact payload (stepup.py);
                without one it is rejected CONFIRMATION, not executed.
  5. execute  — on the mock ledger, marking later legs BLOCKED on first failure

Every step is logged to the hash-chained audit log. A request with an expired
payload, a missing or bad signature, or a replayed/swapped nonce is REJECTED and
LOGGED — so even a fully compromised LLM can do nothing here without a valid
human signature. That is the whole point of the trust boundary.
"""
from __future__ import annotations

import time

from backend.audit.canonical import payload_hash, challenge_hash
from backend.audit.log import AuditLog, AuditEntryType
from backend.gateway.nonce import NonceStore, NonceError
from backend.gateway.signer import MockSigner
from backend.gateway.stepup import StepUpStore
from backend.data import destinations
from backend.data.db import connect
from backend.gateway.executor import AlreadyExecuted, MockExecutor
from backend.policy import safety, scam

# Outcomes recorded for a draft that ended WITHOUT running.
CLOSED_OUTCOMES = frozenset({"DECLINED", "CANCELLED"})
from backend.auth.credentials import MockCredentialStore
from backend.models.contacts import ResolvedContactAdd, ResolvedContactChange
from backend.models.schemas import ResolvedPlan
from backend.policy import (Decision, contact_change_step_up, evaluate,
                            load_context, owner_of)
from backend.policy.new_contact import required_at_gateway


_FROZEN_CONTACTS = ("your payments are frozen, so contacts can't be added or changed — "
                    "nothing was saved. Unfreeze them with a code on your phone first")


class Gateway:
    def __init__(
        self,
        *,
        signer: MockSigner,
        nonce_store: NonceStore,
        audit: AuditLog,
        executor: MockExecutor,
        credentials: MockCredentialStore,
        drafts,
        policy_db_path=None,
        step_up: StepUpStore | None = None,
        recent_change_hours: int = 24,
        cooling_hours: int = 12,
    ):
        self.signer = signer
        self.recent_change_hours = recent_change_hours
        self.cooling_hours = cooling_hours
        self.nonce_store = nonce_store
        self.audit = audit
        self.executor = executor
        self.credentials = credentials
        # What this app actually drafted. Required — no default: a gateway that
        # could be built without it would execute any signed payload again.
        # Anything with executable(draft_id, kind=, submitted_hash=) will do;
        # main.py wires the real DraftStore.
        self.drafts = drafts
        # The ledger policy is evaluated against. None disables the re-check —
        # used only by the M1 gateway unit tests, which predate M5 and exercise
        # the signature matrix in isolation. main.py always wires it.
        self.policy_db_path = policy_db_path
        # Where out-of-band confirmations are recorded. None means none can
        # exist, so an escalated plan is always refused — the closed direction.
        self.step_up = step_up

    def submit(
        self,
        resolved_plan: ResolvedPlan,
        signature: str | None,
        nonce: str,
        credential_id: str,
    ) -> dict:
        draft_id = resolved_plan.draft_id
        p_hash = payload_hash(resolved_plan)
        challenge = challenge_hash(p_hash, nonce)

        # 1. expiry — checked FIRST, before any state is consumed. The time bound
        #    lives inside the signed payload (expires_at); an expired authorization
        #    is rejected without touching the nonce, so a fresh, unexpired
        #    resubmission of the same draft can still use the issued nonce.
        now = int(time.time())
        if now > resolved_plan.expires_at:
            return self._reject(
                draft_id, p_hash, "EXPIRED",
                f"payload expired at {resolved_plan.expires_at}, now {now}",
            )

        # 2. nonce — draft-bound, single-use, TTL. Consumed here: a failed attempt
        #    burns the nonce (one signing attempt per nonce; re-request to retry).
        try:
            self.nonce_store.consume(nonce, draft_id)
        except NonceError as exc:
            return self._reject(draft_id, p_hash, "NONCE", str(exc))

        # 3. signature — over the canonical challenge, against a registered key.
        pubkey = self.credentials.get(credential_id)
        if pubkey is None:
            return self._reject(draft_id, p_hash, "SIGNATURE", "unknown credential")
        if not signature:
            return self._reject(draft_id, p_hash, "SIGNATURE", "missing signature")
        if not self.signer.verify(pubkey, signature, challenge):
            return self._reject(draft_id, p_hash, "SIGNATURE", "bad signature")

        # 3b. at most once. A fresh nonce and a fresh signature exist for this
        #     draft on every request — neither says "not again" — so ask the
        #     ledger. A repeat is refused WITH the original result: a retry
        #     after a lost response learns what happened instead of paying twice.
        prior = self.executor.prior_execution(draft_id)
        if prior is not None:
            return self._already_final(draft_id, p_hash, prior)

        # 3c. the draft itself: it must exist, be `ready`, and this must be
        #     EXACTLY its payload — not an older version, not one the validator
        #     never saw, not one for a draft this app never made.
        refused = self.drafts.executable(draft_id, kind="payment", submitted_hash=p_hash)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)

        # 3d-3f. scam protection: the kill switch, the signed destination, and
        #        the scam score's hold / step-up — enforced HERE, where money
        #        moves, whatever the page showed or skipped.
        refused = self._scam_protection(resolved_plan, draft_id, p_hash)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)

        # 4. policy — re-evaluated at the chokepoint (M5). The owner is derived
        #    from the ACCOUNT ROWS being debited, never from a field in the
        #    request, so a caller cannot nominate whose limits apply to them.
        if self.policy_db_path is not None:
            owner = owner_of(resolved_plan, db_path=self.policy_db_path)
            if owner is None:
                return self._reject(draft_id, p_hash, "POLICY",
                                    "cannot determine the owner of the accounts "
                                    "this plan debits")
            verdicts = evaluate(
                resolved_plan,
                load_context(owner, db_path=self.policy_db_path),
            )
            self.audit.append(AuditEntryType.POLICY,
                              verdicts.to_audit_payload(draft_id))
            if verdicts.blocked:
                return self._reject(draft_id, p_hash, "POLICY",
                                    "; ".join(verdicts.reasons()))
            if (verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION
                    and not (self.step_up is not None
                             and self.step_up.is_confirmed(draft_id, p_hash))):
                return self._reject(draft_id, p_hash, "CONFIRMATION",
                                    "this payment needs an out-of-band "
                                    "confirmation first: "
                                    + "; ".join(verdicts.reasons()))

        # 5. execute on the mock ledger.
        try:
            result = self.executor.execute(resolved_plan, payload_hash=p_hash)
        except AlreadyExecuted as exc:     # lost a race to a concurrent submit
            return self._already_final(draft_id, p_hash, exc.prior)
        if self.step_up is not None:
            self.step_up.consume(draft_id)
        safety.release_hold(draft_id, db_path=self.executor.db_path)   # a served hold is done
        self.audit.append(
            AuditEntryType.EXECUTION,
            {
                "draft_id": draft_id,
                "payload_hash": p_hash,
                "outcome": result["status"],
                "legs": result["legs"],
            },
        )
        return {"accepted": True, "draft_id": draft_id,
                "payload_hash": p_hash, "execution": result}

    def submit_contact_change(
        self,
        change: ResolvedContactChange,
        signature: str | None,
        nonce: str,
        credential_id: str,
    ) -> dict:
        """The same chokepoint for a contact edit: expiry -> nonce -> signature
        -> step-up (a phone change) -> apply -> audit. A contact's details are
        written nowhere else, so a rename or a number change needs the user's
        signature over exactly this change, however the request arrived."""
        draft_id = change.draft_id
        p_hash = payload_hash(change)
        challenge = challenge_hash(p_hash, nonce)

        now = int(time.time())
        if now > change.expires_at:
            return self._reject(draft_id, p_hash, "EXPIRED",
                                f"payload expired at {change.expires_at}, now {now}")
        try:
            self.nonce_store.consume(nonce, draft_id)
        except NonceError as exc:
            return self._reject(draft_id, p_hash, "NONCE", str(exc))
        pubkey = self.credentials.get(credential_id)
        if pubkey is None:
            return self._reject(draft_id, p_hash, "SIGNATURE", "unknown credential")
        if not signature:
            return self._reject(draft_id, p_hash, "SIGNATURE", "missing signature")
        if not self.signer.verify(pubkey, signature, challenge):
            return self._reject(draft_id, p_hash, "SIGNATURE", "bad signature")

        # 3b. at most once. A fresh nonce and a fresh signature exist for this
        #     draft on every request — neither says "not again" — so ask the
        #     ledger. A repeat is refused WITH the original result: a retry
        #     after a lost response learns what happened instead of paying twice.
        prior = self.executor.prior_execution(draft_id)
        if prior is not None:
            return self._already_final(draft_id, p_hash, prior)

        refused = self.drafts.executable(draft_id, kind="contact_edit", submitted_hash=p_hash)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)
        if self._frozen(self._payee_owners([e.payee_id for e in change.edits])):
            return self._reject(draft_id, p_hash, "KILL_SWITCH", _FROZEN_CONTACTS)

        # Re-derived HERE from the payload, not taken from the draft store: a
        # hand-assembled phone change needs the out-of-band code too.
        reasons = contact_change_step_up(change)
        if reasons and not (self.step_up is not None
                            and self.step_up.is_confirmed(draft_id, p_hash)):
            return self._reject(draft_id, p_hash, "CONFIRMATION",
                                "this change needs an out-of-band confirmation "
                                "first: " + " ".join(reasons))

        try:
            result = self.executor.apply_contact_change(change, payload_hash=p_hash)
        except AlreadyExecuted as exc:
            return self._already_final(draft_id, p_hash, exc.prior)
        if self.step_up is not None and reasons:
            self.step_up.consume(draft_id)
        self.audit.append(AuditEntryType.CONTACT_UPDATE, {
            "draft_id": draft_id, "payload_hash": p_hash, "outcome": result["status"],
            # payee ids and fields only: the audit chain is append-only and hard
            # to redact, so the phone numbers themselves are not copied into it.
            "edits": [{"payee_id": e.payee_id, "field": e.field} for e in change.edits],
        })
        return {"accepted": result["status"] == "UPDATED", "draft_id": draft_id,
                "payload_hash": p_hash, "execution": result,
                **({} if result["status"] == "UPDATED"
                   else {"rejection": "FAILED", "reason": result["error"]})}

    def submit_contact_add(
        self,
        add: ResolvedContactAdd,
        signature: str | None,
        nonce: str,
        credential_id: str,
    ) -> dict:
        """The same chokepoint for a NEW contact: expiry -> nonce -> signature
        -> at most once -> exactly the drafted payload -> never a reported
        number -> the phone code if the draft required one -> write -> audit.
        Payees are added nowhere else."""
        draft_id = add.draft_id
        p_hash = payload_hash(add)
        refused = self._authenticate(draft_id, p_hash, add.expires_at, signature,
                                     nonce, credential_id)
        if refused is not None:
            return refused
        prior = self.executor.prior_execution(draft_id)
        if prior is not None:
            return self._already_final(draft_id, p_hash, prior)
        refused = self.drafts.executable(draft_id, kind="contact_add", submitted_hash=p_hash)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)
        if self._frozen({add.user_id}):
            return self._reject(draft_id, p_hash, "KILL_SWITCH", _FROZEN_CONTACTS)
        # Re-derived HERE from the payload: whatever was drafted or signed, a
        # number on the scam list is never added.
        stop = required_at_gateway(add.nickname, add.phone)
        if stop:
            return self._reject(draft_id, p_hash, "POLICY", stop)
        needs_code = "PHONE_CODE" in add.safeguards
        if needs_code and not (self.step_up is not None
                               and self.step_up.is_confirmed(draft_id, p_hash)):
            return self._reject(draft_id, p_hash, "CONFIRMATION",
                                "adding this contact needs the code sent to your phone first")
        try:
            result = self.executor.add_contact(add, payload_hash=p_hash)
        except AlreadyExecuted as exc:
            return self._already_final(draft_id, p_hash, exc.prior)
        if self.step_up is not None and needs_code:
            self.step_up.consume(draft_id)
        # Safeguards and warning codes, not the number or the name: the chain is
        # append-only and hard to redact (the same rule as CONTACT_UPDATE).
        self.audit.append(AuditEntryType.CONTACT_ADD, {
            "draft_id": draft_id, "payload_hash": p_hash, "outcome": result["status"],
            "safeguards": add.safeguards, "hold_minutes": add.hold_minutes,
            "warnings": add.warnings,
        })
        ok = result["status"] == "ADDED"
        return {"accepted": ok, "draft_id": draft_id, "payload_hash": p_hash,
                "execution": result,
                **({} if ok else {"rejection": "FAILED", "reason": result["error"]})}

    def _authenticate(self, draft_id: str, p_hash: str, expires_at: int,
                      signature: str | None, nonce: str, credential_id: str) -> dict | None:
        """expiry -> nonce -> signature, in that order. A rejection dict, or None."""
        now = int(time.time())
        if now > expires_at:
            return self._reject(draft_id, p_hash, "EXPIRED",
                                f"payload expired at {expires_at}, now {now}")
        try:
            self.nonce_store.consume(nonce, draft_id)
        except NonceError as exc:
            return self._reject(draft_id, p_hash, "NONCE", str(exc))
        pubkey = self.credentials.get(credential_id)
        if pubkey is None:
            return self._reject(draft_id, p_hash, "SIGNATURE", "unknown credential")
        if not signature:
            return self._reject(draft_id, p_hash, "SIGNATURE", "missing signature")
        if not self.signer.verify(pubkey, signature, challenge_hash(p_hash, nonce)):
            return self._reject(draft_id, p_hash, "SIGNATURE", "bad signature")
        return None

    def _payee_owners(self, payee_ids: list[str]) -> set[str]:
        conn = connect(self.executor.db_path)
        try:
            return {r["user_id"] for r in conn.execute(
                f"SELECT user_id FROM payees WHERE id IN ({','.join('?' * len(payee_ids))})",
                payee_ids)}
        finally:
            conn.close()

    def _frozen(self, users: set[str]) -> bool:
        """The kill switch covers WHERE money can go too: while payments are
        frozen, no contact is added and no payee's details change."""
        return any(safety.kill_switch_engaged(u, db_path=self.executor.db_path) is not None
                   for u in users if u)

    def _scam_protection(self, plan: ResolvedPlan, draft_id: str, p_hash: str):
        """(rejection, reason) or None. Reads the ledger, never the request."""
        db = self.executor.db_path
        now = int(time.time())
        owner = owner_of(plan, db_path=db)

        # The kill switch: the user froze all outgoing payments.
        if owner and safety.kill_switch_engaged(owner, db_path=db) is not None:
            return ("KILL_SWITCH", "your payments are frozen — nothing was sent. Unfreeze "
                                   "them with a code on your phone first")

        # The destination: a transfer signs WHERE its money goes. Unbound, or no
        # longer the payee's current destination (a new number since the draft),
        # and it does not run.
        conn = connect(db)
        try:
            for leg in plan.plan:
                if leg.type != "TRANSFER":
                    continue
                if leg.destination_version is None or leg.destination_hash is None:
                    return ("DESTINATION", "this transfer is not bound to a destination — "
                                           "nothing was sent")
                cur = destinations.current(conn, leg.payee_id)
                if (cur is None or cur.version != leg.destination_version
                        or cur.routing_hash != leg.destination_hash):
                    return ("SUPERSEDED", "the payee's payment details changed after this "
                                          "was drafted — nothing was sent")
        finally:
            conn.close()

        # The scam score, re-run like policy. The draft's own outcome still
        # binds (a lower score now does not lift the hold the user was shown),
        # a HIGHER one the draft never arranged refuses (RESCORED), and a hold
        # on this draft is honoured whatever either score says.
        if not owner:
            return None                          # policy refuses an ownerless plan below
        drafted = getattr(self.drafts, "scam_outcome_of", lambda _d: None)(draft_id)
        transcript = getattr(self.drafts, "transcript_of", lambda _d: "")(draft_id) or ""
        assessment = scam.reassess(plan, owner, db_path=db, now=now, transcript=transcript,
                                   recent_change_hours=self.recent_change_hours,
                                   cooling_hours=self.cooling_hours, draft_id=draft_id)
        self.audit.append(AuditEntryType.SCAM_ASSESSMENT,
                          {"stage": "gateway", "payload_hash": p_hash, **assessment.to_audit()})
        if scam.rose_past_drafted(drafted, assessment.outcome):
            return ("RESCORED", "this payment looks riskier than when it was drafted — "
                                "cancel it and ask again; nothing was sent")
        outcome = scam.stricter(drafted, assessment.outcome)
        hold = safety.get_hold(draft_id, db_path=db)
        if hold is None and scam.needs_hold(outcome):
            return ("HOLD_REQUIRED", "this payment now needs a safety hold — cancel it "
                                     "and ask again; nothing was sent")
        if hold is not None:
            if hold["status"] == "CANCELLED":
                return ("STATE", "this payment's hold was cancelled — nothing was sent")
            if now < int(hold["release_at"]):
                return ("HELD", f"this payment is on a safety hold for "
                                f"{int(hold['release_at']) - now} more seconds — nothing was sent")
        if outcome == scam.HOLD_STEP_UP and not (
                self.step_up is not None and self.step_up.is_confirmed(draft_id, p_hash)):
            return ("CONFIRMATION", "this payment needs the code sent to your phone first")
        return None

    def _already_final(self, draft_id: str, p_hash: str, prior: dict) -> dict:
        """The draft already has its one outcome. Declined/cancelled is a STATE
        refusal; anything else ran, so this is a DUPLICATE."""
        if prior["outcome"] in CLOSED_OUTCOMES:
            return self._reject(draft_id, p_hash, "STATE",
                                f"this draft was {prior['outcome'].lower()} — nothing was sent")
        return self._duplicate(draft_id, p_hash, prior)

    def _duplicate(self, draft_id: str, p_hash: str, prior: dict) -> dict:
        """Refuse a repeat, audited like any rejection, carrying what the one
        real execution did and when."""
        out = self._reject(draft_id, p_hash, "DUPLICATE",
                           f"this draft was already executed at {prior['executed_at']} "
                           f"({prior['outcome']}); nothing was sent twice")
        return {**out, "execution": prior["result"], "executed_at": prior["executed_at"]}

    def _reject(self, draft_id: str, p_hash: str, kind: str, reason: str) -> dict:
        self.audit.append(
            AuditEntryType.SIGNATURE,
            {"draft_id": draft_id, "payload_hash": p_hash,
             "rejection": kind, "reason": reason},
        )
        return {"accepted": False, "draft_id": draft_id,
                "payload_hash": p_hash, "rejection": kind, "reason": reason}
