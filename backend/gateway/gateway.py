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
from backend.gateway.executor import (AlreadyExecuted, DestinationChanged, MandateRefused,
                                      MockExecutor)
from backend.policy import attempts, safety, scam
from backend.data import billers
from backend.models.mandates import RecurringBillMandate
from backend.recurring import clock as recurring_clock
from backend.recurring import schedule
from backend.recurring import store as recurring
from backend.recurring.terms import occurrence_plan

# Outcomes recorded for a draft that ended WITHOUT running.
CLOSED_OUTCOMES = frozenset({"DECLINED", "CANCELLED"})
from backend.auth.credentials import MockCredentialStore
from backend.models.contacts import ResolvedContactAdd, ResolvedContactChange
from backend.models.schemas import ResolvedPlan
from backend.policy import (Decision, contact_change_refusal, contact_change_step_up,
                            evaluate, load_context, owner_of)
from backend.policy.new_contact import is_reported, required_at_gateway


_FROZEN_CONTACTS = ("your payments are frozen, so contacts can't be added or changed — "
                    "nothing was saved. Unfreeze them with a code on your phone first")


_SUPERSEDED = "the payee's payment details changed after this was drafted — nothing was sent"
_REPORTED_PAYEE = "the payee's number has been reported for scams — nothing was sent"


def destination_refusal(plan: ResolvedPlan, db_path) -> tuple[str, str] | None:
    """(rejection, reason) for a transfer that must not run, else None. A
    transfer signs WHERE its money goes: unbound, no longer the payee's
    current destination (a new number since the draft), or a number on the
    scam list, and it does not run. The signing-challenge endpoint asks the
    same question, so the page never asks for a fingerprint this would refuse."""
    if any(leg.type == "TRANSFER"
           and (leg.destination_version is None or leg.destination_hash is None)
           for leg in plan.plan):
        return ("DESTINATION", "this transfer is not bound to a destination — nothing was sent")
    conn = connect(db_path)
    try:
        if destinations.superseded(conn, plan):
            return ("SUPERSEDED", _SUPERSEDED)
        # A payee reported for scams since it was saved (or drafted). Asked
        # here, before any hold, phone code or name, so nothing invites the
        # user on towards a payment that can never run. The policy engine's
        # reported_number rule refuses it when drafted.
        payees = [leg.payee_id for leg in plan.plan if leg.type == "TRANSFER"]
        if payees and any(is_reported(r["phone"]) for r in conn.execute(
                f"SELECT phone FROM payees WHERE id IN ({','.join('?' * len(payees))})",
                payees)):
            return ("REPORTED", _REPORTED_PAYEE)
    finally:
        conn.close()
    return None


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
        *,
        confirm_name: str | None = None,
    ) -> dict:
        """`confirm_name`: the payee's name as the user typed it on the card
        (HOLD_STEP_UP only). Not signed and never logged — it is friction the
        server checks, not an authorization."""
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
        #        the scam score's hold / step-up (the phone code and the typed
        #        name) — enforced HERE, where money moves, whatever the page
        #        showed or skipped.
        owner = owner_of(resolved_plan, db_path=self.executor.db_path)
        refused, scam_outcome = self._scam_protection(resolved_plan, draft_id, p_hash, owner,
                                                       confirm_name)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)

        # 4. policy — re-evaluated at the chokepoint (M5). The owner is derived
        #    from the ACCOUNT ROWS being debited, never from a field in the
        #    request, so a caller cannot nominate whose limits apply to them.
        if self.policy_db_path is not None:
            if self.policy_db_path != self.executor.db_path:
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

        # 4b. a payment that failed threshold 2 waits before the money moves
        #     (scam.py), and can still be cancelled in that window. Everything
        #     above has passed: release_due() runs it, re-checking the freeze
        #     and policy first.
        if scam.release_delay(scam_outcome):
            release_at = safety.schedule_release(
                draft_id, owner, payload=resolved_plan.model_dump_json(), payload_hash=p_hash,
                now=now, seconds=scam.release_delay(scam_outcome), db_path=self.executor.db_path)
            if self.step_up is not None:
                self.step_up.consume(draft_id)
            safety.release_hold(draft_id, db_path=self.executor.db_path)
            self.audit.append(AuditEntryType.EXECUTION_SCHEDULED, {
                "draft_id": draft_id, "payload_hash": p_hash, "release_at": release_at})
            return {"accepted": True, "scheduled": True, "draft_id": draft_id,
                    "payload_hash": p_hash, "release_at": release_at,
                    "seconds_left": max(0, release_at - int(time.time()))}

        # 5. execute on the mock ledger.
        try:
            result = self.executor.execute(resolved_plan, payload_hash=p_hash)
        except AlreadyExecuted as exc:     # lost a race to a concurrent submit
            return self._already_final(draft_id, p_hash, exc.prior)
        except DestinationChanged:         # a new number landed after step 3e
            return self._reject(draft_id, p_hash, "SUPERSEDED", _SUPERSEDED)
        if self.step_up is not None:
            self.step_up.consume(draft_id)
        safety.release_hold(draft_id, db_path=self.executor.db_path)   # a served hold is done
        attempts.mark(draft_id, attempts.SENT, now=now, db_path=self.executor.db_path)
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
        -> never a reported number -> step-up (a phone change) -> apply ->
        audit. A contact's details are
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
        # Re-derived HERE from the payload: whatever was drafted or signed, a
        # contact's number is never changed to one on the scam list.
        stop = contact_change_refusal(change)
        if stop:
            return self._reject(draft_id, p_hash, "POLICY", stop)

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

    # ------------------------------------------------------------ recurring mandates
    def submit_mandate(
        self,
        terms: RecurringBillMandate,
        signature: str | None,
        nonce: str,
        credential_id: str,
    ) -> dict:
        """Create a recurring bill mandate: expiry -> nonce -> signature -> at
        most once -> exactly the drafted terms -> the signer is the user the
        terms name -> setup checks -> store (with its occurrences) -> audit.

        This moves no money. It records what the user agreed to; every payment
        under it is checked again when it falls due."""
        draft_id = terms.draft_id
        p_hash = payload_hash(terms)
        refused = self._authenticate(draft_id, p_hash, terms.expires_at, signature,
                                     nonce, credential_id)
        if refused is not None:
            return refused
        prior = self.executor.prior_execution(draft_id)
        if prior is not None:
            return self._already_final(draft_id, p_hash, prior)
        refused = self.drafts.executable(draft_id, kind="mandate", submitted_hash=p_hash)
        if refused is not None:
            return self._reject(draft_id, p_hash, *refused)
        # Whose authority this is: the passkey that signed must be the user
        # the terms name. An unknown owner fails closed, as a mismatch does.
        if self._credential_user(credential_id) != terms.user_id:
            return self._reject(draft_id, p_hash, "WRONG_USER",
                                "this passkey doesn't belong to the account holder — nothing "
                                "was set up")
        stop = self._mandate_setup_refusal(terms)
        if stop is not None:
            return self._reject(draft_id, p_hash, *stop)
        try:
            result = self.executor.create_mandate(terms, payload_hash=p_hash,
                                                  credential_id=credential_id,
                                                  now=recurring_clock.now(db_path=self.executor.db_path))
        except AlreadyExecuted as exc:
            return self._already_final(draft_id, p_hash, exc.prior)
        except MandateRefused as exc:
            return self._reject(draft_id, p_hash, "POLICY", exc.reason)
        # Ids, amounts and choices — no names: the chain is hard to redact.
        self.audit.append(AuditEntryType.MANDATE_CREATED, {
            "draft_id": draft_id, "payload_hash": p_hash, "mandate_id": terms.mandate_id,
            "version": terms.version, "user_id": terms.user_id, "credential_id": credential_id,
            "biller_id": terms.biller_id, "biller_ref_version": terms.biller_ref_version,
            "source_account": terms.source_account, "amount_cents": terms.amount_cents,
            "frequency": terms.frequency, "start_date": terms.start_date,
            "occurrence_count": terms.occurrence_count, "total_cap_cents": terms.total_cap_cents,
            "supervised_approvals": terms.supervised_approvals,
            "auto_after_supervised": terms.auto_after_supervised,
            "valid_until": terms.valid_until})
        return {"accepted": True, "draft_id": draft_id, "payload_hash": p_hash,
                "execution": result, "mandate_id": terms.mandate_id}

    def _credential_user(self, credential_id: str) -> str | None:
        cred = self.credentials.get(credential_id)
        user = getattr(cred, "user_id", None)
        if user is None:
            user = getattr(self.credentials, "user_of", lambda _c: None)(credential_id)
        return user

    def _mandate_setup_refusal(self, terms: RecurringBillMandate) -> tuple[str, str] | None:
        db = self.executor.db_path
        if safety.kill_switch_engaged(terms.user_id, db_path=db) is not None:
            return ("KILL_SWITCH", "your payments are frozen, so nothing new can be set up — "
                                   "unfreeze them with a code on your phone first")
        conn = connect(db)
        try:
            user = conn.execute("SELECT kyc_status FROM users WHERE id=?",
                                (terms.user_id,)).fetchone()
            acct = conn.execute("SELECT user_id FROM accounts WHERE id=?",
                                (terms.source_account,)).fetchone()
            cap = conn.execute("SELECT value FROM limits WHERE key='per_transaction'").fetchone()
            biller_ok = billers.matches(conn, terms.biller_id, terms.biller_ref_version,
                                        terms.biller_ref_hash)
        finally:
            conn.close()
        if user is None or str(user["kyc_status"]).upper() != "VERIFIED":
            return ("POLICY", "your identity verification is still pending, so payments are on hold")
        if acct is None or acct["user_id"] != terms.user_id:
            return ("POLICY", "the account to pay from isn't yours")
        if not biller_ok:
            return ("SUPERSEDED", f"{terms.biller_display}'s payment details changed after this "
                                  "was drafted — review them again")
        if cap and terms.amount_cents > int(cap["value"]):
            return ("POLICY", "each payment is over your per-transaction limit")
        first = schedule.due_at(terms.due_dates()[0], terms.timezone)
        if first <= recurring_clock.now(db_path=db):
            return ("STATE", "the first payment date has already passed — set it up again")
        return None

    def run_mandate_occurrence(self, mandate_id: str, seq: int, *, now: int) -> dict:
        """Pay one occurrence of a mandate in its AUTOMATIC phase — the only
        path that moves money without a signature over the payment itself.

        Its authority is the signed mandate, and only within it: the stored
        terms must still hash to what was signed, the mandate must be ACTIVE
        and in AUTO mode (switched by the server after the user's third
        individually signed payment, and only because the signed terms say the
        user chose that), it must be the occurrence's due date, and the count,
        the caps, the biller's reference and the account owner must all hold.
        Then today's rules, exactly as for a signed payment: KYC, the kill
        switch, the policy engine and the scam rules. Anything that would need
        the user — a hold, a phone code, an escalation, any scam signal — makes
        the occurrence NEEDS_REVIEW or HELD, and nothing is paid unattended.
        The executor re-checks the mandate under its write lock and claims the
        occurrence's execution key with the debit: at most one debit, however
        many workers or retries."""
        db = self.executor.db_path
        conn = connect(db)
        try:
            m = recurring.get_mandate(conn, mandate_id)
            occ = recurring.occurrence(conn, mandate_id, seq)
        finally:
            conn.close()
        if m is None or occ is None:
            return {"status": "UNKNOWN", "mandate_id": mandate_id, "seq": seq}
        prior = self.executor.prior_execution(occ["draft_id"])
        if prior is not None:                       # a retry, a second worker, a restart
            return {"status": "ALREADY", "mandate_id": mandate_id, "seq": seq,
                    "execution": prior["result"], "executed_at": prior["executed_at"]}
        terms = recurring.load_terms(m)
        if terms is None:
            return self._occurrence_stop(m, occ, None, "HELD", "INTEGRITY",
                                         "the stored arrangement doesn't match what you signed.",
                                         now=now, suspend=True)
        if m["status"] != "ACTIVE" or occ["status"] != "SCHEDULED" or occ["phase"] != "AUTO":
            return {"status": "NOT_RUNNABLE", "mandate_id": mandate_id, "seq": seq,
                    "mandate_status": m["status"], "occurrence_status": occ["status"]}
        if (m["mode"] != "AUTO" or not terms.auto_after_supervised
                or m["supervised_successes"] < terms.supervised_approvals):
            return self._occurrence_stop(m, occ, terms, "NEEDS_REVIEW", "NOT_AUTO",
                                         "automatic payment isn't switched on for it.", now=now)
        if now < occ["due_at"]:
            return {"status": "NOT_DUE", "mandate_id": mandate_id, "seq": seq}
        if now > occ["auto_until"] or now > terms.valid_until:
            return self._occurrence_stop(m, occ, terms, "MISSED", "MISSED",
                                         "it couldn't be run on its due date.", now=now)
        if (m["paid_count"] >= terms.occurrence_count
                or m["paid_total_cents"] + terms.amount_cents > terms.total_cap_cents):
            return self._occurrence_stop(m, occ, terms, "HELD", "CAP",
                                         "it would go over the arrangement's limit.", now=now)
        conn = connect(db)
        try:
            biller_ok = billers.matches(conn, terms.biller_id, terms.biller_ref_version,
                                        terms.biller_ref_hash)
            acct = conn.execute("SELECT user_id, balance FROM accounts WHERE id=?",
                                (terms.source_account,)).fetchone()
            user = conn.execute("SELECT kyc_status FROM users WHERE id=?",
                                (terms.user_id,)).fetchone()
        finally:
            conn.close()
        if not biller_ok:
            return self._occurrence_stop(
                m, occ, terms, "HELD", "BILLER_CHANGED",
                f"{terms.biller_display}'s payment details changed since you set this up.",
                now=now, suspend=True)
        if acct is None or acct["user_id"] != terms.user_id:
            return self._occurrence_stop(m, occ, terms, "HELD", "ACCOUNT",
                                         "the account to pay from isn't yours any more.",
                                         now=now, suspend=True)
        if user is None or str(user["kyc_status"]).upper() != "VERIFIED":
            return self._occurrence_stop(m, occ, terms, "HELD", "KYC",
                                         "your identity verification is pending.", now=now)
        if safety.kill_switch_engaged(terms.user_id, db_path=db) is not None:
            return self._occurrence_stop(m, occ, terms, "HELD", "KILL_SWITCH",
                                         "your payments are frozen.", now=now)

        real_now = int(time.time())     # policy and scam rules keep real time
        plan = occurrence_plan(terms, draft_id=occ["draft_id"], seq=seq,
                               due=schedule.parse_date(occ["due_date"]), now=real_now)
        p_hash = payload_hash(plan)
        verdicts = evaluate(plan, load_context(terms.user_id,
                                               db_path=self.policy_db_path or db, now=real_now))
        self.audit.append(AuditEntryType.POLICY, verdicts.to_audit_payload(occ["draft_id"]))
        if verdicts.blocked:
            return self._occurrence_stop(m, occ, terms, "HELD", "POLICY",
                                         "; ".join(verdicts.reasons()), now=now)
        if verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION:
            return self._occurrence_stop(m, occ, terms, "NEEDS_REVIEW", "POLICY",
                                         "it needs an extra confirmation from you: "
                                         + "; ".join(verdicts.reasons()), now=now)
        assessment = scam.reassess(plan, terms.user_id, db_path=db, now=real_now,
                                   recent_change_hours=self.recent_change_hours,
                                   cooling_hours=self.cooling_hours, draft_id=occ["draft_id"])
        self.audit.append(AuditEntryType.SCAM_ASSESSMENT,
                          {"stage": "mandate", "payload_hash": p_hash, **assessment.to_audit()})
        if assessment.outcome != scam.ALLOW or assessment.signals:
            # Unattended payment needs a clean slate: ANY scam signal (a new
            # passkey, the freeze just turned off, stopped attempts) means the
            # user decides this one.
            why = "; ".join(s.detail for s in assessment.signals) or assessment.outcome
            return self._occurrence_stop(m, occ, terms, "NEEDS_REVIEW", "SCAM",
                                         f"something on your account needs a look first ({why}).",
                                         now=now)
        if acct["balance"] < terms.amount_cents:
            return self._occurrence_stop(m, occ, terms, "FAILED", "FUNDS",
                                         f"there isn't enough money in {terms.source_display}.",
                                         now=now)

        # Audit-critical: if the log can't take this entry, the exception
        # propagates and nothing is debited.
        self.audit.append(AuditEntryType.MANDATE_OCCURRENCE, {
            "mandate_id": mandate_id, "seq": seq, "draft_id": occ["draft_id"],
            "payload_hash": p_hash, "stage": "executing", "authority": recurring.MANDATE})
        try:
            result = self.executor.execute(plan, payload_hash=p_hash,
                                           authority=recurring.MANDATE, now=now)
        except AlreadyExecuted as exc:
            return {"status": "ALREADY", "mandate_id": mandate_id, "seq": seq,
                    "execution": exc.prior["result"], "executed_at": exc.prior["executed_at"]}
        except MandateRefused as exc:
            return self._occurrence_stop(m, occ, terms, "HELD", "MANDATE", exc.reason + ".",
                                         now=now)
        self.audit.append(AuditEntryType.EXECUTION, {
            "draft_id": occ["draft_id"], "payload_hash": p_hash, "outcome": result["status"],
            "legs": result["legs"], "authority": recurring.MANDATE,
            "mandate_id": mandate_id, "mandate_version": terms.version, "seq": seq})
        return {"status": result["status"], "mandate_id": mandate_id, "seq": seq,
                "execution": result}

    def _occurrence_stop(self, m: dict, occ: dict, terms, to: str, code: str, reason: str, *,
                         now: int, suspend: bool = False) -> dict:
        """An automatic occurrence that won't be paid: record why, tell the
        user, and (for a change only new terms can fix) suspend the mandate."""
        db = self.executor.db_path
        conn = connect(db)
        try:
            conn.execute("BEGIN IMMEDIATE")
            moved = recurring.set_occurrence(conn, m["mandate_id"], occ["seq"], frm=("SCHEDULED",),
                                             to=to, now=now, reason=reason, phase="AUTO")
            if moved and terms is not None:
                what = recurring.describe(terms, occ["seq"])
                until = schedule.label(schedule.local_date(occ["review_until"], terms.timezone))
                title, body = {
                    "HELD": (f"{terms.biller_display} payment {occ['seq']} on hold",
                             f"{what} was NOT paid: {reason} You can review it and approve it "
                             f"yourself until {until}."),
                    "NEEDS_REVIEW": (f"{terms.biller_display} payment {occ['seq']} needs you",
                                     f"{what} was NOT paid automatically: {reason} Open it to "
                                     f"approve it with your passkey, until {until}."),
                    "FAILED": (f"{terms.biller_display} payment {occ['seq']} failed",
                               f"{what} was NOT paid: {reason} It won't be retried — pay it "
                               f"yourself if you need to."),
                    "MISSED": (f"{terms.biller_display} payment {occ['seq']} missed",
                               f"{what} was NOT paid: {reason} It won't be paid late — pay it "
                               f"yourself if you need to."),
                }[to]
                recurring.notify(conn, m["user_id"], to, title, body, now=now,
                                 mandate_id=m["mandate_id"], seq=occ["seq"])
            if suspend:
                recurring.suspend(conn, m, terms, reason[:1].upper() + reason[1:], now=now)
            conn.commit()
        finally:
            conn.close()
        self.audit.append(AuditEntryType.MANDATE_OCCURRENCE, {
            "mandate_id": m["mandate_id"], "seq": occ["seq"], "draft_id": occ["draft_id"],
            "stage": "stopped", "status": to, "code": code, "suspended": suspend})
        return {"status": to, "code": code, "reason": reason, "mandate_id": m["mandate_id"],
                "seq": occ["seq"]}

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

    def release_due(self, now: int | None = None) -> list[dict]:
        """Run every scheduled (large) payment whose wait is over. Each was
        signed and passed every check when scheduled; the freeze and policy
        are checked again now, because the ledger may have moved. A cancel in
        the window already recorded CANCELLED in the executions table, so the
        executor refuses the payment and nothing is sent."""
        now = int(time.time()) if now is None else now
        db = self.executor.db_path
        done = []
        for row in safety.claim_due_releases(now, db_path=db):
            draft_id, p_hash = row["draft_id"], row["payload_hash"]
            plan = ResolvedPlan.model_validate_json(row["payload"])
            stop = None
            if safety.kill_switch_engaged(row["user_id"], db_path=db) is not None:
                stop = "kill switch"
            elif self.policy_db_path is not None:
                verdicts = evaluate(plan, load_context(row["user_id"], db_path=self.policy_db_path))
                self.audit.append(AuditEntryType.POLICY, verdicts.to_audit_payload(draft_id))
                if verdicts.blocked:
                    stop = "policy: " + "; ".join(verdicts.reasons())
            if stop is None:
                try:
                    result = self.executor.execute(plan, payload_hash=p_hash)
                except AlreadyExecuted:              # cancelled in the window
                    safety.set_release_status(draft_id, ("RUNNING",), "CANCELLED", db_path=db)
                    attempts.mark(draft_id, attempts.STOPPED, now=now, db_path=db)
                    done.append({"draft_id": draft_id, "status": "CANCELLED"})
                    continue
                except DestinationChanged:
                    stop = "the payee's number changed"
                else:
                    safety.set_release_status(draft_id, ("RUNNING",), "SENT", db_path=db)
                    attempts.mark(draft_id, attempts.SENT, now=now, db_path=db)
                    self.audit.append(AuditEntryType.EXECUTION, {
                        "draft_id": draft_id, "payload_hash": p_hash,
                        "outcome": result["status"], "legs": result["legs"], "delayed": True})
                    draft = self.drafts.get(draft_id) if hasattr(self.drafts, "get") else None
                    if draft is not None:
                        draft.status = "executed"
                    done.append({"draft_id": draft_id, "status": "SENT", "execution": result})
                    continue
            try:
                self.executor.close(draft_id, "payment", p_hash, "CANCELLED")
            except AlreadyExecuted:
                pass
            safety.set_release_status(draft_id, ("RUNNING",), "CANCELLED", db_path=db)
            attempts.mark(draft_id, attempts.STOPPED, now=now, db_path=db)
            self.audit.append(AuditEntryType.DRAFT_CANCELLED, {
                "draft_id": draft_id, "payload_hash": p_hash, "prior_status": "scheduled",
                "by": stop})
            draft = self.drafts.get(draft_id) if hasattr(self.drafts, "get") else None
            if draft is not None:
                draft.status = "cancelled"
            done.append({"draft_id": draft_id, "status": "CANCELLED", "reason": stop})
        return done

    def _scam_protection(self, plan: ResolvedPlan, draft_id: str, p_hash: str,
                         owner: str | None, confirm_name: str | None = None):
        """((rejection, reason) or None, the scam outcome that binds or None).
        Reads the ledger, never the request: `owner` is derived from the
        account rows being debited."""
        db = self.executor.db_path
        now = int(time.time())

        # The kill switch: the user froze all outgoing payments.
        if owner and safety.kill_switch_engaged(owner, db_path=db) is not None:
            return ("KILL_SWITCH", "your payments are frozen — nothing was sent. Unfreeze "
                                   "them with a code on your phone first"), None

        refused = destination_refusal(plan, db)
        if refused is not None:
            return refused, None

        # The scam score, re-run like policy. The draft's own outcome still
        # binds (a lower score now does not lift the hold the user was shown),
        # a HIGHER one the draft never arranged refuses (RESCORED), and a hold
        # on this draft is honoured whatever either score says.
        if not owner:
            return None, None                    # policy refuses an ownerless plan below
        drafted = getattr(self.drafts, "scam_outcome_of", lambda _d: None)(draft_id)
        transcript = getattr(self.drafts, "transcript_of", lambda _d: "")(draft_id) or ""
        assessment = scam.reassess(plan, owner, db_path=db, now=now, transcript=transcript,
                                   recent_change_hours=self.recent_change_hours,
                                   cooling_hours=self.cooling_hours, draft_id=draft_id,
                                   unanswered=getattr(self.drafts, "unanswered_of",
                                                      lambda _d: False)(draft_id))
        self.audit.append(AuditEntryType.SCAM_ASSESSMENT,
                          {"stage": "gateway", "payload_hash": p_hash, **assessment.to_audit()})
        outcome = scam.stricter(drafted, assessment.outcome)

        def refuse(kind, reason):
            return (kind, reason), outcome
        if outcome == scam.BLOCK:
            return refuse("BLOCKED", "this payment was stopped because it shows several signs "
                                     "of a scam — nothing was sent. To make it, call your bank")
        asked = getattr(self.drafts, "purpose_of", lambda _d: None)(draft_id) is not None
        if (scam.rose_past_drafted(drafted, assessment.outcome)
                or scam.asks_unasked(assessment, asked)):
            return refuse("RESCORED", "this payment looks riskier than when it was drafted — "
                                      "cancel it and ask again; nothing was sent")
        hold = safety.get_hold(draft_id, db_path=db)
        if hold is None and scam.needs_hold(outcome):
            return refuse("HOLD_REQUIRED", "this payment now needs a safety hold — cancel it "
                                           "and ask again; nothing was sent")
        if hold is not None:
            if hold["status"] == "CANCELLED":
                return refuse("STATE", "this payment's hold was cancelled — nothing was sent")
            if not safety.hold_covers(hold, p_hash):
                # The hold was for another payload on this draft (an answer
                # changed it) and this one's wait was never recorded.
                return refuse("HOLD_REQUIRED", "this payment's safety hold was for a different "
                                               "payment — cancel it and ask again; nothing was sent")
            if now < int(hold["release_at"]):
                return refuse("HELD", f"this payment is on a safety hold for "
                                      f"{int(hold['release_at']) - now} more seconds — nothing "
                                      f"was sent")
        if outcome == scam.HOLD_STEP_UP:
            if not (self.step_up is not None and self.step_up.is_confirmed(draft_id, p_hash)):
                return refuse("CONFIRMATION", "this payment needs the code sent to your phone first")
            # The name the card asked for with this payload, else the payee
            # the risk points at now. A name the page never collected fails here.
            expected = (getattr(self.drafts, "confirm_name_of", lambda *_: None)(draft_id, p_hash)
                        or assessment.riskiest_payee)
            if expected and not scam.name_confirmed(confirm_name, expected):
                return refuse("CONFIRMATION", "this payment needs the payee's name typed in "
                                              "first — nothing was sent")
        return None, outcome

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
