"""
The execution gateway — the one chokepoint funds pass through.
(brief Section 4.2: accepts only (payload, signature); 4.5: verifies signature,
payload hash and nonce; 4.1: sequential execution, stop at first failure.)

submit() verifies, in order:
  1. nonce  — draft-bound, fresh, single-use (swap-after-approval & replay blocked)
  2. signature — over the canonical challenge hash, against a registered public key
  3. execute — on the mock ledger, marking later legs BLOCKED on first failure

Every step is logged to the hash-chained audit log. A request with a missing or
bad signature, or a replayed/expired/swapped nonce, is REJECTED and LOGGED — so
even a fully compromised LLM can do nothing here without a valid human
signature. That is the whole point of the trust boundary.
"""
from __future__ import annotations

from backend.audit.canonical import payload_hash, challenge_hash
from backend.audit.log import AuditLog, AuditEntryType
from backend.gateway.nonce import NonceStore, NonceError
from backend.gateway.signer import MockSigner
from backend.gateway.executor import MockExecutor
from backend.auth.credentials import MockCredentialStore
from backend.models.schemas import ResolvedPlan


class Gateway:
    def __init__(
        self,
        *,
        signer: MockSigner,
        nonce_store: NonceStore,
        audit: AuditLog,
        executor: MockExecutor,
        credentials: MockCredentialStore,
    ):
        self.signer = signer
        self.nonce_store = nonce_store
        self.audit = audit
        self.executor = executor
        self.credentials = credentials

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

        # 1. nonce — draft-bound, single-use, TTL. Consumed here: a failed attempt
        #    burns the nonce (one signing attempt per nonce; re-request to retry).
        try:
            self.nonce_store.consume(nonce, draft_id)
        except NonceError as exc:
            return self._reject(draft_id, p_hash, "NONCE", str(exc))

        # 2. signature — over the canonical challenge, against a registered key.
        pubkey = self.credentials.get(credential_id)
        if pubkey is None:
            return self._reject(draft_id, p_hash, "SIGNATURE", "unknown credential")
        if not signature:
            return self._reject(draft_id, p_hash, "SIGNATURE", "missing signature")
        if not self.signer.verify(pubkey, signature, challenge):
            return self._reject(draft_id, p_hash, "SIGNATURE", "bad signature")

        # 3. execute on the mock ledger.
        result = self.executor.execute(resolved_plan)
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

    def _reject(self, draft_id: str, p_hash: str, kind: str, reason: str) -> dict:
        self.audit.append(
            AuditEntryType.SIGNATURE,
            {"draft_id": draft_id, "payload_hash": p_hash,
             "rejection": kind, "reason": reason},
        )
        return {"accepted": False, "draft_id": draft_id,
                "payload_hash": p_hash, "rejection": kind, "reason": reason}
