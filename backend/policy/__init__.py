"""
Policy Engine. (brief Section 8: backend/policy/)

PURE deterministic functions, no LLM. Runs AFTER the resolver and BEFORE the
confirmation overlay, over a concrete `ResolvedPlan`:

  - KYC gate (unverified users cannot transact; equity needs investment-eligible)
  - per-transaction + daily limits
  - velocity throttling (rate-limit frequent transfers)
  - amount anomaly (flag amounts far above this user's median with this payee)

Precedence is explicit and documented in engine.py: KYC -> per-transaction ->
daily -> velocity -> anomaly, first BLOCK wins, and anomaly can only escalate
to REQUIRE_EXTRA_CONFIRMATION. The engine never mutates the plan — the plan is
what gets hashed and signed.

WHERE IT IS ENFORCED (the part that matters):

    Checking policy before rendering the overlay is UX. The enforcement point
    is `gateway.submit()`, which re-runs the same evaluation against the same
    ledger after verifying the signature and before executing. Without that,
    a caller who assembled or replayed a signed payload could skip the overlay
    path entirely and the policy engine would be advisory. The gateway is the
    one place funds pass through (brief 4.2), so it is the one place a limit
    can actually be a limit.

TRUST BOUNDARY (enforced by tests/test_import_boundary.py):
    backend/policy/  MUST NOT transitively import  backend/agent/
Deterministic means deterministic: no path from a risk decision to the LLM.
"""
from backend.policy.context import load_context, owner_of
from backend.policy.engine import (
    ANOMALY_MULTIPLE,
    Decision,
    PolicyContext,
    PolicyResult,
    Verdict,
    check_anomaly,
    check_daily,
    check_kyc,
    check_per_transaction,
    check_velocity,
    evaluate,
)

__all__ = [
    "ANOMALY_MULTIPLE", "Decision", "PolicyContext", "PolicyResult", "Verdict",
    "check_anomaly", "check_daily", "check_kyc", "check_per_transaction",
    "check_velocity", "evaluate", "load_context", "owner_of",
]
