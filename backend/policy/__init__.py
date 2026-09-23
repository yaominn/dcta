"""
Policy Engine. (brief Section 8: backend/policy/)

Responsibility: PURE deterministic functions, no LLM. Enforces:
  - KYC gate (unverified users cannot transact; equity needs investment-eligible)
  - per-transaction + daily limits
  - velocity throttling (rate-limit frequent small transfers)
  - amount anomaly (flag amounts far above this user's median with this payee)

# TODO: Milestone 5 — KYC, limits, velocity, anomaly checks.
"""
