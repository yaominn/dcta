"""
Deterministic Resolver + clarify loop. (brief Section 8: backend/resolver/)

Responsibility: take the LLM's symbolic IntentPlan and resolve every field to
a concrete, verified value. PURE deterministic code, no LLM.
  - Payee mention -> payee_id (0 matches: ask; 1: proceed; 2+: disambiguate).
  - Symbolic amounts ({ref, op}) -> concrete numbers against the ledger.
  - Equity: floor to WHOLE shares; keep remainder in the source account.
  - "unresolved" fields are NEVER guessed — they trigger a clarifying question.

# TODO: Milestone 4 — payee matching, amount resolution, one-question clarify loop.
"""
