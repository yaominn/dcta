"""
Independent Validation Agent (read-only). (brief Section 5 / Section 8)

Audits the resolved draft against the raw transcript. Combines:
  - deterministic checks (amounts extracted from transcript by rules, payee
    mentions matched against the payee list), and
  - an LLM check with a SEPARATE prompt.
Any discrepancy in beneficiary, amount, asset class or source account FREEZES
the transaction and alerts the user.

SCOPE OF THE INDEPENDENCE CLAIM (do not overstate to judges):
    The LLM half reads the same transcript as the parser, so it shares that
    input's failure modes; a spoken injection can target both. The validator
    catches model error, drift and mis-parse. It does NOT defend against
    transcript-borne injection — that is handled architecturally, because the
    user must still sign. (brief Section 5)

# TODO: Milestone 6 — draft-vs-transcript validation, freeze on mismatch.
"""
