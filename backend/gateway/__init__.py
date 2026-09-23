"""
Gateway — signature verification + mock ledger execution. (brief Section 8)

Accepts ONLY (payload, signature). Verifies signature, payload hash and nonce.
Rejects everything else. (brief Section 4.2)

# MOCK: the "bank execution" here is a write against the simulated SQLite ledger.
        No real DBS APIs. (brief Section 12)

# TODO: Milestone 1 — canonical payload + SHA-256, signature/nonce verification,
        mock execution. Built FIRST, before the LLM, deliberately — the trust
        boundary must not depend on anything the LLM does.
"""
