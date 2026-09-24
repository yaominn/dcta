"""
Gateway — signature verification + mock ledger execution. (brief Section 8)

Accepts ONLY (payload, signature). Verifies signature, payload hash and nonce.
Rejects everything else. (brief Section 4.2)

# MOCK: the "bank execution" here is a write against the simulated SQLite ledger.
        No real DBS APIs. (brief Section 12)

Built in Milestone 1 FIRST, before the LLM, deliberately — the trust boundary
must not depend on anything the LLM does.
"""
from backend.gateway.gateway import Gateway
from backend.gateway.nonce import NonceStore, NonceError
from backend.gateway.signer import MockSigner, WebAuthnVerifier
from backend.gateway.executor import MockExecutor

__all__ = [
    "Gateway",
    "NonceStore",
    "NonceError",
    "MockSigner",
    "WebAuthnVerifier",
    "MockExecutor",
]
