"""
WebAuthn — transaction signing only. (brief Section 4.5 / Section 8)

WebAuthn signs the canonical payload hash (+ a draft-bound, single-use,
120s-TTL server nonce). userVerification="required" so the real device
biometric is used. Uses py_webauthn.

HONEST LIMITATION (state in the pitch, don't hide it):
    The OS biometric prompt does NOT display transaction details; the
    authenticator signs a blind hash. "What you see is what you sign" depends
    on our overlay being rendered deterministically from the same canonical
    payload — a client-integrity assumption, NOT a cryptographic guarantee.
    The out-of-band confirmation for high-value transactions closes this gap,
    because it is the only channel independent of a possibly-compromised renderer.

NOTE: WebAuthn is for TRANSACTION SIGNING only. App login is a mock session
(pick a seeded user) — different ceremony, different nonce/UV flow.

Milestone 1 ships the # MOCK credential store here so the gateway can verify
against a test key; Milestone 2 adds real WebAuthn registration + signing.
"""
from backend.auth.credentials import MockCredentialStore

__all__ = ["MockCredentialStore"]
