"""
WebAuthn — transaction signing only. (brief Section 4.5 / Section 8)

WebAuthn signs the canonical payload hash (+ a draft-bound, single-use,
120s-TTL server nonce). userVerification="required" so the real device
biometric is used. Uses the Duo `webauthn` library (publishes to PyPI as
`webauthn`; imports as `webauthn`).

HONEST LIMITATION (state in the pitch, don't hide it):
    The OS biometric prompt does NOT display transaction details; the
    authenticator signs a blind hash. "What you see is what you sign" depends
    on our overlay being rendered deterministically from the same canonical
    payload -- a client-integrity assumption, NOT a cryptographic guarantee.
    The recomputed-hash binding (the browser derives payload_hash itself and
    the server verifies against its own) makes that assumption as strong as it
    can be. The out-of-band confirmation for high-value transactions closes the
    residual gap, being the only channel independent of a possibly-compromised
    renderer.

NOTE: WebAuthn is for TRANSACTION SIGNING only. App login is a mock session
(pick a seeded user) -- different ceremony, different nonce/UV flow.
"""
from backend.auth.credentials import (
    MockCredentialStore,
    WebAuthnCredentialStore,
    WebAuthnCredential,
)
from backend.auth.webauthn import (
    registration_options,
    verify_registration,
    verify_assertion,
)

__all__ = [
    "MockCredentialStore",
    "WebAuthnCredentialStore",
    "WebAuthnCredential",
    "registration_options",
    "verify_registration",
    "verify_assertion",
]
