"""
The signature verification seam. (brief Section 4.5; gateway accepts only
(payload, signature) per Section 4.2)

# MOCK: this stands in for py_webauthn in Milestone 2. The interface the
gateway calls is:

    verify(public_key: str, signature_hex: str, challenge_hex: str) -> bool

In M2 the BODY of verify() becomes webauthn.verify_authentication_response(...)
against a registered COSE public key, while the gateway code that calls it does
not change. Building against this mock now lets us test the full
verify -> execute -> log path end to end in M1, before any real biometric
exists.

Why HMAC here (not asymmetric): real WebAuthn is asymmetric (device private key
signs, registered public key verifies). A symmetric HMAC mock is fine because we
are only exercising the gateway's control flow and the audit binding — the
cryptographic realism is M2's job. The verify() shape matches, so the swap is a
body-only change.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets


class MockSigner:
    """# MOCK: HMAC-SHA256 over the challenge hex with a shared test secret."""

    def __init__(self, secret: bytes | None = None):
        self._secret = secret or secrets.token_bytes(32)

    @property
    def public_key(self) -> str:
        """Credential identifier the mock credential store maps to this signer. # MOCK"""
        return "mock-pubkey"

    def sign(self, challenge_hex: str) -> str:
        """Produce a signature over the canonical challenge. # MOCK (dev/test only)."""
        return hmac.new(self._secret, challenge_hex.encode(), hashlib.sha256).hexdigest()

    def verify(self, public_key: str, signature_hex: str, challenge_hex: str) -> bool:
        if public_key != self.public_key:
            return False
        expected = self.sign(challenge_hex)
        return hmac.compare_digest(expected, signature_hex)
