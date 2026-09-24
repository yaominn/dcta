"""
The signature verification seam. (brief Section 4.5; gateway accepts only
(payload, signature) per Section 4.2)

Two verifiers, ONE interface the gateway calls:

    verify(credential, signature, challenge_hex) -> bool

  - MockSigner       : HMAC-SHA256 over the challenge hex with a shared test
                       secret. M1 only; exercises the full verify -> execute ->
                       log path before any real biometric exists.
  - WebAuthnVerifier : real WebAuthn assertion verification via
                       webauthn.verify_authentication_response (M2). The
                       "signature" is the assertion bundle; the challenge_hex
                       is sha256(payload_hash + nonce), which the server
                       re-derives INDEPENDENTLY of the browser. require_user_
                       verification=True rejects a non-biometric assertion;
                       the sign-count check is replay protection. On success
                       the stored sign count is advanced.

The gateway code that calls verify() does not change between M1 and M2 -- the
swap is a body-only change to this seam, exactly as designed.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets

from backend.auth.webauthn import verify_assertion


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


class WebAuthnVerifier:
    """Verifies real WebAuthn assertions. The gateway calls verify() exactly as
    it does for the mock signer; here `credential` is the WebAuthnCredential
    (COSE key + current sign count) the credential store returned, `signature`
    is the assertion bundle the browser produced, and `challenge_hex` is the
    server's own sha256(payload_hash + nonce). On success the stored sign count
    is advanced (the library's replay signal for counter-using authenticators)."""

    def __init__(self, *, credential_store, rp_id: str, expected_origin: str):
        self.credential_store = credential_store
        self.rp_id = rp_id
        self.expected_origin = expected_origin

    def verify(self, credential, signature, challenge_hex: str) -> bool:
        # The gateway rejects None credential / missing signature before here,
        # but defend anyway: a bad assertion must never raise past the boundary.
        if credential is None or not signature:
            return False
        try:
            new_count = verify_assertion(
                assertion_payload=signature,
                expected_challenge=bytes.fromhex(challenge_hex),
                rp_id=self.rp_id,
                expected_origin=self.expected_origin,
                credential_public_key=credential.public_key,
                credential_current_sign_count=credential.sign_count,
            )
            self.credential_store.update_sign_count(
                credential.credential_id, new_count
            )
            return True
        except Exception:
            # Any verification failure (bad signature, wrong challenge, UV
            # flag unset, sign count not advancing, wrong RP/origin) -> reject.
            return False
