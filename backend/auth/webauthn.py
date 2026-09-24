"""
WebAuthn ceremony helpers — transaction signing only. (brief Section 4.5 / 8)

Wraps the `webauthn` library (the Duo lib; publishes to PyPI as `webauthn`,
imports as `webauthn`). Three ceremonies:

  - registration (begin/complete): a user enrolls a platform authenticator
    (fingerprint/face). The resulting COSE public key is stored; the gateway
    later verifies assertions against it. userVerification=REQUIRED, so only a
    UV-capable authenticator may enroll.
  - signing: the browser recomputes payload_hash from the rendered
    ResolvedPlan (frontend/canonical.js), builds the challenge
    sha256(payload_hash + server_nonce) ITSELF, and asks the authenticator to
    sign it with userVerification="required". The server re-derives the SAME
    challenge from its own payload_hash + the nonce and verifies the assertion
    against it — so a compromised renderer cannot make the user sign something
    else ("what you see is what you sign" is a property, not a convention).
  - assertion verification: verify_authentication_response with
    require_user_verification=True (the UV flag in authenticatorData is checked;
    a non-biometric assertion is rejected) and the sign-count replay check.

HONEST LIMITATION (state in the pitch): the OS biometric prompt signs a BLIND
hash; it does not display transaction details. "What you see is what you sign"
rests on the overlay rendering deterministically from the same canonical
payload the hash covers -- a client-integrity assumption, not a cryptographic
guarantee. The recomputed-hash binding here makes that assumption as strong as
it can be: the server verifies the authenticator signed a challenge derived
from the payload the browser displayed.
"""
from __future__ import annotations

from webauthn import (
    generate_registration_options,
    verify_registration_response,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers import generate_challenge
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
)


def registration_options(
    *, rp_id: str, rp_name: str, user_id: str, username: str,
) -> tuple[str, bytes]:
    """Build a PublicKeyCredentialCreationOptions for a user.

    Returns (options_json_for_the_browser, challenge_bytes_to_remember). The
    challenge is server-issued and verified on completion (anti-replay for the
    registration ceremony itself). UV=REQUIRED so a non-biometric authenticator
    cannot enroll.
    """
    challenge = generate_challenge()  # 32 random bytes
    opts = generate_registration_options(
        rp_id=rp_id,
        rp_name=rp_name,
        user_id=user_id.encode("utf-8"),  # user handle (mock demo; spec prefers opaque)
        user_name=username,
        challenge=challenge,
        authenticator_selection=AuthenticatorSelectionCriteria(
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
    )
    return options_to_json(opts), challenge


def verify_registration(
    *, credential_payload: dict | str, expected_challenge: bytes,
    rp_id: str, expected_origin: str,
) -> tuple[bytes, bytes, int]:
    """Verify a registration response. Returns (credential_id, public_key,
    sign_count) to store. Raises on any failure (bad challenge, wrong RP/origin,
    missing UV, unsupported attestation)."""
    verified = verify_registration_response(
        credential=credential_payload,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        require_user_verification=True,
    )
    return (
        verified.credential_id,
        verified.credential_public_key,
        verified.sign_count,
    )


def verify_assertion(
    *, assertion_payload: dict | str, expected_challenge: bytes,
    rp_id: str, expected_origin: str,
    credential_public_key: bytes, credential_current_sign_count: int,
) -> int:
    """Verify a WebAuthn assertion. Returns the new sign count to store.

    expected_challenge is sha256(payload_hash + nonce) as bytes -- the server
    re-derives it independently of the browser. require_user_verification=True
    rejects an assertion whose authenticatorData UV flag is unset (no biometric).
    The library raises (ImpersonationError) if the sign count did not advance
    on a counter-using authenticator -- replay protection.
    """
    verified = verify_authentication_response(
        credential=assertion_payload,
        expected_challenge=expected_challenge,
        expected_rp_id=rp_id,
        expected_origin=expected_origin,
        credential_public_key=credential_public_key,
        credential_current_sign_count=credential_current_sign_count,
        require_user_verification=True,
    )
    return verified.new_sign_count
