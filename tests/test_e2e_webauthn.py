"""
M2 acceptance test — real WebAuthn approves a hard-coded transfer, end to end.

Drives a real Chromium with a CDP *virtual authenticator* (isUserVerified=True,
isUserConsenting=True) as "mock biometrics" per brief §2. The full ceremony runs
through the REAL frontend (no API shortcuts):

  register passkey  ->  overlay renders the demo plan  ->  biometric sign  ->
  gateway executes  ->  hash-chained audit verifies

The virtual authenticator auto-approves (UV flag set, presence simulated), so the
assertion the gateway verifies is a GENUINE WebAuthn assertion over
sha256(payload_hash + nonce), produced by a real authenticator implementation —
not a mock. This is the proof that the JS canonicalizer, the challenge binding,
the credential store, and the verifier all agree end to end.

Brief §2: "where real biometric authentication is not available, virtual
authenticators ... are acceptable as mock biometrics." Brief §10 WebAuthn
warning: localhost works over HTTP (a secure context); a deployed demo link
needs HTTPS and a matching RP id.
"""
from __future__ import annotations

import pytest
import requests

pytest.importorskip("playwright")
from playwright.sync_api import sync_playwright  # noqa: E402


def _add_virtual_authenticator(client) -> str:
    """Enable the CDP WebAuthn domain and add a platform (ctap2/internal)
    authenticator that auto-verifies + auto-consents -> "mock biometrics"."""
    client.send("WebAuthn.enable", {})
    res = client.send("WebAuthn.addVirtualAuthenticator", {
        "options": {
            "protocol": "ctap2",
            "transport": "internal",
            "hasResidentKey": True,
            "hasUserVerification": True,
            "isUserVerified": True,
            "isUserConsenting": True,
            "automaticPresenceSimulation": True,
        },
    })
    return res["authenticatorId"]


def test_real_webauthn_approves_hardcoded_transfer(server_url):
    """THE M2 acceptance test: a real (virtual) biometric approves the
    hard-coded $500 transfer to Mom, end to end — register, render, sign,
    execute, audit-verify — through the real frontend, not via API shortcuts."""
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        client = page.context.new_cdp_session(page)
        auth_id = _add_virtual_authenticator(client)
        try:
            page.goto(server_url + "/")
            page.wait_for_selector("#register-btn", state="visible", timeout=10000)

            # 1. register a passkey — the virtual authenticator auto-creates it.
            page.click("#register-btn")
            # registerPasskey() does begin -> create -> complete -> reload();
            # wait for the reloaded overlay (plan + enabled sign button).
            page.wait_for_selector(
                "#sign:not([disabled])", state="visible", timeout=20000,
            )

            # 2. the overlay rendered the hard-coded demo plan ($500 -> Mom).
            plan_text = page.inner_text("#plan")
            assert "Mom" in plan_text, "payee_display 'Mom' must be rendered"
            assert "$500.00" in plan_text, "amount $500.00 must be rendered"

            # 3. biometric sign -> gateway execute. The virtual authenticator
            #    auto-approves (UV flag set), so navigator.credentials.get
            #    resolves with a genuine assertion over sha256(phash + nonce).
            page.click("#sign")
            page.wait_for_selector("#result:not([hidden])", timeout=20000)
            status = page.inner_text("#result h3")
            assert status == "EXECUTED", f"expected EXECUTED, got {status!r}"
            cls = page.get_attribute("#result", "class") or ""
            assert "ok" in cls, f"result box class should contain 'ok': {cls!r}"

            # 4. balance debited on the mock ledger: 842050 - 50000 = 792050 cents.
            accts = requests.get(
                server_url + "/api/seed/accounts?user_id=u_alice", timeout=5,
            ).json()
            savings = next(a for a in accts["accounts"] if a["id"] == "acct_savings")
            assert savings["balance"] == 792050, (
                f"savings should be 792050 after $500 debit, got {savings['balance']}"
            )

            # 5. the hash-chained audit log verifies end to end.
            verify = requests.get(server_url + "/api/audit/verify", timeout=5).json()
            assert verify["ok"] is True, f"audit chain must verify: {verify}"
        finally:
            client.send(
                "WebAuthn.removeVirtualAuthenticator",
                {"authenticatorId": auth_id},
            )
            browser.close()
