# Trust-boundary diagram (placeholder — to be finalized before submission)

This document lists every boundary the pipeline crosses, what may cross it,
and who could forge it. A proper diagram will be rendered for the submission.

## Boundaries

| # | Boundary | Crosses | Who could forge it | Mitigation |
|---|---|---|---|---|
| 1 | Browser -> ASR | audio + transcript | MITM on audio; injected speech | HTTPS; user speech is *authorized* untrusted input (defended by schema, not secrecy) |
| 2 | Stored 3rd-party data -> prompt | payee names, biller ref text | Attacker who poisoned a biller reference | **Opaque IDs** before prompt; sanitizer replaces names with `payee_17`/`biller_03` |
| 3 | LLM -> draft store | symbolic IntentPlan | A compromised/rogue model | Draft is inert without a human signature; schema-constrained output rejects invented fields |
| 4 | Resolver -> policy | concrete ResolvedPlan | None (pure deterministic code) | Deterministic; no external input |
| 5 | ResolvedPlan -> overlay | canonical JSON | A compromised renderer | Overlay renders from fixed template, never LLM text; **client-integrity assumption, stated honestly** |
| 6 | Overlay -> WebAuthn | payload hash + draft-bound nonce | Replay/swap of an approved draft | Nonce bound to `draft_id`, single-use, 120s TTL; challenge = sha256(payload_hash + nonce) |
| 7 | WebAuthn -> gateway | (payload, signature) | Forged signature / unsigned request | Gateway accepts ONLY (payload, signature); verifies signature, hash, nonce freshness |
| 8 | Gateway -> ledger | signed execution | A rogue agent trying to execute | Agent has no gateway credentials and no import path to gateway/ (enforced by import-boundary test) |
| 9 | Every step -> audit log | transcript/draft/policy/sig/exec hashes | Tampering with history | Hash-chained; `verify_chain()` pinpoints the break |

## The decisive boundary

Boundary 7 (gateway) is where "a draft" becomes "a debit." It accepts only a
signed payload and verifies it against a registered public key + a draft-bound
nonce. The agent never reaches it. That asymmetry — generate here, execute
there, with a human signature in between — is the entire security argument.

## Honest client-integrity caveat (state in the pitch)

The OS biometric prompt signs a blind hash; it does not show transaction
details. "What you see is what you sign" therefore depends on the overlay
being rendered deterministically from the same canonical payload — a
*client-integrity* assumption, **not** a cryptographic guarantee. The
out-of-band confirmation channel for high-value transactions closes this gap,
because it is the only channel independent of a possibly-compromised renderer.
