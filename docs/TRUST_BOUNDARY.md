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
| 7 | WebAuthn -> gateway | (payload, signature) | Forged signature / unsigned request | Gateway accepts ONLY (payload, signature); verifies signature, hash, nonce freshness; **re-evaluates policy (M5)** so a signed payload that skipped the overlay still meets KYC, limits and velocity |
| 8 | Gateway -> ledger | signed execution | A rogue agent trying to execute | Agent has no gateway credentials and no import path to gateway/ (enforced by import-boundary test) |
| 9 | Every step -> audit log | transcript/draft/policy/sig/exec hashes | Tampering with history | Hash-chained; `verify_chain()` pinpoints the break |
| 10 | Recurring mandate -> gateway | a signed `RecurringBillMandate` (no money moves) | Unsigned / tampered / expired terms; another user's passkey | Separate, versioned payload: bounded count, fixed amount = per-payment cap, total cap, biller reference version + hash, the user's explicit automation choice, `valid_until`. Signed with WebAuthn over its canonical hash; `Gateway.submit_mandate()` checks expiry, nonce, signature, the drafted terms byte for byte, that the passkey belongs to the user it names, KYC, the kill switch and the biller |
| 11 | Scheduler -> ledger (automatic payments) | one occurrence of a signed mandate | A worker, a retry or a forged "auto" flag trying to pay early, twice, or above the terms | The **only** debit without a signature over the payment itself. `Gateway.run_mandate_occurrence()` re-derives the terms' hash, requires ACTIVE + AUTO (set by the server after three individually signed payments, only if the signed terms allow it), the due date, count and caps, the same biller version, then KYC, kill switch, policy and the scam rules; anything needing the user becomes HELD / NEEDS_REVIEW. The executor re-checks the mandate under its write lock and claims the occurrence's execution key with the debit (at most once) |

## The decisive boundary

Boundary 7 (gateway) is where "a draft" becomes "a debit." It accepts only a
signed payload and verifies it against a registered public key + a draft-bound
nonce, **and re-runs the policy engine against the ledger before executing** —
because a limit that is only checked on the way to the overlay is a limit a
caller can walk around. The user whose limits apply is derived from the account
rows being debited, never from a field in the request. The agent never reaches it. That asymmetry — generate here, execute
there, with a human signature in between — is the entire security argument.

## The one exception: recurring bills after three approvals

"Every payment carries a fresh signature" is true for every payment except
one kind. A recurring bill's first payments are ordinary drafts signed one by
one through boundary 7. After three of them succeed, **and only if the user
chose it when signing the mandate**, later occurrences are paid by the server
(boundary 11) with no new biometric prompt. What authorizes them is the signed
mandate, not a stretched `ResolvedPlan` signature: a fixed biller (bound by
reference version and hash), a fixed amount, a bounded count and total, its own
dates, and an end. Every automatic payment is re-checked against today's
rules first, is announced to the user afterwards, and stops — HELD,
NEEDS_REVIEW or SUSPENDED — for anything unusual. Pause and cancel need no
signature and win against a payment in flight. Material changes need a new
signed mandate, whose approval count starts from zero. Full detail:
[`RECURRING_BILLS.md`](RECURRING_BILLS.md).

## Honest client-integrity caveat (state in the pitch)

The OS biometric prompt signs a blind hash; it does not show transaction
details. "What you see is what you sign" therefore depends on the overlay
being rendered deterministically from the same canonical payload — a
*client-integrity* assumption, **not** a cryptographic guarantee. The
out-of-band confirmation channel for high-value transactions closes this gap,
because it is the only channel independent of a possibly-compromised renderer.
