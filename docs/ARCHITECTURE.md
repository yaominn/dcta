# Architecture (placeholder — to be drawn before submission, brief Section 6/11)

```
Voice/Text
  -> ASR (transcript + word confidences where available)
  -> Input sanitizer        (STORED third-party fields -> opaque IDs;
                             injection tripwire. NOT the user's transcript.)
  -> LLM Parser             (schema-constrained -> symbolic plan with mentions)
                             ^ the only LLM step with authority over the draft
  -> Deterministic Resolver (payee matching, amounts, symbolic refs; clarify loop)
  -> Policy Engine          (KYC, balances, limits, velocity, anomaly)
  -> Validation Agent       (draft vs transcript; freeze on mismatch)
  -> Confirmation Overlay   (fixed template rendered from JSON)
  -> WebAuthn signature     (over canonical payload hash + draft-bound nonce)
  -> Gateway                (verify signature, hash, nonce -> execute on mock ledger)
  -> Hash-chained audit log (every step)
```

## Component responsibilities (brief Section 8)

| Package | Responsibility | Milestone |
|---|---|---|
| `backend/agent/` | LLM parser, prompts, schema. **Must not import gateway/ or auth/.** | 3 |
| `backend/resolver/` | Deterministic payee/amount resolution + clarify loop | 4 |
| `backend/policy/` | KYC, limits, velocity, anomaly (pure functions, no LLM) | 5 |
| `backend/validator/` | Independent draft-vs-transcript audit, freeze on mismatch | 6 |
| `backend/gateway/` | Signature + hash + nonce verification; mock ledger execution | 1 |
| `backend/audit/` | Hash-chained log + `verify_chain()` | 1 |
| `backend/auth/` | WebAuthn transaction signing only (mock login session separate) | 2 |
| `backend/models/` | **Frozen v1 schemas** — the cross-team contract (this repo) | 0 |
| `backend/data/` | SQLite mock ledger + seed script (this repo) | 0 |

## The core principle (the whole pitch)

> **GenAI is a generator of drafts, never an executor of funds.**

The LLM turns language into a structured draft. It has no credentials, no
execution path, and no authority anywhere else. Every other step is
deterministic code, an independent check, or the human. Even if the LLM is
fully compromised, the worst outcome is a wrong draft the user sees and
declines. The security property does not depend on model behaviour and does
not degrade when the model does.
