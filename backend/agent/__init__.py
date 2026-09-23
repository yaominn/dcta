"""
Agent Service — the LLM parser. (brief Section 8: backend/agent/)

Responsibility: turn the ASR transcript into a schema-constrained IntentPlan
(symbolic, with mentions). Output handling: generate -> validate against the
Pydantic schema -> reject and retry, bounded retries. (brief Section 8)

TRUST BOUNDARY (enforced by the import-boundary test in tests/):
    backend/agent/  MUST NOT transitively import  backend/gateway/  or  backend/auth/
The agent writes drafts to the draft store. It has NO gateway credentials and
no code path to execution. Even fully compromised, the worst it can do is emit
a wrong draft the user then declines. (brief Section 4.2 / 3)

# TODO: Milestone 3 — LLM parser, prompts, opaque-ID prompt context,
        swappable provider interface (Hunyuan preferred, stub fallback).
        Provider takes credentials from backend.config.settings — never hardcoded.
"""
