"""
Hash-chained audit log + verify_chain(). (brief Section 4.5 / Section 8)

Each entry stores prev_hash and its own hash. Logs: transcript hash, draft
hash, validation result, policy result, signature and execution result.
verify_chain() reports EXACTLY where tampering occurred.

# TODO: Milestone 1 — append-only chain + verify_chain(). Built alongside the
        gateway (the security core, before the LLM).
"""
