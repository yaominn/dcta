"""
Canonical serialization + hashing tests. (brief Section 4.5)

These prove the hash is STABLE: same plan -> same hash, key order irrelevant,
float drift absorbed. If the hash weren't stable, "what you see is what you
sign" would silently break (a user signs one blob, the gateway sees another).
"""
from __future__ import annotations

from backend.audit.canonical import (
    canonical_json,
    payload_hash,
    entry_hash,
    challenge_hash,
)
from backend.models.schemas import ResolvedPlan, ResolvedTransfer


def _plan(amount=500.0, created_at="2026-10-16T10:00:00+00:00", draft_id="d1"):
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[
            ResolvedTransfer(
                id="t1", type="TRANSFER", source_account="acct_savings",
                payee_id="payee_17", payee_display="Mom", amount=amount,
            )
        ],
        created_at=created_at,
    )


def test_canonical_sorts_keys():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    assert canonical_json({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_canonical_float_fixed_2dp():
    assert canonical_json({"amount": 500.0}) == '{"amount":"500.00"}'


def test_canonical_absorbs_tiny_float_drift():
    # 500.0 and 500.0000001 both format to "500.00" -> same canonical form.
    assert canonical_json({"a": 500.0}) == canonical_json({"a": 500.0000001})


def test_different_plans_have_different_hashes():
    assert payload_hash(_plan(amount=500.0)) != payload_hash(_plan(amount=600.0))


def test_identical_plans_have_identical_hashes():
    assert payload_hash(_plan()) == payload_hash(_plan())


def test_created_at_is_part_of_the_hash():
    a = payload_hash(_plan(created_at="2026-01-01T00:00:00+00:00"))
    b = payload_hash(_plan(created_at="2026-02-02T00:00:00+00:00"))
    assert a != b


def test_challenge_binds_to_nonce():
    p = payload_hash(_plan())
    assert challenge_hash(p, "nonceA") != challenge_hash(p, "nonceB")


def test_entry_hash_binds_to_prev():
    # Changing prev_hash changes the entry hash -> this is what makes the chain
    # tamper-evident (every later link depends on the previous one).
    assert entry_hash("0" * 64, "DRAFT", "{}", "ts") != entry_hash("1" * 64, "DRAFT", "{}", "ts")
