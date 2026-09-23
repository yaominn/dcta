"""
Canonical serialization + hashing tests. (brief Section 4.5)

These prove the hash is STABLE: same plan -> same hash, key order irrelevant.
Money is int cents; a float in the payload RAISES — so a float can never
silently produce a hash collision (the bug where 500.001 and 500.004 both
rounded to '500.00' -> one signature valid for two different plans).
"""
from __future__ import annotations

import pytest

from backend.audit.canonical import (
    canonical_json,
    payload_hash,
    entry_hash,
    challenge_hash,
)
from backend.models.schemas import ResolvedPlan, ResolvedTransfer


def _plan(amount_cents=50000, created_at="2026-10-16T10:00:00+00:00", draft_id="d1"):
    return ResolvedPlan(
        draft_id=draft_id,
        plan=[
            ResolvedTransfer(
                id="t1", type="TRANSFER", source_account="acct_savings",
                payee_id="payee_17", payee_display="Mom", amount_cents=amount_cents,
            )
        ],
        created_at=created_at,
    )


def test_canonical_sorts_keys():
    assert canonical_json({"b": 2, "a": 1}) == canonical_json({"a": 1, "b": 2})
    assert canonical_json({"a": 1, "b": 2}) == '{"a":1,"b":2}'


def test_canonical_int_cents_pass_through():
    # money is int cents — no transformation, just the integer.
    assert canonical_json({"amount_cents": 50000}) == '{"amount_cents":50000}'


def test_canonical_raises_on_float():
    """Regression (B2): a float in a canonical payload must RAISE, not silently
    round. Floats cannot be canonicalized deterministically across languages
    (Python f'{2.675:.2f}'='2.67', JS (2.675).toFixed(2)='2.68'), which produced
    hash collisions (500.001 and 500.004 both -> '500.00')."""
    with pytest.raises(TypeError, match="float in canonical payload"):
        canonical_json({"amount": 500.001})


def test_distinct_cents_distinct_hashes():
    """Property (B2): distinct amount_cents yield distinct payload hashes.
    With int cents, the 500.001/500.004 collision is structurally impossible —
    you have 50001 cents or 50004 cents, and they hash differently."""
    assert payload_hash(_plan(amount_cents=50001)) != payload_hash(_plan(amount_cents=50004))


def test_different_plans_have_different_hashes():
    assert payload_hash(_plan(amount_cents=50000)) != payload_hash(_plan(amount_cents=60000))


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
