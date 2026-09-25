"""
The validator reads looser language — without loosening what it catches.

Reported: "okay then 2 bucks to jonny" was FROZEN. The parser (an LLM) read it
correctly; the validator split the transcript on "then", paired its one leg
with the clause "okay" by POSITION, found no amount there, and froze a correct
plan. And shorthand an LLM reads without effort — "5k", "two grand", "a
hundred and fifty" — the validator could not read at all.

The fix is more RULES, not a model: the validator is valuable because it is
not an LLM, so the same injected text cannot talk both into agreeing.

  1. Pairing by recipient: filler clauses are dropped, and each leg takes the
     clause that names ITS recipient. Pairing by the recipient — never by the
     amount — keeps the cross-clause swap check, and makes it stronger: a
     leg's recipient and amount must now appear in the SAME clause.
  2. Vocabulary: k / grand / thousand multipliers (digits and words), "and"
     inside number words, currency prefixes — with money never touching a
     float, and a multiplier consuming its number ("5 grand" is not also $5).
"""
from __future__ import annotations

import contextlib
import io
import time

import pytest

from backend.audit.canonical import hash_transcript
from backend.audit.log import AuditLog
from backend.data.seed import seed
from backend.models.schemas import (IntentPlan, LiteralAmount, MentionTarget,
                                    ResolvedPlan, ResolvedTransfer, TransferIntent)
from backend.validator import validate
from backend.validator.amounts import extract_literal_cents

PAYEES = {"mom": ("payee_17", "Mom ··3310"), "john": ("payee_21", "John ··4521"),
          "jonny": ("payee_21", "John ··4521")}


@pytest.fixture(autouse=True)
def _ledger():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    yield
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _check(tmp_path, transcript: str, legs: list[tuple[str, int, int]]):
    """legs: (mention, literal_cents in the intent, amount_cents in the resolved
    plan). Returns the validator's report."""
    intent = IntentPlan(plan=[
        TransferIntent(id=f"t{i}", type="TRANSFER",
                       source_account=MentionTarget(mention="default"),
                       target=MentionTarget(mention=m),
                       amount=LiteralAmount(literal_cents=lit))
        for i, (m, lit, _) in enumerate(legs, 1)])
    now = int(time.time())
    resolved = ResolvedPlan(
        draft_id=f"flex-{time.time_ns()}",
        plan=[ResolvedTransfer(id=f"t{i}", type="TRANSFER", source_account="acct_savings",
                               payee_id=PAYEES[m][0], payee_display=PAYEES[m][1],
                               amount_cents=amt)
              for i, (m, _, amt) in enumerate(legs, 1)],
        transcript_hash=hash_transcript(transcript), created_at=now, expires_at=now + 300)
    return validate(intent, resolved, transcript, audit=AuditLog(tmp_path / "a.db"))


def _amount_failed(report, leg=None):
    return any(c["check"] == "amount" and c["outcome"] == "fail"
               and (leg is None or c["leg"] == leg) for c in report.checks)


# --------------------------------------------------------------------------- 1. pairing by recipient
def test_the_reported_case_no_longer_freezes(tmp_path):
    """Exactly what was typed. It froze with "not derivable from its clause
    'okay'"; the amount is plainly in the sentence."""
    report = _check(tmp_path, "okay then 2 bucks to jonny", [("jonny", 200, 200)])
    assert not _amount_failed(report), report.checks


@pytest.mark.parametrize("transcript", [
    "okay then pay mom 50 then pay john 20",
    "alright then um then pay mom 50 then pay john 20",
])
def test_filler_clauses_are_ignored(tmp_path, transcript):
    report = _check(tmp_path, transcript, [("mom", 5000, 5000), ("john", 2000, 2000)])
    assert not _amount_failed(report), report.checks


def test_a_cross_clause_swap_is_still_caught_with_filler_present(tmp_path):
    """The attack the clause check exists for: amounts the user DID say, moved
    to the wrong recipient. Filler in front must not open a gap."""
    report = _check(tmp_path, "okay then pay mom 500 then pay john 200",
                    [("mom", 20000, 20000), ("john", 50000, 50000)])
    assert _amount_failed(report, "t1") and _amount_failed(report, "t2")


def test_legs_in_a_different_order_than_spoken_still_pass(tmp_path):
    """Correct amounts, legs listed john-first: position would have paired them
    with the wrong clauses and false-frozen; the recipient pairs them right."""
    report = _check(tmp_path, "pay mom 500 then pay john 200",
                    [("john", 20000, 20000), ("mom", 50000, 50000)])
    assert not _amount_failed(report), report.checks


def test_reordering_legs_does_not_launder_a_swap(tmp_path):
    """Reordered AND swapped — each leg still meets its own recipient's clause."""
    report = _check(tmp_path, "pay mom 500 then pay john 200",
                    [("john", 50000, 50000), ("mom", 20000, 20000)])
    assert _amount_failed(report)


def test_the_same_recipient_twice_pairs_in_spoken_order(tmp_path):
    ok = _check(tmp_path, "pay mom 50 then pay mom 20",
                [("mom", 5000, 5000), ("mom", 2000, 2000)])
    swapped = _check(tmp_path, "pay mom 50 then pay mom 20",
                     [("mom", 2000, 2000), ("mom", 5000, 5000)])
    assert not _amount_failed(ok), ok.checks
    assert _amount_failed(swapped)


# --------------------------------------------------------------------------- 2. vocabulary
@pytest.mark.parametrize("text,cents", [
    ("5k to mom", 500000),
    ("$1.5k to mom", 150000),
    ("2.5K", 250000),
    ("two grand", 200000),
    ("a grand to mom", 100000),
    ("5 grand", 500000),
    ("5 thousand", 500000),
    ("a hundred and fifty dollars", 15000),
    ("one thousand and five", 100500),
    ("fifty k", 5000000),
    ("SGD 50", 5000),
    ("S$50", 5000),
    ("50 sgd", 5000),
    ("2 bucks", 200),
])
def test_shorthand_amounts_are_read(text, cents):
    assert cents in extract_literal_cents(text)


@pytest.mark.parametrize("text,not_also", [
    ("5 grand", 500),          # not also $5
    ("5k", 500),
    ("2 thousand", 200),
    ("1.5k", 100),             # the "1" before the point is not $1
])
def test_a_multiplier_consumes_its_number(text, not_also):
    """An extra reading is an extra amount a tampered draft could pass with."""
    assert not_also not in extract_literal_cents(text)


def test_a_fraction_of_a_cent_is_not_an_amount():
    """1.123456k = $1,123.456: not whole cents, so not money — and computed
    without a float to discover that."""
    assert extract_literal_cents("1.123456k") == set()


def test_existing_readings_are_unchanged():
    for text, want in {"pay mom five hundred": {50000}, "1,200.50": {120050},
                       "twenty-five cents": {25}, "$500": {50000}}.items():
        assert extract_literal_cents(text) == want, text


def test_shorthand_end_to_end(tmp_path):
    ok = _check(tmp_path, "send mom 1.5k", [("mom", 150000, 150000)])
    assert not _amount_failed(ok), ok.checks
    tampered = _check(tmp_path, "send mom 5 grand", [("mom", 500, 500)])
    assert _amount_failed(tampered), "a tampered $5 must not pass as '5 grand'"
