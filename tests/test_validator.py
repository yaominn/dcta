"""
M6 acceptance tests — Independent Validation Agent. (brief §9)

One test per acceptance case in the brief, plus a clause-localized cross-clause
swap test that proves §4.1's literal check was built right, and the boundary
tests live in test_import_boundary.py. The validator is exercised directly (no
HTTP for the logic tests), exactly like the M4 resolver tests; the freeze→nonce
integration is exercised in test_8 via the real main.py singletons.

Headline arithmetic locked in the seed (brief §13), all integer cents:
  acct_savings 842050 - 50000 (t1) = 792050 -> at AAPL 24150:
  792050 // 24150 = 32 whole shares = 772800, remainder 19250. No floats.
"""
from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi import HTTPException

from backend.agent import StubProvider
from backend.audit.canonical import hash_transcript
from backend.audit.log import AuditEntryType, AuditLog
from backend.data.seed import seed
from backend.models.schemas import (
    AmountOp,
    BuyEquityIntent,
    IntentPlan,
    LiteralAmount,
    MentionTarget,
    ResolvedPayBill,
    ResolvedPlan,
    ResolvedTransfer,
    SymbolicAmount,
    TransferIntent,
)
from backend.resolver import Resolved, resolve
from backend.validator import default_freeze_set, validate

seed()  # clean mock ledger before the run (matches the other suites)


# --------------------------------------------------------------------------- builders
def _mention(s: str) -> MentionTarget:
    return MentionTarget(mention=s)


def _lit(cents: int) -> LiteralAmount:
    return LiteralAmount(literal_cents=cents)


def _sym(ref: str, op: AmountOp) -> SymbolicAmount:
    return SymbolicAmount(after_leg=ref, op=op)


def _headline() -> tuple[IntentPlan, str]:
    """'pay mom five hundred then buy apple with the rest' -> the two-leg
    headline IntentPlan + the transcript it was spoken from."""
    intent = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(50000),
        ),
        BuyEquityIntent(
            id="t2", type="BUY_EQUITY",
            source_account=_mention("savings"), ticker=_mention("Apple"),
            amount=_sym("t1", AmountOp.ALL),
        ),
    ])
    return intent, "pay mom five hundred then buy apple with the rest"


def _resolve_headline() -> tuple[IntentPlan, str, ResolvedPlan]:
    intent, transcript = _headline()
    res = resolve(intent, transcript=transcript, user_id="u_alice")
    assert isinstance(res, Resolved), f"headline did not resolve: {res}"
    return intent, transcript, res.plan


def _tamper(plan: ResolvedPlan, leg_idx: int, **updates) -> ResolvedPlan:
    """Return a copy of `plan` with one leg's fields updated. Pydantic v2
    model_copy(update=...) — the original is untouched."""
    legs = list(plan.plan)
    legs[leg_idx] = legs[leg_idx].model_copy(update=updates)
    return plan.model_copy(update={"plan": legs})


def _audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "audit.db")


def _failed(report, check: str, leg: str | None = None) -> bool:
    """True if any hard check named `check` failed (optionally on `leg`)."""
    return any(
        c["check"] == check and c["outcome"] == "fail"
        and (leg is None or c["leg"] == leg)
        for c in report.checks
    )


# --------------------------------------------------------------------------- 1. clean plan passes
def test_1_clean_plan_passes(tmp_path):
    """The headline case validates with no mismatch (brief §9.1). t2's 772800
    appears nowhere in the transcript and still passes — covered by test_4."""
    intent, transcript, plan = _resolve_headline()
    report = validate(intent, plan, transcript, audit=_audit(tmp_path))
    assert report.verdict == "pass"
    assert not report.frozen
    # every hard check passed
    assert all(c["outcome"] == "pass" for c in report.checks), report.checks


# --------------------------------------------------------------------------- 2. tampered amount freezes
def test_2_tampered_amount_freezes(tmp_path):
    """Change amount_cents on the literal leg -> freeze naming the amount check
    (brief §9.2). The literal 50000 is still spoken, but resolved (20000) !=
    the literal (50000), so the resolved-vs-literal consistency check fires."""
    intent, transcript, plan = _resolve_headline()
    tampered = _tamper(plan, 0, amount_cents=20000)
    report = validate(intent, tampered, transcript, audit=_audit(tmp_path))
    assert report.verdict == "freeze"
    assert _failed(report, "amount", "t1"), report.checks


# --------------------------------------------------------------------------- 3. tampered beneficiary freezes
def test_3_tampered_beneficiary_freezes(tmp_path):
    """Swap payee_id to a payee never mentioned in the transcript -> freeze
    naming the beneficiary check (brief §9.3). payee_30 is "Landlord"; the
    transcript says "mom" only."""
    intent, transcript, plan = _resolve_headline()
    tampered = _tamper(plan, 0, payee_id="payee_30",
                       payee_display="Landlord ··7001")
    report = validate(intent, tampered, transcript, audit=_audit(tmp_path))
    assert report.verdict == "freeze"
    assert _failed(report, "beneficiary", "t1"), report.checks


# --------------------------------------------------------------------------- 4. symbolic amount does NOT false-positive
def test_4_symbolic_amount_no_false_positive(tmp_path):
    """t2's 772800 was COMPUTED ('the rest'), appears nowhere in the transcript,
    and must still pass (brief §9.4). This is the test that proves §4.1 was
    implemented correctly: symbolic amounts are recomputed, not text-matched."""
    intent, transcript, plan = _resolve_headline()
    # sanity: 772800 truly is not in the transcript
    assert "7728" not in transcript and "seven hundred" not in transcript
    report = validate(intent, plan, transcript, audit=_audit(tmp_path))
    assert report.verdict == "pass"
    # and the symbolic leg's amount check passed specifically
    assert any(
        c["check"] == "amount" and c["leg"] == "t2" and c["outcome"] == "pass"
        for c in report.checks
    ), report.checks


# --------------------------------------------------------------------------- 5. wrong symbolic arithmetic freezes
def test_5_wrong_symbolic_arithmetic_freezes(tmp_path):
    """Change t2's amount_cents to a plausible but wrong number; the independent
    recomputation must catch it (brief §9.5). 780000 is close to 772800 but the
    recomputation yields exactly 772800, so the mismatch freezes."""
    intent, transcript, plan = _resolve_headline()
    tampered = _tamper(plan, 1, amount_cents=780000)
    report = validate(intent, tampered, transcript, audit=_audit(tmp_path))
    assert report.verdict == "freeze"
    assert _failed(report, "amount", "t2"), report.checks


# --------------------------------------------------------------------------- 6. LLM unavailable does not freeze
def test_6_llm_unavailable_does_not_freeze(tmp_path):
    """With no credentials, get_provider() returns the deterministic stub. The
    stub is not a real model, so the validator records llm_check='unavailable'
    and a clean plan still passes (brief §9.6, §5)."""
    intent, transcript, plan = _resolve_headline()
    report = validate(intent, plan, transcript,
                      provider=StubProvider(), audit=_audit(tmp_path))
    assert report.verdict == "pass"
    assert report.llm_check == "unavailable"
    assert not report.frozen


# --------------------------------------------------------------------------- 7. audit entry is written + chain ok
def test_7_audit_entry_written_chain_ok(tmp_path):
    """Append one VALIDATION entry per validation; verify_chain() still passes
    afterwards (brief §9.7)."""
    intent, transcript, plan = _resolve_headline()
    audit = _audit(tmp_path)
    report = validate(intent, plan, transcript, audit=audit)
    entries = audit.all_entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["entry_type"] == AuditEntryType.VALIDATION.value
    assert e["hash"] == report.audit_hash
    # the payload carries what §7 requires
    import json
    payload = json.loads(e["payload"])
    assert payload["draft_id"] == plan.draft_id
    assert "payload_hash" in payload and "transcript_hash" in payload
    assert payload["verdict"] == "pass"
    assert "checks" in payload and "llm_check" in payload
    assert payload["frozen"] is False
    # the chain is intact after the append
    assert audit.verify_chain() == {"ok": True, "break_at": None, "reason": None}


# --------------------------------------------------------------------------- 8. frozen draft is unsignable
def test_8_frozen_draft_is_unsignable(tmp_path):
    """A frozen draft gets no nonce (403 at /api/auth/nonce), and a gateway
    submission for that draft is rejected (brief §9.8). Freeze = no nonce is
    ever issued -> no WebAuthn challenge -> no signature -> gateway rejects."""
    default_freeze_set.clear()
    try:
        # freeze via the validator (tampered beneficiary -> freeze)
        intent, transcript, plan = _resolve_headline()
        draft_id = plan.draft_id
        tampered = _tamper(plan, 0, payee_id="payee_30",
                           payee_display="Landlord ··7001")
        report = validate(intent, tampered, transcript,
                          audit=_audit(tmp_path))
        assert report.frozen
        assert draft_id in default_freeze_set

        # no nonce is issued for the frozen draft (the /api/auth/nonce gate)
        from backend.main import issue_nonce
        with pytest.raises(HTTPException) as exc:
            issue_nonce(draft_id=draft_id)
        assert exc.value.status_code == 403

        # a gateway submission for that draft is rejected: with no nonce ever
        # issued, any nonce passed in is unknown -> NONCE rejection.
        from backend.main import _gateway
        result = _gateway.submit(tampered, None, "no-such-nonce", "cred_alice")
        assert result["accepted"] is False
        assert result["rejection"] == "NONCE"
    finally:
        default_freeze_set.clear()


# --------------------------------------------------------------------------- extra: clause-localized cross-clause swap
def test_clause_localized_cross_clause_swap_freezes(tmp_path):
    """§4.1 / item 1: the literal check is CLAUSE-LOCALIZED. A literal swapped
    in from a different clause is globally derivable (so a global 'does this
    number appear?' check would admit it) but not from THIS leg's clause.

    Transcript: 'transfer 500 to mom then 200 to john'.
    Attacker tampers BOTH intent t1.literal_cents and resolved t1.amount_cents
    to 20000 (matching). Globally, 20000 is derivable ('200' in clause 2). But
    clause 0 is 'transfer 500 to mom', which yields {50000} only — so the
    clause-localized check catches the swap and freezes."""
    intent = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(20000),                # tampered: was 50000
        ),
        TransferIntent(
            id="t2", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("john"),
            amount=_lit(20000),
        ),
    ])
    transcript = "transfer 500 to mom then 200 to john"
    now = int(time.time())
    resolved = ResolvedPlan(
        draft_id="swap_test",
        plan=[
            ResolvedTransfer(
                id="t1", type="TRANSFER", source_account="acct_savings",
                payee_id="payee_17", payee_display="Mom ··3310",
                amount_cents=20000,           # tampered to match the literal
            ),
            ResolvedTransfer(
                id="t2", type="TRANSFER", source_account="acct_savings",
                payee_id="payee_21", payee_display="John ··4521",
                amount_cents=20000,
            ),
        ],
        transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
    )
    report = validate(intent, resolved, transcript, audit=_audit(tmp_path))
    assert report.verdict == "freeze"
    # the amount check on t1 failed specifically (clause 0 has no 20000)
    assert _failed(report, "amount", "t1"), report.checks


# --------------------------------------------------------------------------- extra: soft signals recorded but never freeze
def test_soft_signals_never_freeze(tmp_path):
    """§4.3: source_account and asset_class are lenient tripwires — recorded as
    soft signals, never the sole cause of a freeze. A plan whose transcript
    never says 'savings' still passes if the hard checks pass."""
    intent, _, plan = _resolve_headline()
    # a transcript that says nothing about the account type or 'buy' language,
    # but DOES name mom and the amount and apple — so hard checks pass.
    transcript = "pay mom five hundred then apple with the rest"
    report = validate(intent, plan, transcript, audit=_audit(tmp_path))
    assert report.verdict == "pass"
    assert not report.frozen
    # but there should be soft warnings about the missing account type / buy word
    assert any(s["check"] == "source_account" and s["outcome"] == "warn"
               for s in report.soft_signals), report.soft_signals


# --------------------------------------------------------------------------- extra: LLM disagree is soft
def test_llm_disagree_is_soft_does_not_freeze(tmp_path):
    """§5 / item 6: an LLM disagreement is recorded but never the sole cause of
    a freeze. A clean plan with a disagreeing auditor still passes."""
    intent, transcript, plan = _resolve_headline()

    class _DisagreeProvider:
        name = "hunyuan"  # not "stub", so the LLM half runs

        def complete(self, *, system: str, user: str) -> str:
            return "DISAGREE\nthe amount looks off to me."

    report = validate(intent, plan, transcript,
                     provider=_DisagreeProvider(), audit=_audit(tmp_path))
    assert report.llm_check == "disagree"
    # deterministic checks all passed -> still pass (LLM disagree is soft)
    assert report.verdict == "pass"
    assert not report.frozen
    assert any(s["check"] == "llm" and s["outcome"] == "disagree"
               for s in report.soft_signals), report.soft_signals


# --------------------------------------------------------------------------- extra: provider error -> unavailable, no freeze
def test_provider_error_is_unavailable_no_freeze(tmp_path):
    """§5: a provider outage (bad key, rate limit, timeout) never freezes."""
    intent, transcript, plan = _resolve_headline()

    class _BrokenProvider:
        name = "hunyuan"

        def complete(self, *, system: str, user: str) -> str:
            raise RuntimeError("upstream timeout")

    report = validate(intent, plan, transcript,
                      provider=_BrokenProvider(), audit=_audit(tmp_path))
    assert report.llm_check == "unavailable"
    assert report.verdict == "pass"
    assert not report.frozen


# --------------------------------------------------------------------------- extra: PAY_BILL beneficiary check
def test_pay_bill_beneficiary_mismatch_freezes(tmp_path):
    """A PAY_BILL leg whose biller is never named in the transcript freezes on
    the beneficiary check (§4.2)."""
    intent = IntentPlan(plan=[
        TransferIntent(
            id="t1", type="TRANSFER",
            source_account=_mention("savings"), target=_mention("mom"),
            amount=_lit(50000),
        ),
    ])
    transcript = "pay 500 to mom from savings"
    now = int(time.time())
    # tamper: resolved leg is a PAY_BILL to SP Group, never mentioned
    resolved = ResolvedPlan(
        draft_id="bill_test",
        plan=[
            ResolvedPayBill(
                id="t1", type="PAY_BILL", source_account="acct_savings",
                biller_id="biller_03", biller_display="SP Group",
                amount_cents=50000,
            ),
        ],
        transcript_hash=hash_transcript(transcript),
        created_at=now, expires_at=now + 300,
    )
    report = validate(intent, resolved, transcript, audit=_audit(tmp_path))
    assert report.verdict == "freeze"
    assert _failed(report, "beneficiary", "t1"), report.checks
