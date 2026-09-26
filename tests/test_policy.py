"""
M5 acceptance tests — the policy engine. (brief Section 8: backend/policy/)

One test per rule plus the interactions that matter: precedence, accumulation
across legs of one plan, and the property that the plan is never mutated.

Notes on the seeded data, which shapes several of these tests:
  - u_bob has NO accounts, so his KYC block cannot be reached through the
    resolver. The rules are pure functions, so they are tested directly against
    a hand-built ResolvedPlan instead.
  - seeded history rows are a DAY apart, so nothing exercises velocity against
    the seed. Those tests build their own rows.
  - transaction_history.payee_id is NOT NULL and FKs to payees, so bills and
    equity buys have no per-counterparty baseline; anomaly is transfers-only.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from backend.audit import AuditLog
from backend.audit.canonical import hash_transcript, payload_hash, challenge_hash
from backend.auth import MockCredentialStore
from backend.data.seed import seed
from backend.gateway import Gateway, MockExecutor, MockSigner, NonceStore
from backend.models.schemas import (
    ResolvedBuyEquity, ResolvedPayBill, ResolvedPlan, ResolvedTransfer,
)
from backend.policy import (
    check_anomaly,
    Decision, PolicyContext, evaluate, load_context, owner_of,
)
from support import dest


class _EveryPayloadIsTheDraft:
    """Stand-in for the draft store in gateway unit tests: every submitted
    payload counts as its own ready draft, so these tests exercise the nonce /
    signature / expiry / policy rules in isolation. The real binding — only a
    ready draft's exact payload executes — is tested in test_draft_states.py."""

    def executable(self, draft_id, *, kind, submitted_hash):
        return None

_TX = "stub: policy tests"
_NOW = int(time.time())


# --------------------------------------------------------------------------- builders
def _plan(*legs, draft_id="d1"):
    return ResolvedPlan(draft_id=draft_id, plan=list(legs),
                        transcript_hash=hash_transcript(_TX),
                        created_at=_NOW, expires_at=_NOW + 300)


def _transfer(cents, leg_id="t1", payee="payee_17", display="Mom ··3310"):
    return ResolvedTransfer(id=leg_id, type="TRANSFER", source_account="acct_savings",
                            payee_id=payee, payee_display=display, amount_cents=cents,
                            **dest(payee))


def _equity(cents=24150, leg_id="t1"):
    return ResolvedBuyEquity(id=leg_id, type="BUY_EQUITY", source_account="acct_savings",
                             ticker="AAPL", amount_cents=cents, estimated_shares=1,
                             estimated_fill_price_cents=24150)


_LIMITS = {"per_transaction": 2000000, "daily": 5000000,
           "velocity_count": 5, "velocity_window_minutes": 10}


def _ctx(*, kyc="VERIFIED", eligible=1, history=None, limits=None, now=_NOW):
    return PolicyContext(
        user={"id": "u_alice", "nickname": "Alice",
              "kyc_status": kyc, "investment_eligible": eligible},
        limits=dict(limits or _LIMITS),
        history=list(history or []),
        now=now,
    )


def _hist(amount, payee="payee_17", minutes_ago=0, days_ago=1):
    """A history row. Default is YESTERDAY: most tests want rows that establish a
    median without also counting toward today's total or the velocity window —
    which is how the seeded data is shaped (its rows are a day apart). Tests that
    care about today or the window pass days_ago=0 explicitly."""
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago, days=days_ago)
    return {"payee_id": payee, "amount": amount, "ts": ts.isoformat()}


# --------------------------------------------------------------------------- 1. KYC
def test_kyc_pending_user_is_blocked():
    """u_bob is PENDING. He has no accounts either, so this is the only way the
    gate can be reached — see the module docstring."""
    res = evaluate(_plan(_transfer(5000)), _ctx(kyc="PENDING"))
    assert res.blocked
    assert res.verdicts[0].rule == "kyc"


def test_equity_requires_investment_eligibility():
    res = evaluate(_plan(_equity()), _ctx(eligible=0))
    assert res.blocked
    assert res.verdicts[0].rule == "investment_eligibility"


def test_ineligible_user_may_still_transfer():
    """Investment eligibility gates EQUITY only — it must not block a transfer."""
    res = evaluate(_plan(_transfer(5000, payee="payee_17"),
                         ), _ctx(eligible=0, history=[_hist(5000)] * 3))
    assert not res.blocked


def test_verified_eligible_user_passes():
    res = evaluate(_plan(_transfer(50000)), _ctx(history=[_hist(50000)] * 6))
    assert res.decision is Decision.ALLOW


# --------------------------------------------------------------------------- 2. limits
@pytest.mark.parametrize("cents,blocked", [(2000000, False), (2000001, True)])
def test_per_transaction_limit_boundary(cents, blocked):
    """The cap itself is allowed; one cent over is not."""
    res = evaluate(_plan(_transfer(cents)), _ctx(history=[_hist(cents)] * 5))
    assert res.blocked is blocked
    if blocked:
        assert res.verdicts[0].rule == "per_transaction"


def test_daily_limit_accumulates_across_legs_of_one_plan():
    """Four legs of $15,000 are not four separate under-limit payments: the
    fourth takes the day to $60,000, over the $50,000 cap."""
    legs = [_transfer(1500000, leg_id=f"t{i}") for i in range(1, 5)]
    res = evaluate(_plan(*legs), _ctx(history=[_hist(1500000)] * 8))
    assert res.blocked
    blocked = [v for v in res.verdicts if v.decision is Decision.BLOCK]
    assert len(blocked) == 1 and blocked[0].leg_id == "t4"
    assert blocked[0].rule == "daily"


def test_daily_limit_counts_todays_history_not_older_rows():
    """Yesterday's payments must not eat today's allowance."""
    old = [_hist(2000000, days_ago=1), _hist(2000000, days_ago=2)]
    res = evaluate(_plan(_transfer(2000000)), _ctx(history=old + [_hist(2000000)] * 3))
    assert not res.blocked


def test_blocked_leg_does_not_consume_the_daily_allowance():
    """A leg that will never execute must not push a later leg over the limit."""
    legs = [_transfer(2000001, leg_id="t1"), _transfer(1000000, leg_id="t2")]
    res = evaluate(_plan(*legs), _ctx(history=[_hist(1000000)] * 3))
    assert res.verdicts[0].rule == "per_transaction"     # blocked
    assert res.verdicts[1].decision is not Decision.BLOCK  # not punished for it


# --------------------------------------------------------------------------- 3. velocity
def test_velocity_throttles_a_burst():
    """Six transfers inside the 10-minute window; the cap is five."""
    burst = [_hist(5000, payee="payee_21", minutes_ago=m, days_ago=0) for m in range(5)]
    res = evaluate(_plan(_transfer(5000, payee="payee_21", display="John ··4521")),
                   _ctx(history=burst))
    assert res.blocked
    assert res.verdicts[0].rule == "velocity"


def test_velocity_allows_five_and_ignores_older_rows():
    """Four in-window + this one = five, the cap. Rows outside the window are
    irrelevant — which is why the seed (rows a day apart) never fires it."""
    ctx = _ctx(history=[_hist(5000, payee="payee_21", minutes_ago=m, days_ago=0)
                        for m in range(4)]
                       + [_hist(5000, payee="payee_21", minutes_ago=30, days_ago=0)] * 10)
    res = evaluate(_plan(_transfer(5000, payee="payee_21", display="John ··4521")), ctx)
    assert not res.blocked


def test_velocity_counts_legs_within_one_plan():
    """Six transfers in a single plan is a burst too."""
    legs = [_transfer(1000, leg_id=f"t{i}", payee="payee_21", display="John ··4521")
            for i in range(1, 7)]
    res = evaluate(_plan(*legs), _ctx())
    assert res.blocked
    assert res.verdicts[-1].rule == "velocity"


# --------------------------------------------------------------------------- 4. anomaly
def test_anomaly_fires_on_a_wildly_unusual_amount():
    """Demo scenario 3: $5,000 against a $50 median is 100x. It ESCALATES —
    the user confirms — it does not block."""
    history = [_hist(5000, payee="payee_21")] * 12
    res = evaluate(_plan(_transfer(500000, payee="payee_21", display="John ··4521")),
                   _ctx(history=history))
    assert res.decision is Decision.REQUIRE_EXTRA_CONFIRMATION
    assert not res.blocked
    assert res.verdicts[0].rule == "anomaly"
    assert "John ··4521" in res.verdicts[0].reason


def test_anomaly_stays_quiet_for_a_normal_amount():
    """$500 to a payee whose median is $500 must not fire. A risk check that
    flags everything is a risk check nobody reads."""
    history = [_hist(50000, payee="payee_17")] * 6
    res = evaluate(_plan(_transfer(50000, payee="payee_17")), _ctx(history=history))
    assert res.decision is Decision.ALLOW


def test_first_ever_payee_asks_for_confirmation():
    """No baseline is not the same as a safe baseline."""
    res = evaluate(_plan(_transfer(5000, payee="payee_30", display="Landlord ··7001")),
                   _ctx(history=[_hist(50000, payee="payee_17")]))
    assert res.decision is Decision.REQUIRE_EXTRA_CONFIRMATION
    assert res.verdicts[0].rule == "anomaly"


def test_anomaly_does_not_apply_to_bills_or_equity():
    """Neither carries a payee_id, and transaction_history cannot represent
    them, so there is no per-counterparty baseline to compare against."""
    bill = ResolvedPayBill(id="t1", type="PAY_BILL", source_account="acct_savings",
                           biller_id="biller_03", biller_display="SP Group",
                           amount_cents=8000)
    res = evaluate(_plan(bill, _equity(leg_id="t2")), _ctx())
    assert res.decision is Decision.ALLOW


# --------------------------------------------------------------------------- 5. precedence + purity
def test_precedence_a_blocked_leg_reports_one_reason():
    """KYC beats everything: a pending user sending an over-limit, anomalous
    amount is told about the KYC hold, not given four errors."""
    res = evaluate(_plan(_transfer(9999999)), _ctx(kyc="PENDING"))
    assert [v.rule for v in res.verdicts] == ["kyc"]


def test_evaluate_never_mutates_the_plan():
    """The plan is what gets hashed and signed. If policy could change it, the
    binding between what the user saw and what they signed would be broken."""
    plan = _plan(_transfer(500000, payee="payee_21", display="John ··4521"))
    before = payload_hash(plan)
    evaluate(plan, _ctx(history=[_hist(5000, payee="payee_21")] * 12))
    assert payload_hash(plan) == before
    assert plan.plan[0].amount_cents == 500000


def test_audit_payload_is_canonicalizable():
    """It goes into the hash-chained log, so it must contain no float and no
    non-JSON type."""
    from backend.audit.canonical import canonical_json
    res = evaluate(_plan(_transfer(5000)), _ctx())
    assert canonical_json(res.to_audit_payload("d1"))


# --------------------------------------------------------------------------- 6. loader + gateway enforcement
def test_load_context_reads_the_seeded_ledger(tmp_path):
    db = tmp_path / "ledger.db"
    seed(db)
    ctx = load_context("u_alice", db_path=db)
    assert ctx.user["kyc_status"] == "VERIFIED"
    assert ctx.limits["per_transaction"] == 2000000
    assert len(ctx.history) == 18
    assert load_context("u_bob", db_path=db).user["kyc_status"] == "PENDING"


def test_owner_is_derived_from_the_account_rows(tmp_path):
    """ResolvedPlan carries no user_id on purpose. The gateway must not let a
    caller nominate whose limits apply — it reads the owner from the ledger."""
    db = tmp_path / "ledger.db"
    seed(db)
    assert owner_of(_plan(_transfer(5000)), db_path=db) == "u_alice"
    unknown = _plan(ResolvedTransfer(id="t1", type="TRANSFER",
                                     source_account="acct_nope", payee_id="payee_17",
                                     payee_display="Mom ··3310", amount_cents=5000))
    assert owner_of(unknown, db_path=db) is None


def _gateway(tmp_path, ttl=120):
    db = tmp_path / "ledger.db"
    seed(db)
    signer = MockSigner()
    creds = MockCredentialStore()
    creds.register("cred_alice", signer.public_key)
    gw = Gateway(drafts=_EveryPayloadIsTheDraft(), signer=signer, nonce_store=NonceStore(ttl_seconds=ttl),
                 audit=AuditLog(db), executor=MockExecutor(db), credentials=creds,
                 policy_db_path=db)
    return gw, signer, db


def _submit(gw, signer, plan):
    nonce = gw.nonce_store.issue(plan.draft_id)
    sig = signer.sign(challenge_hash(payload_hash(plan), nonce))
    return gw.submit(plan, sig, nonce, "cred_alice")


def test_gateway_rejects_a_signed_but_policy_blocked_plan(tmp_path):
    """THE enforcement test. A correctly signed payload that violates policy is
    refused at the chokepoint. Without this the policy engine is advisory: a
    caller who assembled a signed plan could skip the overlay and every limit
    with it."""
    gw, signer, db = _gateway(tmp_path)
    over_limit = _plan(_transfer(2000001), draft_id="blocked")
    out = _submit(gw, signer, over_limit)
    assert out["accepted"] is False
    assert out["rejection"] == "POLICY"
    assert "per-transaction limit" in out["reason"]


def test_policy_rejection_is_logged_to_the_audit_chain(tmp_path):
    gw, signer, db = _gateway(tmp_path)
    _submit(gw, signer, _plan(_transfer(2000001), draft_id="blocked"))
    kinds = [e["entry_type"] for e in gw.audit.all_entries()]
    assert "POLICY" in kinds
    assert gw.audit.verify_chain()["ok"] is True


def test_gateway_still_executes_an_allowed_plan(tmp_path):
    """Belt and braces: the re-check must not break the happy path."""
    gw, signer, db = _gateway(tmp_path)
    out = _submit(gw, signer, _plan(_transfer(50000), draft_id="ok"))
    assert out["accepted"] is True
    assert out["execution"]["status"] == "EXECUTED"


def test_executed_transfer_is_recorded_in_history(tmp_path):
    """Until M5 nothing but seed.py ever wrote transaction_history, so the daily
    total and velocity count never moved when a payment actually happened."""
    from backend.data.db import connect
    gw, signer, db = _gateway(tmp_path)
    before = load_context("u_alice", db_path=db)
    _submit(gw, signer, _plan(_transfer(50000), draft_id="ok"))
    after = load_context("u_alice", db_path=db)
    assert len(after.history) == len(before.history) + 1


# --------------------------------------------------------------------------- F1: every executed leg counts
def test_non_transfer_legs_count_toward_the_daily_limit(tmp_path):
    """F1 regression. transaction_history.payee_id was NOT NULL, so the executor
    could only record transfers: a $19,000 equity purchase left no trace and
    "daily limit" silently meant "daily TRANSFER limit". A user could exceed the
    daily limit by mixing leg types across drafts.

    Every executed leg is recorded now — payee_id nullable, leg_type saying what
    moved — so the daily total reflects all the money that actually left."""
    from datetime import datetime, timezone

    from backend.data.db import connect
    from backend.data.seed import seed
    from backend.gateway.executor import MockExecutor
    from backend.models.schemas import ResolvedBuyEquity, ResolvedPayBill

    db = tmp_path / "dcta.db"
    seed(db)
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    def todays_total() -> int:
        ctx = load_context(user_id="u_alice", db_path=db, now=_NOW)
        return sum(int(h["amount"]) for h in ctx.history if h["ts"][:10] == today)

    before = todays_total()
    result = MockExecutor(db).execute(_plan(
        ResolvedBuyEquity(id="t1", source_account="acct_savings", ticker="AAPL",
                          amount_cents=241_500, estimated_shares=10,
                          estimated_fill_price_cents=24_150),
        ResolvedPayBill(id="t2", source_account="acct_savings", biller_id="biller_03",
                        biller_display="SP Group", amount_cents=12_345),
    ), payload_hash="test")
    assert result["status"] == "EXECUTED"

    rows = [dict(r) for r in connect(db).execute(
        "SELECT leg_type, payee_id, amount FROM transaction_history "
        "ORDER BY id DESC LIMIT 2")]
    assert {r["leg_type"] for r in rows} == {"BUY_EQUITY", "PAY_BILL"}
    assert all(r["payee_id"] is None for r in rows), "no payee on a non-transfer leg"

    assert todays_total() == before + 241_500 + 12_345


def test_payee_less_rows_cannot_pollute_the_anomaly_baseline(tmp_path):
    """The other half of F1. The anomaly rule compares against this user's
    history WITH THIS PAYEE. Rows carrying payee_id NULL must not enter that
    median, or a big equity purchase would make a large transfer look normal."""
    from backend.data.seed import seed
    from backend.gateway.executor import MockExecutor
    from backend.models.schemas import ResolvedBuyEquity

    db = tmp_path / "dcta.db"
    seed(db)
    MockExecutor(db).execute(_plan(
        ResolvedBuyEquity(id="t1", source_account="acct_savings", ticker="AAPL",
                          amount_cents=241_500, estimated_shares=10,
                          estimated_fill_price_cents=24_150)), payload_hash="test")

    ctx = load_context(user_id="u_alice", db_path=db, now=_NOW)
    # $5,000 to a payee whose history is all $50 must still escalate.
    verdict = check_anomaly(_transfer(500_000, payee="payee_21", display="John ··4521"), ctx)
    assert verdict is not None and verdict.rule == "anomaly"
