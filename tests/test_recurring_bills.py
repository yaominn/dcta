"""
Recurring bill payments with a supervised start (docs/RECURRING_BILLS.md).

Every test here runs on its own throwaway ledger with a controlled clock: no
sleeps, no live provider. The API tests at the end use the app's TestClient on
the (re-seeded) repo DB, like the other API tests.

Pinned:
  1. Setup reads recurring wording by rules, asks for every missing detail, and
     never guesses; a one-time bill stays one-time.
  2. The mandate is signed over its exact terms; an unsigned, tampered,
     expired, wrong-user or cancelled mandate produces no debit.
  3. Payments 1-3 wait for their own signed approval; declined, expired and
     failed ones don't count. The 4th is paid automatically, once, with a
     receipt and a notification — only if the user chose that at setup.
  4. Duplicate runs, concurrent workers, retries and a restart after an
     uncertain result debit at most once; nothing runs before it's due,
     after the end, or above a cap.
  5. Pause, cancel, a changed biller, no funds, the kill switch, a policy
     block or escalation and any scam signal stop automatic payment.
  6. Month ends, time zones, missed runs and the final payment are
     deterministic.
"""
from __future__ import annotations

import contextlib
import io
import sqlite3
import threading
import time
from datetime import date

import pytest

from backend.audit.canonical import challenge_hash, payload_hash
from backend.audit.log import AuditLog
from backend.auth.credentials import MockCredentialStore
from backend.data import billers
from backend.data.db import connect
from backend.data.seed import seed
from backend.drafts import Draft, DraftStore
from backend.gateway import Gateway, MockExecutor, MockSigner, NonceStore
from backend.gateway.executor import MandateRefused
from backend.models.mandates import RecurringBillMandate
from backend.recurring import approve, clock, parse, schedule, store, terms as T
from backend.recurring.scheduler import run_due

SGT = "Asia/Singapore"
OCT_12 = schedule.due_at(date(2026, 10, 12), SGT) + 3600       # 10:00 SGT, 12 Oct 2026


# --------------------------------------------------------------------------- a throwaway bank
class Env:
    """A seeded ledger, the real gateway / executor / draft store on it, the
    mock passkey, and a clock the test moves by hand."""

    def __init__(self, db, monkeypatch):
        self.db = db
        self.now = OCT_12
        monkeypatch.setattr(clock, "now", lambda db_path=None: self.now)
        self.signer = MockSigner()
        self.creds = MockCredentialStore()
        self.creds.register("cred_alice", self.signer.public_key, user_id="u_alice")
        self.drafts = DraftStore()
        self.nonces = NonceStore()
        self.audit = AuditLog(db)
        self.executor = MockExecutor(db)
        self.gw = self.gateway()

    def gateway(self):
        return Gateway(signer=self.signer, nonce_store=self.nonces, audit=self.audit,
                       executor=self.executor, credentials=self.creds, drafts=self.drafts,
                       policy_db_path=self.db)

    def sql(self, query, args=()):
        conn = connect(self.db)
        try:
            out = [dict(r) for r in conn.execute(query, args)]
            conn.commit()
            return out
        finally:
            conn.close()

    def balance(self, account="acct_savings"):
        return self.sql("SELECT balance FROM accounts WHERE id=?", (account,))[0]["balance"]

    def form(self, **over):
        f = {"biller_id": "biller_03", "source_account": "acct_savings", "amount": "85.00",
             "frequency": "MONTHLY", "start_date": "2026-11-01", "occurrence_count": 6,
             "auto_after_supervised": True}
        f.update(over)
        return {k: v for k, v in f.items() if v is not None}

    def draft_terms(self, **over) -> RecurringBillMandate:
        draft_id = DraftStore.new_id()
        conn = connect(self.db)
        try:
            terms, errors = T.build(self.form(**over), conn=conn, user_id="u_alice",
                                    draft_id=draft_id, mandate_id=T.new_mandate_id(),
                                    transcript="pay SP Group monthly", now=self.now,
                                    sign_now=int(time.time()))
        finally:
            conn.close()
        assert terms is not None, errors
        self.drafts.put(Draft(draft_id=draft_id, user_id="u_alice", transcript="x",
                              intent_plan={}, created_at=time.time(), kind="mandate",
                              status="ready", resolved_mandate=terms))
        return terms

    def sign(self, payload, draft_id):
        nonce = self.nonces.issue(draft_id)
        return self.signer.sign(challenge_hash(payload_hash(payload), nonce)), nonce

    def enroll(self, **over) -> RecurringBillMandate:
        terms = self.draft_terms(**over)
        sig, nonce = self.sign(terms, terms.draft_id)
        out = self.gw.submit_mandate(terms, sig, nonce, "cred_alice")
        assert out["accepted"], out
        return terms

    def occ(self, terms, seq):
        return self.sql("SELECT * FROM mandate_occurrences WHERE mandate_id=? AND seq=?",
                        (terms.mandate_id, seq))[0]

    def mandate(self, terms):
        return self.sql("SELECT * FROM mandates WHERE mandate_id=?", (terms.mandate_id,))[0]

    def to_due(self, terms, seq, plus=0):
        self.now = self.occ(terms, seq)["due_at"] + plus
        return run_due(self.now, gateway=self.gw)

    def review(self, terms, seq):
        draft, *_ = approve.build_draft(terms.mandate_id, seq, user_id="u_alice", db_path=self.db,
                                        now=self.now, recent_change_hours=24, cooling_hours=12,
                                        executor=self.executor)
        if draft.status == "ready":
            self.drafts.put(draft)
        return draft

    def approve(self, terms, seq):
        draft = self.review(terms, seq)
        assert draft.status == "ready", draft.policy
        sig, nonce = self.sign(draft.resolved_plan, draft.draft_id)
        return self.gw.submit(draft.resolved_plan, sig, nonce, "cred_alice")

    def notes(self, kind=None):
        rows = self.sql("SELECT * FROM notifications ORDER BY id")
        return [r for r in rows if kind is None or r["kind"] == kind]


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = tmp_path / "ledger.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    return Env(db, monkeypatch)


def _three_approvals(env, terms):
    for seq in (1, 2, 3):
        env.to_due(terms, seq)
        assert env.approve(terms, seq)["accepted"]


# --------------------------------------------------------------------------- 6. dates, deterministic
def test_monthly_dates_use_the_last_day_of_short_months_and_return_to_the_start_day():
    dates = schedule.occurrence_dates("MONTHLY", date(2027, 1, 31), 5)
    assert dates == [date(2027, 1, 31), date(2027, 2, 28), date(2027, 3, 31),
                     date(2027, 4, 30), date(2027, 5, 31)]
    assert schedule.occurrence_dates("MONTHLY", date(2028, 1, 30), 2)[1] == date(2028, 2, 29)


def test_weekly_dates_and_counting_to_an_end_date():
    assert schedule.occurrence_dates("WEEKLY", date(2026, 10, 20), 3) == [
        date(2026, 10, 20), date(2026, 10, 27), date(2026, 11, 3)]
    assert schedule.count_until("WEEKLY", date(2026, 10, 20), date(2026, 12, 15), limit=60) == 9
    assert schedule.count_until("MONTHLY", date(2026, 11, 1), date(2027, 4, 1), limit=60) == 6


def test_due_time_is_nine_am_in_the_mandate_time_zone():
    # 09:00 SGT on 1 Nov 2026 is 01:00 UTC.
    assert schedule.due_at(date(2026, 11, 1), SGT) == 1793494800
    assert schedule.due_at(date(2026, 11, 1), "Europe/London") - schedule.due_at(
        date(2026, 11, 1), SGT) == 8 * 3600
    # The automatic window is that local day; approvals run three days more.
    assert schedule.day_end(date(2026, 11, 1), SGT) == 1793548799
    assert schedule.review_until(date(2026, 11, 1), SGT) == 1793548799 + 3 * 86400


# --------------------------------------------------------------------------- 1. reading the request
def _billers():
    return [billers.BillerRef("biller_03", "SP Group", 1, "a" * 64, "Ref ••231"),
            billers.BillerRef("biller_07", "CityGas", 1, "b" * 64, "Ref ••231")]


def test_the_brief_example_is_read_completely_by_rules():
    f = parse.extract("Pay SP Group S$85 from savings every month, starting 1 November, "
                      "for six months.", billers=_billers(), today=date(2026, 10, 12))
    assert f.to_dict() == {"biller_id": "biller_03", "source_account": "acct_savings",
                           "amount_cents": 8500, "frequency": "MONTHLY",
                           "start_date": "2026-11-01", "occurrence_count": 6, "end_date": None}
    assert f.missing() == []


@pytest.mark.parametrize("said, missing", [
    ("pay SP Group monthly", ["source_account", "amount_cents", "start_date", "end"]),
    ("pay SP Group $85 from savings starting 1 November for 6 payments", ["frequency"]),
    ("pay SP Group $85 from savings every month for six months", ["start_date"]),
    ("pay SP Group $85 from savings every month starting 1 Nov", ["end"]),
    ("pay my bill every month", ["biller_id", "source_account", "amount_cents",
                                 "start_date", "end"]),
    ("pay SP Group $85 every two months from savings starting 1 nov for 3 payments",
     ["frequency"]),
])
def test_anything_not_said_is_asked_never_guessed(said, missing):
    f = parse.extract(said, billers=_billers(), today=date(2026, 10, 12))
    assert f.missing() == missing


def test_a_date_already_past_this_year_means_next_year():
    f = parse.extract("pay SP Group $85 monthly starting 1 March for 2 payments",
                      billers=_billers(), today=date(2026, 10, 12))
    assert f.start_date == "2027-03-01"


def test_the_router_keeps_one_time_bills_one_time_and_asks_for_a_bare_bill():
    from backend.agent.router import classify_request as route
    assert route("Pay SP Group S$85 from savings every month, starting 1 November, "
                 "for six months.") == "recurring_bill"
    assert route("set up autopay for CityGas") == "recurring_bill"
    assert route("pay my bill") == "bill_ambiguous"
    assert route("pay SP Group 85 dollars") == "payment"
    assert route("Pay mom five hundred then buy Apple with the rest") == "payment"


# --------------------------------------------------------------------------- terms
def test_terms_need_an_explicit_choice_about_automatic_payment(env):
    conn = connect(env.db)
    try:
        terms, errors = T.build(env.form(auto_after_supervised=None), conn=conn,
                                user_id="u_alice", draft_id="d", mandate_id=T.new_mandate_id(),
                                transcript="x", now=env.now)
    finally:
        conn.close()
    assert terms is None and "auto_after_supervised" in errors


@pytest.mark.parametrize("over, field", [
    ({"biller_id": "biller_99"}, "biller_id"),
    ({"source_account": "acct_nobody"}, "source_account"),
    ({"amount": "eighty"}, "amount"),
    ({"amount": "25000"}, "amount"),                 # over the per-transaction limit
    ({"frequency": "DAILY"}, "frequency"),
    ({"start_date": "2026-10-01"}, "start_date"),    # in the past
    ({"occurrence_count": 61}, "end"),
    ({"occurrence_count": None}, "end"),
    ({"end_date": "2027-01-01"}, "end"),             # count AND end date
])
def test_bad_or_missing_fields_are_refused_not_fixed(env, over, field):
    conn = connect(env.db)
    try:
        terms, errors = T.build(env.form(**over), conn=conn, user_id="u_alice", draft_id="d",
                                mandate_id=T.new_mandate_id(), transcript="x", now=env.now)
    finally:
        conn.close()
    assert terms is None and field in errors


def test_terms_that_disagree_with_themselves_cannot_exist(env):
    good = env.draft_terms().model_dump()
    for change in ({"total_cap_cents": good["total_cap_cents"] + 1},
                   {"per_payment_cap_cents": good["amount_cents"] * 2},
                   {"end_date": "2027-05-01"},
                   {"valid_until": good["valid_until"] + 86400},
                   {"expires_at": good["created_at"] + 3600},
                   {"supervised_approvals": 1}):
        with pytest.raises(Exception):
            RecurringBillMandate.model_validate({**good, **change})


def test_the_end_date_option_counts_the_payments(env):
    terms = env.draft_terms(occurrence_count=None, end_date="2027-02-15")
    assert terms.occurrence_count == 4 and terms.end_date == "2027-02-01"
    assert terms.total_cap_cents == 4 * 8500


# --------------------------------------------------------------------------- 2. enrollment
def test_enrollment_stores_the_signed_terms_and_every_occurrence(env):
    terms = env.enroll()
    m = env.mandate(terms)
    assert (m["status"], m["mode"], m["supervised_successes"], m["paid_count"]) == (
        "ACTIVE", "SUPERVISED", 0, 0)
    assert m["payload_hash"] == payload_hash(terms)
    occs = env.sql("SELECT seq, due_date, status FROM mandate_occurrences WHERE mandate_id=? "
                   "ORDER BY seq", (terms.mandate_id,))
    assert [o["due_date"] for o in occs] == ["2026-11-01", "2026-12-01", "2027-01-01",
                                             "2027-02-01", "2027-03-01", "2027-04-01"]
    assert {o["status"] for o in occs} == {"SCHEDULED"}
    assert env.balance() == 842050                  # setting up moves no money
    assert [e["entry_type"] for e in env.audit.all_entries()][-1] == "MANDATE_CREATED"


def test_an_unsigned_mandate_is_refused(env):
    terms = env.draft_terms()
    nonce = env.nonces.issue(terms.draft_id)
    out = env.gw.submit_mandate(terms, None, nonce, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "SIGNATURE"
    assert env.sql("SELECT * FROM mandates") == []


def test_tampered_terms_are_refused(env):
    terms = env.draft_terms()
    sig, nonce = env.sign(terms, terms.draft_id)
    bigger = terms.model_copy(update={"amount_cents": 850000, "per_payment_cap_cents": 850000,
                                      "total_cap_cents": 850000 * 6})
    out = env.gw.submit_mandate(bigger, sig, nonce, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "SIGNATURE"
    # Even signed, terms the server didn't draft are refused.
    sig2, nonce2 = env.sign(bigger, terms.draft_id)
    out = env.gw.submit_mandate(bigger, sig2, nonce2, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "OUTDATED"
    assert env.sql("SELECT * FROM mandates") == []


def test_expired_terms_are_refused(env):
    terms = env.draft_terms()
    old = terms.model_copy(update={"created_at": terms.created_at - 1000,
                                   "expires_at": terms.expires_at - 1000})
    sig, nonce = env.sign(old, terms.draft_id)
    out = env.gw.submit_mandate(old, sig, nonce, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "EXPIRED"


def test_another_users_passkey_cannot_create_it(env):
    env.creds.register("cred_bob", env.signer.public_key, user_id="u_bob")
    env.creds.register("cred_unknown", env.signer.public_key)
    for cred in ("cred_bob", "cred_unknown"):
        terms = env.draft_terms()
        sig, nonce = env.sign(terms, terms.draft_id)
        out = env.gw.submit_mandate(terms, sig, nonce, cred)
        assert not out["accepted"] and out["rejection"] == "WRONG_USER"


def test_a_mandate_is_created_at_most_once(env):
    terms = env.enroll()
    sig, nonce = env.sign(terms, terms.draft_id)
    out = env.gw.submit_mandate(terms, sig, nonce, "cred_alice")
    assert out["rejection"] == "DUPLICATE"
    assert len(env.sql("SELECT * FROM mandates")) == 1


def test_a_biller_change_while_reviewing_is_refused(env):
    terms = env.draft_terms()
    conn = connect(env.db)
    billers.change_reference(conn, "biller_03", "Acct 99999")
    conn.commit()
    conn.close()
    sig, nonce = env.sign(terms, terms.draft_id)
    out = env.gw.submit_mandate(terms, sig, nonce, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "SUPERSEDED"


def test_no_setup_while_frozen(env):
    from backend.policy import safety
    safety.engage_kill_switch("u_alice", now=int(time.time()), db_path=env.db)
    terms = env.draft_terms()
    sig, nonce = env.sign(terms, terms.draft_id)
    out = env.gw.submit_mandate(terms, sig, nonce, "cred_alice")
    assert out["rejection"] == "KILL_SWITCH"


# --------------------------------------------------------------------------- 3. the supervised start
def test_nothing_happens_before_the_due_time(env):
    terms = env.enroll()
    env.now = env.occ(terms, 1)["due_at"] - 1
    assert run_due(env.now, gateway=env.gw) == []
    assert env.occ(terms, 1)["status"] == "SCHEDULED"


def test_payments_one_to_three_wait_for_their_own_approval(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    assert env.occ(terms, 1)["status"] == "PENDING_APPROVAL"
    assert env.balance() == 842050                    # pending is not paid
    due = env.notes("DUE")
    assert due and "approve it with your passkey" in due[-1]["body"]
    assert "http" not in due[-1]["body"]              # no link that approves anything
    # Running again changes nothing: still one prompt, still unpaid.
    run_due(env.now, gateway=env.gw)
    assert len(env.notes("DUE")) == 1 and env.balance() == 842050
    out = env.approve(terms, 1)
    assert out["accepted"] and out["execution"]["status"] == "EXECUTED"
    assert env.balance() == 842050 - 8500
    m = env.mandate(terms)
    assert (m["supervised_successes"], m["paid_count"], m["mode"]) == (1, 1, "SUPERVISED")
    assert env.occ(terms, 1)["status"] == "EXECUTED"


def test_a_declined_prompt_is_not_paid_and_does_not_count(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    draft = env.review(terms, 1)
    env.executor.close(draft.draft_id, "payment", payload_hash(draft.resolved_plan), "DECLINED")
    assert env.occ(terms, 1)["status"] == "DECLINED"
    assert env.mandate(terms)["supervised_successes"] == 0
    with pytest.raises(approve.NotApprovable):          # never offered again
        env.review(terms, 1)
    assert env.balance() == 842050


def test_an_expired_prompt_is_not_paid_later(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    env.now = env.occ(terms, 1)["review_until"] + 1
    run_due(env.now, gateway=env.gw)
    assert env.occ(terms, 1)["status"] == "EXPIRED"
    with pytest.raises(approve.NotApprovable):
        env.review(terms, 1)
    assert env.balance() == 842050 and env.mandate(terms)["supervised_successes"] == 0


def test_a_failed_approval_does_not_count(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    draft = env.review(terms, 1)
    env.sql("UPDATE accounts SET balance=100 WHERE id='acct_savings'")
    sig, nonce = env.sign(draft.resolved_plan, draft.draft_id)
    out = env.gw.submit(draft.resolved_plan, sig, nonce, "cred_alice")
    assert out["execution"]["status"] == "FAILED"
    assert env.occ(terms, 1)["status"] == "FAILED"
    assert env.mandate(terms)["supervised_successes"] == 0
    assert env.balance() == 100


def test_after_three_approvals_the_fourth_is_paid_automatically_once(env):
    terms = env.enroll()
    _three_approvals(env, terms)
    m = env.mandate(terms)
    assert (m["mode"], m["supervised_successes"]) == ("AUTO", 3)
    assert env.notes("AUTO_ON")
    before = env.balance()
    events = env.to_due(terms, 4)
    assert [e["status"] for e in events] == ["EXECUTED"]
    assert env.balance() == before - 8500
    assert env.occ(terms, 4)["status"] == "EXECUTED" and env.occ(terms, 4)["phase"] == "AUTO"
    receipt = env.notes("AUTO_PAID")[-1]
    assert "paid automatically" in receipt["body"] and env.occ(terms, 4)["draft_id"] in receipt["body"]
    # Again, from another gateway (a restart), and again: no second debit.
    run_due(env.now, gateway=env.gateway())
    run_due(env.now + 60, gateway=env.gw)
    assert env.balance() == before - 8500
    executions = [e for e in env.audit.all_entries() if e["entry_type"] == "EXECUTION"]
    assert '"authority":"mandate"' in executions[-1]["payload"]


def test_without_the_choice_every_payment_stays_supervised(env):
    terms = env.enroll(auto_after_supervised=False)
    _three_approvals(env, terms)
    assert env.mandate(terms)["mode"] == "SUPERVISED"
    before = env.balance()
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "PENDING_APPROVAL"
    assert env.balance() == before


def test_the_server_never_trusts_an_auto_flag_from_outside(env):
    """The executor refuses a MANDATE debit for a supervised occurrence, or
    for a plan that isn't an occurrence at all."""
    terms = env.enroll()
    env.to_due(terms, 1)
    occ = env.occ(terms, 1)
    plan = T.occurrence_plan(terms, draft_id=occ["draft_id"], seq=1,
                             due=date(2026, 11, 1), now=int(time.time()))
    with pytest.raises(MandateRefused):
        env.executor.execute(plan, payload_hash=payload_hash(plan), authority="mandate",
                             now=env.now)
    stray = T.occurrence_plan(terms, draft_id="not-an-occurrence", seq=1,
                              due=date(2026, 11, 1), now=int(time.time()))
    with pytest.raises(MandateRefused):
        env.executor.execute(stray, payload_hash=payload_hash(stray), authority="mandate",
                             now=env.now)
    assert env.balance() == 842050


# --------------------------------------------------------------------------- 4. at most once
def test_concurrent_workers_debit_once(env):
    terms = env.enroll()
    _three_approvals(env, terms)
    before = env.balance()
    env.now = env.occ(terms, 4)["due_at"]
    gateways = [env.gateway() for _ in range(6)]
    errors = []

    def work(gw):
        try:
            run_due(env.now, gateway=gw)
        except Exception as exc:             # pragma: no cover - surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=work, args=(g,)) for g in gateways]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert env.balance() == before - 8500
    assert len(env.notes("AUTO_PAID")) == 1


def test_a_restart_after_an_uncertain_result_does_not_pay_twice(env):
    """The debit committed but the worker died before reporting: the next run
    finds the execution key claimed and returns the recorded result."""
    terms = env.enroll()
    _three_approvals(env, terms)
    env.now = env.occ(terms, 4)["due_at"]
    env.sql("UPDATE mandate_occurrences SET phase='AUTO' WHERE mandate_id=? AND seq=4",
            (terms.mandate_id,))
    occ = env.occ(terms, 4)
    plan = T.occurrence_plan(terms, draft_id=occ["draft_id"], seq=4,
                             due=date(2027, 2, 1), now=int(time.time()))
    env.executor.execute(plan, payload_hash=payload_hash(plan), authority="mandate", now=env.now)
    before = env.balance()
    out = env.gateway().run_mandate_occurrence(terms.mandate_id, 4, now=env.now)
    assert out["status"] == "ALREADY" and out["execution"]["status"] == "EXECUTED"
    run_due(env.now, gateway=env.gateway())
    assert env.balance() == before and env.occ(terms, 4)["status"] == "EXECUTED"


def test_nothing_beyond_the_last_payment(env):
    terms = env.enroll(occurrence_count=4)
    _three_approvals(env, terms)
    env.to_due(terms, 4)
    m = env.mandate(terms)
    assert (m["status"], m["paid_count"], m["paid_total_cents"]) == ("COMPLETED", 4, 4 * 8500)
    assert env.notes("COMPLETED")
    before = env.balance()
    env.now += 400 * 86400
    run_due(env.now, gateway=env.gw)
    assert env.balance() == before


def test_a_plan_above_the_terms_is_refused_under_the_lock(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    occ = env.occ(terms, 1)
    more = T.occurrence_plan(terms.model_copy(update={"amount_cents": 9000}),
                             draft_id=occ["draft_id"], seq=1, due=date(2026, 11, 1),
                             now=int(time.time()))
    with pytest.raises(MandateRefused):
        env.executor.execute(more, payload_hash=payload_hash(more), now=env.now)
    assert env.balance() == 842050


def test_the_total_cap_holds_even_if_the_counters_were_moved(env):
    terms = env.enroll()
    _three_approvals(env, terms)
    env.sql("UPDATE mandates SET paid_total_cents=? WHERE mandate_id=?",
            (terms.total_cap_cents, terms.mandate_id))
    before = env.balance()
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "HELD" and env.balance() == before


# --------------------------------------------------------------------------- 5. what stops it
def _auto(env, **over):
    terms = env.enroll(**over)
    _three_approvals(env, terms)
    return terms, env.balance()


def test_pause_stops_it_and_resume_does_not_catch_up(env):
    terms, before = _auto(env)
    store.pause(terms.mandate_id, "u_alice", now=env.now, db_path=env.db)
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "SKIPPED" and env.balance() == before
    store.resume(terms.mandate_id, "u_alice", now=env.now, db_path=env.db)
    run_due(env.now, gateway=env.gw)
    assert env.occ(terms, 4)["status"] == "SKIPPED" and env.balance() == before
    env.to_due(terms, 5)
    assert env.occ(terms, 5)["status"] == "EXECUTED" and env.balance() == before - 8500


def test_pause_wins_against_a_waiting_approval(env):
    terms = env.enroll()
    env.to_due(terms, 1)
    draft = env.review(terms, 1)
    store.pause(terms.mandate_id, "u_alice", now=env.now, db_path=env.db)
    sig, nonce = env.sign(draft.resolved_plan, draft.draft_id)
    out = env.gw.submit(draft.resolved_plan, sig, nonce, "cred_alice")
    assert not out["accepted"] and out["rejection"] == "MANDATE"
    assert env.balance() == 842050


def test_pause_racing_a_payment_is_serialised(env):
    """The payment holds the write lock from its claim to its commit: a pause
    either lands first (nothing paid) or after (the payment is reported)."""
    terms, before = _auto(env)
    env.now = env.occ(terms, 4)["due_at"]
    results = {}

    def pay():
        results["run"] = run_due(env.now, gateway=env.gateway())

    def pause():
        results["pause"] = store.pause(terms.mandate_id, "u_alice", now=env.now, db_path=env.db)
    threads = [threading.Thread(target=pay), threading.Thread(target=pause)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    paid = env.balance() == before - 8500
    assert env.mandate(terms)["status"] == "PAUSED"
    assert env.occ(terms, 4)["status"] == ("EXECUTED" if paid else "SKIPPED")
    assert env.balance() in (before, before - 8500)


def test_cancel_is_final(env):
    terms, before = _auto(env)
    store.cancel(terms.mandate_id, "u_alice", now=env.now, db_path=env.db)
    assert store.resume(terms.mandate_id, "u_alice", now=env.now,
                        db_path=env.db)["status"] == "CANCELLED"
    for seq in (4, 5, 6):
        assert env.occ(terms, seq)["status"] == "CANCELLED"
    env.now = env.occ(terms, 4)["due_at"]
    run_due(env.now, gateway=env.gw)
    assert env.balance() == before


def test_a_changed_biller_reference_suspends_it(env):
    terms, before = _auto(env)
    conn = connect(env.db)
    billers.change_reference(conn, "biller_03", "Acct 55555")
    conn.commit()
    conn.close()
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "HELD" and env.balance() == before
    m = env.mandate(terms)
    assert m["status"] == "SUSPENDED"
    assert store.resume(terms.mandate_id, "u_alice", now=env.now,
                        db_path=env.db)["status"] == "SUSPENDED"     # needs new terms
    assert env.notes("SUSPENDED")


def test_insufficient_funds_fails_without_retry(env):
    terms, _ = _auto(env)
    env.sql("UPDATE accounts SET balance=100 WHERE id='acct_savings'")
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "FAILED" and env.balance() == 100
    assert env.notes("FAILED")
    env.sql("UPDATE accounts SET balance=900000 WHERE id='acct_savings'")
    run_due(env.now + 60, gateway=env.gw)
    assert env.occ(terms, 4)["status"] == "FAILED" and env.balance() == 900000


def test_the_kill_switch_holds_it(env):
    from backend.policy import safety
    terms, before = _auto(env)
    safety.engage_kill_switch("u_alice", now=int(time.time()), db_path=env.db)
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "HELD" and env.balance() == before


def test_a_policy_block_holds_it(env):
    terms, before = _auto(env)
    env.sql("UPDATE limits SET value=5000 WHERE key='per_transaction'")
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "HELD" and env.balance() == before


def test_a_policy_escalation_needs_the_user(env, monkeypatch):
    from backend.gateway import gateway as gw_mod
    from backend.policy import Decision, PolicyResult, Verdict
    terms, before = _auto(env)
    monkeypatch.setattr(gw_mod, "evaluate", lambda plan, ctx: PolicyResult(verdicts=[
        Verdict("b1", Decision.REQUIRE_EXTRA_CONFIRMATION, "anomaly", "unusual")]))
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "NEEDS_REVIEW" and env.balance() == before
    assert env.notes("NEEDS_REVIEW")


def test_any_scam_signal_needs_the_user(env):
    """A passkey added in the last hours (account takeover's first step) means
    no unattended payment."""
    terms, before = _auto(env)
    now = int(time.time())
    env.sql("INSERT INTO webauthn_credentials VALUES ('old', 'u_alice', x'00', 0, ?)",
            (now - 30 * 86400,))
    env.sql("INSERT INTO webauthn_credentials VALUES ('new', 'u_alice', x'00', 0, ?)", (now,))
    env.to_due(terms, 4)
    assert env.occ(terms, 4)["status"] == "NEEDS_REVIEW" and env.balance() == before


def test_a_held_payment_can_still_be_approved_by_the_user(env):
    from backend.policy import safety
    terms, before = _auto(env)
    safety.engage_kill_switch("u_alice", now=int(time.time()), db_path=env.db)
    env.to_due(terms, 4)
    safety.release_kill_switch("u_alice", now=int(time.time()), db_path=env.db)
    out = env.approve(terms, 4)
    assert out["accepted"] and env.balance() == before - 8500


def test_tampered_stored_terms_stop_everything(env):
    terms, before = _auto(env)
    env.sql("UPDATE mandates SET terms=replace(terms, '\"amount_cents\":8500', "
            "'\"amount_cents\":85000') WHERE mandate_id=?", (terms.mandate_id,))
    env.to_due(terms, 4)
    assert env.balance() == before
    assert env.mandate(terms)["status"] == "SUSPENDED"


def test_new_terms_start_their_own_supervised_count(env):
    """Changing anything material is a new mandate, signed again — and the
    three approvals don't carry over."""
    old, _ = _auto(env)
    store.cancel(old.mandate_id, "u_alice", now=env.now, db_path=env.db)
    env.now = OCT_12
    new = env.enroll(amount="90.00")
    m = env.mandate(new)
    assert (m["mode"], m["supervised_successes"]) == ("SUPERVISED", 0)


# --------------------------------------------------------------------------- 6. missed runs
def test_an_automatic_payment_whose_day_passed_is_missed_not_paid_late(env):
    terms, before = _auto(env)
    env.now = env.occ(terms, 4)["auto_until"] + 1
    run_due(env.now, gateway=env.gw)
    assert env.occ(terms, 4)["status"] == "MISSED" and env.balance() == before
    assert env.notes("MISSED")


def test_a_prompt_that_was_never_shown_in_time_is_missed(env):
    terms = env.enroll()
    env.now = env.occ(terms, 1)["review_until"] + 1
    run_due(env.now, gateway=env.gw)
    assert env.occ(terms, 1)["status"] == "MISSED"


def test_a_worker_down_for_months_does_not_catch_up(env):
    terms, before = _auto(env)
    env.now = env.occ(terms, 6)["due_at"] + 60
    run_due(env.now, gateway=env.gw)
    assert [env.occ(terms, s)["status"] for s in (4, 5, 6)] == ["MISSED", "MISSED", "EXECUTED"]
    assert env.balance() == before - 8500
    assert env.mandate(terms)["status"] == "COMPLETED"


def test_the_final_payment_completes_the_arrangement(env):
    terms, before = _auto(env)
    for seq in (4, 5, 6):
        env.to_due(terms, seq)
    m = env.mandate(terms)
    assert (m["status"], m["paid_count"]) == ("COMPLETED", 6)
    assert env.balance() == before - 3 * 8500


# --------------------------------------------------------------------------- migration
def test_an_existing_ledger_gains_the_tables_without_a_reseed(tmp_path):
    from backend.data.db import migrate
    db = tmp_path / "old.db"
    with contextlib.redirect_stdout(io.StringIO()):
        seed(db)
    conn = sqlite3.connect(db)
    for t in ("mandate_occurrences", "mandates", "notifications", "recurring_clock"):
        conn.execute(f"DROP TABLE {t}")
    conn.execute("CREATE TABLE b2 AS SELECT id, name, reference_text FROM billers")
    conn.execute("DROP TABLE billers")
    conn.execute("ALTER TABLE b2 RENAME TO billers")
    conn.commit()
    conn.close()
    conn = connect(db)
    try:
        migrate(conn)
        migrate(conn)                                  # idempotent
        assert billers.current(conn, "biller_03").version == 1
        assert conn.execute("SELECT COUNT(*) FROM mandates").fetchone()[0] == 0
        assert conn.execute("SELECT COUNT(*) FROM payees").fetchone()[0] == 4
    finally:
        conn.close()


# --------------------------------------------------------------------------- the API
@pytest.fixture
def client(monkeypatch):
    from fastapi.testclient import TestClient
    from backend.main import app
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    box = {"now": OCT_12}
    monkeypatch.setattr(clock, "now", lambda db_path=None: box["now"])
    c = TestClient(app)
    c.clock = box
    yield c
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _mock_sign(client, payload_model, draft_id):
    from backend.main import _signer
    nonce = client.get("/api/auth/nonce", params={"draft_id": draft_id}).json()["nonce"]
    return _signer.sign(challenge_hash(payload_hash(payload_model), nonce)), nonce


def test_api_from_the_sentence_to_an_automatic_payment(client):
    body = client.post("/api/drafts", json={
        "transcript": "Pay SP Group S$85 from savings every month, starting 1 November, "
                      "for six months."}).json()
    assert body["status"] == "recurring_setup" and body["missing"] == []
    f = body["fields"]
    form = {"biller_id": f["biller_id"], "source_account": f["source_account"],
            "amount": "85.00", "frequency": f["frequency"], "start_date": f["start_date"],
            "occurrence_count": f["occurrence_count"]}
    again = client.post(f"/api/recurring/setup/{body['draft_id']}", json=form).json()
    assert again["status"] == "recurring_setup" and "auto_after_supervised" in again["errors"]
    review = client.post(f"/api/recurring/setup/{body['draft_id']}",
                         json={**form, "auto_after_supervised": True}).json()
    assert review["status"] == "ready" and review["preview"]["auto_from_payment"] == 4
    terms = RecurringBillMandate.model_validate(review["mandate"])
    assert terms.biller_display == "SP Group" and terms.total_cap_cents == 51000
    sig, nonce = _mock_sign(client, terms, terms.draft_id)
    out = client.post("/api/recurring/mandates/enroll", json={
        "mandate": review["mandate"], "signature": sig, "nonce": nonce,
        "credential_id": "cred_alice"}).json()
    assert out["accepted"], out
    mid = out["mandate_id"]

    for seq in (1, 2, 3):
        conn = connect()
        due = conn.execute("SELECT due_at FROM mandate_occurrences WHERE mandate_id=? AND seq=?",
                           (mid, seq)).fetchone()["due_at"]
        conn.close()
        client.clock["now"] = due
        client.post("/api/recurring/run-due")
        pending = client.get("/api/recurring/pending").json()["pending"]
        assert [(p["mandate_id"], p["seq"]) for p in pending] == [(mid, seq)]
        card = client.post(f"/api/recurring/occurrences/{mid}/{seq}/review", json={}).json()
        assert card["status"] == "ready" and card["recurring"]["seq"] == seq
        from backend.models.schemas import ResolvedPlan
        plan = ResolvedPlan.model_validate(card["resolved_plan"])
        sig, nonce = _mock_sign(client, plan, plan.draft_id)
        res = client.post("/api/gateway/execute", json={
            "resolved_plan": card["resolved_plan"], "signature": sig, "nonce": nonce,
            "credential_id": "cred_alice"}).json()
        assert res["accepted"], res

    detail = client.get(f"/api/recurring/mandates/{mid}").json()
    assert detail["mode"] == "AUTO" and detail["approvals_left"] is None
    conn = connect()
    due4 = conn.execute("SELECT due_at FROM mandate_occurrences WHERE mandate_id=? AND seq=4",
                        (mid,)).fetchone()["due_at"]
    before = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
    conn.close()
    client.clock["now"] = due4
    events = client.post("/api/recurring/run-due").json()["events"]
    assert [e["status"] for e in events] == ["EXECUTED"]
    client.post("/api/recurring/run-due")
    conn = connect()
    after = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
    conn.close()
    assert before - after == 8500
    kinds = [n["kind"] for n in client.get("/api/recurring/notifications").json()["notifications"]]
    assert "AUTO_PAID" in kinds and "AUTO_ON" in kinds
    phone = [m["text"] for m in client.get("/api/phone/messages").json()["messages"]]
    assert any("paid automatically" in t for t in phone)

    assert client.post(f"/api/recurring/mandates/{mid}/pause", json={}).json()["status"] == "PAUSED"
    assert client.post(f"/api/recurring/mandates/{mid}/cancel", json={}).json()["status"] == "CANCELLED"


def test_api_missing_details_are_asked_and_nothing_is_signable(client):
    body = client.post("/api/drafts", json={"transcript": "pay SP Group monthly"}).json()
    assert body["status"] == "recurring_setup"
    assert set(body["missing"]) == {"source_account", "amount_cents", "start_date", "end"}
    assert len(body["questions"]) == 4
    r = client.get("/api/auth/nonce", params={"draft_id": body["draft_id"]})
    assert r.status_code == 409                       # a setup is not signable
    out = client.post(f"/api/recurring/setup/{body['draft_id']}",
                      json={"biller_id": "biller_03", "frequency": "MONTHLY"}).json()
    assert out["status"] == "recurring_setup"
    assert {"source_account", "amount", "start_date", "end",
            "auto_after_supervised"} <= set(out["errors"])
    conn = connect()
    assert conn.execute("SELECT COUNT(*) FROM mandates").fetchone()[0] == 0
    conn.close()


def test_api_a_bare_bill_is_asked_one_time_or_recurring(client):
    body = client.post("/api/drafts", json={"transcript": "pay my bill"}).json()
    assert body["status"] == "clarify" and body["kind"] == "recurrence"
    assert {c["id"] for c in body["choices"]} == {"once", "recurring"}
    once = client.post("/api/drafts", json={"transcript": "pay my bill", "recurrence": "once"})
    assert once.json().get("kind") != "recurring_setup"
    rec = client.post("/api/drafts", json={"transcript": "pay my bill",
                                           "recurrence": "recurring"}).json()
    assert rec["status"] == "recurring_setup"


def test_api_one_time_bills_are_unchanged(client):
    body = client.post("/api/drafts", json={"transcript": "pay SP Group 85 dollars from savings"}).json()
    assert body["status"] == "ready", body
    assert body["resolved_plan"]["plan"][0]["type"] == "PAY_BILL"
    conn = connect()
    assert conn.execute("SELECT COUNT(*) FROM mandates").fetchone()[0] == 0
    conn.close()


def test_api_the_demo_clock_is_off_by_default(client):
    assert client.post("/api/recurring/clock/advance", json={}).status_code == 404
    assert client.get("/api/recurring/clock").json()["demo"] is False


def test_api_a_recurring_transfer_to_a_person_is_not_offered(client):
    body = client.post("/api/drafts", json={"transcript": "send Mom 500 every month"}).json()
    assert body["status"] == "info" and body["kind"] == "recurring_unsupported"
