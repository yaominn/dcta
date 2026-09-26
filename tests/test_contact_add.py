"""
Adding a new contact from the chat — and deciding how careful to be about it.

Adding a payee is the step before most scam payments, so these pin:
  - the LLM parses the name and number; the resolver validates them; a bad or
    missing value is a question, and a number already saved is not added twice
  - deterministic rules set the FLOOR of safeguards; the LLM's scam read can
    raise it, never lower it, and cannot refuse a contact on its own
  - a clear scam is refused: nothing is saved
  - a contact is written ONLY through the gateway with a signature, the phone
    code when the draft required one, never for a reported number
  - a HOLD safeguard blocks payments to the new contact, at the gateway too
  - a payment to an unknown name offers "add them", and the answer with their
    number continues from the server's copy of that payment
"""
from __future__ import annotations

import contextlib
import io
import re
import time

import pytest
from fastapi.testclient import TestClient

from backend.agent import (StubProvider, assess_scam_risk, build_context, classify_request,
                           parse_contact_add)
from backend.audit.canonical import challenge_hash, payload_hash
from backend.data.db import connect
from backend.data.seed import seed
from backend.models.contacts import ResolvedContactAdd
from backend.policy.engine import Decision, PolicyContext, evaluate
from backend.policy.new_contact import (CODE, HOLD, REFUSE, STANDARD, NewContactFacts,
                                        decide)
from backend.models.schemas import ResolvedPlan, ResolvedTransfer


@pytest.fixture
def client():
    with contextlib.redirect_stdout(io.StringIO()):
        seed()
    from backend.main import _phone, app
    from backend.validator import default_freeze_set
    default_freeze_set.clear()
    _phone.clear()
    yield TestClient(app)
    with contextlib.redirect_stdout(io.StringIO()):
        seed()


def _payees(nickname):
    conn = connect()
    try:
        return [dict(r) for r in conn.execute(
            "SELECT * FROM payees WHERE user_id='u_alice' AND nickname=?", (nickname,))]
    finally:
        conn.close()


def _code(client):
    msgs = client.get("/api/phone/messages").json()["messages"]
    return re.search(r"code (\d{6})", msgs[0]["text"]).group(1)


def _sign_add(client, d, payload=None):
    from backend.main import _signer
    body = payload or d["contact_add"]
    add = ResolvedContactAdd.model_validate(body)
    nonce = client.get("/api/auth/nonce", params={"draft_id": add.draft_id}).json()["nonce"]
    sig = _signer.sign(challenge_hash(payload_hash(add), nonce))
    return client.post("/api/contacts/add", json={
        "contact_add": body, "signature": sig, "nonce": nonce,
        "credential_id": "cred_alice"}).json()


def _confirm(client, d):
    r = client.post(f"/api/drafts/{d['draft_id']}/confirm", json={"code": _code(client)})
    assert r.status_code == 200, r.text


# --------------------------------------------------------------------------- routing + parsing
@pytest.mark.parametrize("t", [
    "add Bob as a contact, 9123 4567",
    "add a new contact called uncle bob with number 9123 4567",
    "new contact Jim 8123 0000",
    "save Jim's number 8123 0000",
    "add uncle bob, his number is 9123 4567",
])
def test_router_sends_new_contacts_to_the_add_pipeline(t):
    assert classify_request(t) == "contact_add"


@pytest.mark.parametrize("t", ["send the change to mom", "pay mom five hundred",
                               "rename John to Johnny", "change mom's number to 9123 4567"])
def test_router_leaves_other_requests_alone(t):
    assert classify_request(t) != "contact_add"


def test_stub_parses_name_and_number_verbatim():
    ctx = build_context(payees=[], billers=[], accounts=[], equities=[])
    plan = parse_contact_add("add uncle bob as a contact, nine one two three four five six seven",
                             provider=StubProvider(), context=ctx)
    assert plan.contact.nickname == "uncle bob"
    assert plan.contact.phone == "nine one two three four five six seven"


def test_a_bare_number_takes_the_name_the_user_gave_earlier():
    ctx = build_context(payees=[], billers=[], accounts=[], equities=[])
    plan = parse_contact_add("9123 4567", provider=StubProvider(), context=ctx, name_hint="bob")
    assert (plan.contact.nickname, plan.contact.phone) == ("bob", "9123 4567")


def test_the_scam_check_never_sees_a_number_or_an_account():
    seen = {}

    class Spy(StubProvider):
        def complete(self, *, system, user):
            seen["user"] = user
            return super().complete(system=system, user=user)

    assess_scam_risk("add bob", facts={"new_contact_name": "Bob", "number_is_overseas": False},
                     provider=Spy())
    assert "9123" not in seen["user"] and "acct_" not in seen["user"]


# --------------------------------------------------------------------------- the ladder
def _facts(**kw):
    base = dict(nickname="Bob", phone="+65 9123 4567")
    base.update(kw)
    return NewContactFacts(**base)


def test_an_ordinary_contact_needs_only_the_biometric():
    d = decide(_facts(conversation="add bob, 9123 4567"), ai_risk="low", ai_signals=[],
               hold_minutes=720)
    assert d.rung == STANDARD and d.safeguards == ("BIOMETRIC",) and d.hold_minutes == 0


def test_adding_someone_to_pay_them_now_needs_a_phone_code():
    d = decide(_facts(for_payment=True, pending_cents=20000), ai_risk="low", ai_signals=[],
               hold_minutes=720)
    assert d.rung == CODE and "PHONE_CODE" in d.safeguards


def test_a_large_first_payment_puts_the_contact_on_hold():
    d = decide(_facts(for_payment=True, pending_cents=300000), ai_risk="low", ai_signals=[],
               hold_minutes=720)
    assert d.rung == HOLD and d.hold_minutes == 720


def test_mums_new_number_is_held():
    d = decide(_facts(nickname="Mom", phone="+65 8765 4321",
                      existing=[{"nickname": "Mom", "phone": "+65 9123 3310"}]),
               ai_risk="low", ai_signals=[], hold_minutes=720)
    assert d.rung == HOLD and "name_clash" in [w.code for w in d.warnings]


@pytest.mark.parametrize("said", [
    "the police officer told me to move my savings to a safe account",
    "an officer from MAS asked me to transfer it",
])
def test_an_official_giving_orders_is_refused(said):
    d = decide(_facts(conversation=said), ai_risk="low", ai_signals=[], hold_minutes=720)
    assert d.rung == REFUSE and d.safeguards == ()


def test_a_reported_number_is_refused():
    d = decide(_facts(phone="+65 8888 1234"), ai_risk="low", ai_signals=[], hold_minutes=720)
    assert d.rung == REFUSE


def test_the_llm_can_raise_the_rung_but_never_lower_it():
    risky = _facts(conversation="new number, don't tell dad")          # rules alone: HOLD
    assert decide(risky, ai_risk="low", ai_signals=[], hold_minutes=720).rung == HOLD
    plain = _facts(conversation="add bob, 9123 4567")                   # rules alone: STANDARD
    assert decide(plain, ai_risk="medium", ai_signals=[], hold_minutes=720).rung == CODE
    assert decide(plain, ai_risk="high", ai_signals=["romance"], hold_minutes=720).rung == HOLD


def test_the_llm_alone_cannot_refuse_a_contact():
    d = decide(_facts(conversation="add bob, 9123 4567"), ai_risk="high",
               ai_signals=["safe_account"], hold_minutes=720)
    assert d.rung == HOLD


def test_a_missing_scam_check_adds_care():
    d = decide(_facts(conversation="add bob, 9123 4567"), ai_risk=None, ai_signals=[],
               hold_minutes=720)
    assert d.rung == CODE and d.ai_risk == "unavailable"


# --------------------------------------------------------------------------- the hold, at policy
def _plan_to(payee_id, cents=5000):
    now = int(time.time())
    return ResolvedPlan(draft_id="d", plan=[ResolvedTransfer(
        id="t1", source_account="acct_savings", payee_id=payee_id,
        payee_display="Bob ··4567", amount_cents=cents)],
        transcript_hash="0" * 64, created_at=now, expires_at=now + 60)


def test_a_payee_on_hold_cannot_be_paid_until_it_lifts():
    now = int(time.time())
    ctx = dict(user={"kyc_status": "VERIFIED"}, limits={}, history=[], now=now)
    held = evaluate(_plan_to("payee_x"), PolicyContext(**ctx, holds={"payee_x": now + 3600}))
    assert held.decision is Decision.BLOCK and held.verdicts[0].rule == "new_contact_hold"
    after = evaluate(_plan_to("payee_x"), PolicyContext(**{**ctx, "now": now + 3601},
                                                       holds={"payee_x": now + 3600}))
    assert after.verdicts[0].rule != "new_contact_hold"


# --------------------------------------------------------------------------- end to end
def test_a_plain_contact_is_added_only_after_a_signature(client):
    d = client.post("/api/drafts", json={"transcript": "add Bob as a contact, 9123 4567"}).json()
    assert d["status"] == "ready" and d["kind"] == "contact_add"
    assert d["contact_add"]["safeguards"] == ["BIOMETRIC"]
    assert _payees("Bob") == []                                  # nothing written yet
    out = _sign_add(client, d)
    assert out["accepted"] and out["execution"]["status"] == "ADDED"
    row = _payees("Bob")[0]
    assert row["phone"] == "+65 9123 4567" and row["last4"] == "4567" and row["hold_until"] is None
    # and now it can be paid by name
    pay = client.post("/api/drafts", json={"transcript": "send 20 dollars to bob"}).json()
    assert pay["status"] == "ready"
    assert pay["resolved_plan"]["plan"][0]["payee_display"] == "Bob ··4567"


def test_an_unsigned_add_is_rejected_and_nothing_is_saved(client):
    d = client.post("/api/drafts", json={"transcript": "add Bob as a contact, 9123 4567"}).json()
    nonce = client.get("/api/auth/nonce", params={"draft_id": d["draft_id"]}).json()["nonce"]
    out = client.post("/api/contacts/add", json={
        "contact_add": d["contact_add"], "signature": None, "nonce": nonce,
        "credential_id": "cred_alice"}).json()
    assert out["accepted"] is False and out["rejection"] == "SIGNATURE"
    assert _payees("Bob") == []


def test_a_contact_that_needs_a_code_is_not_added_without_it(client):
    d = client.post("/api/drafts", json={
        "transcript": "add Bob as a contact, 9123 4567, it's urgent"}).json()
    assert d["contact_add"]["safeguards"] == ["BIOMETRIC", "PHONE_CODE"]
    assert d["requires_extra_confirmation"] is True
    assert "+65 9123 4567" in client.get("/api/phone/messages").json()["messages"][0]["text"]
    assert _sign_add(client, d)["rejection"] == "CONFIRMATION"
    assert _payees("Bob") == []


def test_a_swapped_safeguard_is_not_what_was_drafted(client):
    d = client.post("/api/drafts", json={
        "transcript": "add Bob as a contact, 9123 4567, it's urgent"}).json()
    lighter = {**d["contact_add"], "safeguards": ["BIOMETRIC"]}
    assert _sign_add(client, d, payload=lighter)["rejection"] == "OUTDATED"
    assert _payees("Bob") == []


def test_mums_new_number_is_held_and_cannot_be_paid(client):
    d = client.post("/api/drafts", json={
        "transcript": "add Mom as a contact, her new number is 8765 4321"}).json()
    assert d["status"] == "ready"
    assert "HOLD" in d["contact_add"]["safeguards"] and d["contact_add"]["hold_minutes"] > 0
    codes = [w["code"] for w in d["risk"]["warnings"]]
    assert "name_clash" in codes and "words_new_number" in codes
    _confirm(client, d)
    assert _sign_add(client, d)["accepted"]
    new = [p for p in _payees("Mom") if p["phone"] == "+65 8765 4321"][0]
    assert new["hold_until"] > time.time()
    pay = client.post("/api/drafts", json={"transcript": "send 50 dollars to mom"}).json()
    if pay["status"] == "clarify":                               # two Moms now: pick the new one
        pay = client.post(f"/api/drafts/{pay['draft_id']}/clarify",
                          json={"field": pay["field"], "choice_id": new["id"]}).json()
    assert pay["status"] == "blocked"
    assert "safety hold" in " ".join(pay["reasons"])


def test_a_scam_is_refused_and_nothing_is_saved(client):
    d = client.post("/api/drafts", json={
        "transcript": "add Officer Tan as a contact, 9000 1111, the police told me "
                      "to move my money to a safe account"}).json()
    assert d["status"] == "blocked" and d["kind"] == "contact_add"
    assert d["risk"]["rung"] == "REFUSE" and "contact_add" not in d
    assert _payees("Officer Tan") == []
    assert client.get("/api/auth/nonce", params={"draft_id": d["draft_id"]}).status_code != 200


def test_a_reported_number_is_never_added(client):
    d = client.post("/api/drafts", json={"transcript": "add Ken as a contact, 8888 1234"}).json()
    assert d["status"] == "blocked"
    assert "reported_number" in [w["code"] for w in d["risk"]["warnings"]]
    assert _payees("Ken") == []


def test_a_number_already_saved_is_not_added_twice(client):
    d = client.post("/api/drafts", json={"transcript": "add Mum as a contact, 9123 3310"}).json()
    assert d["status"] == "clarify" and d["kind"] == "phone_exists"
    assert "Mom" in d["question"]


def test_a_missing_number_is_asked_for_and_the_answer_continues(client):
    d = client.post("/api/drafts", json={"transcript": "add Bob as a new contact"}).json()
    assert d["status"] == "clarify" and d["new_contact"] == {"name": "Bob", "awaiting": "phone"}
    d2 = client.post("/api/drafts", json={"transcript": "9123 4567",
                                          "new_contact_for": d["draft_id"]}).json()
    assert d2["status"] == "ready" and d2["contact_add"]["nickname"] == "Bob"
    assert _sign_add(client, d2)["accepted"]


def test_paying_an_unknown_name_offers_to_add_them(client):
    pay = client.post("/api/drafts", json={"transcript": "send 200 dollars to uncle bob"}).json()
    assert pay["status"] == "clarify" and pay["kind"] == "payee"
    assert pay["new_contact"] == {"name": "Uncle Bob", "awaiting": "phone"}
    add = client.post("/api/drafts", json={"transcript": "his number is 9123 4567",
                                           "new_contact_for": pay["draft_id"]}).json()
    assert add["status"] == "ready" and add["contact_add"]["nickname"] == "Uncle Bob"
    # waiting to pay someone new is itself a reason for the phone code
    assert "PHONE_CODE" in add["contact_add"]["safeguards"]
    assert add["risk"]["for_payment"] is True
    _confirm(client, add)
    assert _sign_add(client, add)["accepted"]
    again = client.post("/api/drafts", json={"transcript": "send 200 dollars to uncle bob"}).json()
    assert again["status"] == "ready"


def test_a_large_waiting_payment_puts_the_new_contact_on_hold(client):
    pay = client.post("/api/drafts", json={"transcript": "send 3000 dollars to uncle bob"}).json()
    add = client.post("/api/drafts", json={"transcript": "9123 4567",
                                           "new_contact_for": pay["draft_id"]}).json()
    assert "HOLD" in add["contact_add"]["safeguards"]
    assert "large_first_payment" in add["contact_add"]["warnings"]


def test_the_answer_must_belong_to_a_draft_that_asked(client):
    r = client.post("/api/drafts", json={"transcript": "9123 4567",
                                         "new_contact_for": "no-such-draft"})
    assert r.status_code == 404
    pay = client.post("/api/drafts", json={"transcript": "send 50 dollars to mom"}).json()
    r = client.post("/api/drafts", json={"transcript": "9123 4567",
                                         "new_contact_for": pay["draft_id"]})
    assert r.status_code == 409


def test_a_signed_add_runs_once(client):
    d = client.post("/api/drafts", json={"transcript": "add Bob as a contact, 9123 4567"}).json()
    assert _sign_add(client, d)["accepted"]
    assert client.get("/api/auth/nonce", params={"draft_id": d["draft_id"]}).status_code == 409
    assert len(_payees("Bob")) == 1


def test_contact_add_is_audited_without_the_number(client):
    from backend.main import _audit
    d = client.post("/api/drafts", json={"transcript": "add Bob as a contact, 9123 4567"}).json()
    _sign_add(client, d)
    entry = [e for e in _audit.all_entries() if e["entry_type"] == "CONTACT_ADD"][-1]
    assert "9123" not in entry["payload"] and '"outcome":"ADDED"' in entry["payload"]


def test_the_llm_agreeing_with_secrecy_refuses_but_a_new_number_is_only_held():
    secret = _facts(conversation="hi mum it's me, new number, don't tell dad")
    assert decide(secret, ai_risk="high", ai_signals=["secrecy"], hold_minutes=720).rung == REFUSE
    moved = _facts(conversation="mom has a new number")
    assert decide(moved, ai_risk="high", ai_signals=["impersonation_family"],
                  hold_minutes=720).rung == HOLD
