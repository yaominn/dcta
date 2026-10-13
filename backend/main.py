"""
DCTA — Direct Conversational Transaction Agent. (brief Section 1/2)

Scenario 1 — Voice-Enabled Payment and Transaction, with KYC and basic risk
control. Stated up front, as the submission requires.

Run:  uvicorn backend.main:app --reload
This is the Milestone 0 surface: a handful of read-only endpoints that prove
the mock ledger is seeded and FastAPI is alive. The real transaction pipeline
(ASR -> LLM -> resolver -> policy -> validator -> overlay -> WebAuthn ->
gateway -> audit) is built in Milestones 1-8.
"""
from __future__ import annotations

import logging
import re
import threading
from contextlib import asynccontextmanager
import time

from typing import Literal

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, PrivateAttr, field_validator

from backend.config import settings
from backend.data.db import DB_PATH, get_conn, migrate
from backend.audit import AuditLog
from backend.audit.log import AuditEntryType
from backend.audit.canonical import payload_hash, challenge_hash, hash_transcript
from backend.gateway.gateway import CLOSED_OUTCOMES, destination_refusal
from backend.gateway.executor import AlreadyExecuted
from backend.gateway import (Gateway, NonceStore, MockSigner, MockExecutor, WebAuthnVerifier,
                             SimulatedPhone, StepUpError, StepUpStore)
from backend.auth import (
    MockCredentialStore,
    WebAuthnCredentialStore,
    registration_options,
    verify_registration,
)
from backend.models.schemas import IntentPlan, ResolvedPlan, ResolvedTransfer
from backend.agent import (ParseFailure, ProviderUnavailable, assess_scam_risk,
                           build_context, classify_question, classify_request, get_provider,
                           looks_like_payment,
                           parse_contact_add, parse_contact_edit, parse_transcript,
                           unknown_payee_fallback)
from backend.models.contacts import (ContactAddPlan, ContactEditPlan, ResolvedContactAdd,
                                     ResolvedContactChange)
from backend.models.schemas import MAX_AUTH_WINDOW_S
from backend.policy.new_contact import (NewContactFacts, decide as decide_new_contact,
                                        required_at_gateway)
from backend.policy import contact_change_refusal, contact_change_step_up
from backend.resolver.contacts import (InvalidValue, NewContact, contact_name,
                                       normalize_nickname, resolve_contact_add,
                                       resolve_contact_edit)
from backend.validator.contacts import validate_contact_add, validate_contact_change
from backend.asr import (MAX_AUDIO_BYTES,
                         ASRNoSpeech, ASRUnavailable, get_asr_provider)
from backend.resolver import Clarify, resolve
from backend import answers, ingest, spelling
from backend.agent.router import asks_only_about_past_payments
from backend.validator import default_freeze_set, validate
from backend.resolver import Clarify, Resolved, resolve
from backend.policy import Decision, evaluate, load_context
from backend.drafts import Draft, DraftStore
from backend.narrate import narrate
from backend.policy import attempts, safety, scam
from backend.trace import RecordingProvider, TraceStore
from backend.display import (account_label, add_summary, change_summary, cents_to_display,
                             plan_summary)
from backend.data import billers as _billers
from backend.data import destinations
from backend.models.mandates import DEFAULT_TIMEZONE, RecurringBillMandate
from backend.recurring import approve as recurring_approve
from backend.recurring import clock as recurring_clock
from backend.recurring import parse as recurring_parse
from backend.recurring import schedule as recurring_schedule
from backend.recurring import store as recurring_store
from backend.recurring import terms as recurring_terms
from backend.recurring.scheduler import run_due

from pathlib import Path

@asynccontextmanager
async def _lifespan(_app):
    """The release loop (_release_loop) runs while the server does. Only a real
    server starts it: tests drive Gateway.release_due() themselves."""
    stop = threading.Event()
    threading.Thread(target=_release_loop, args=(stop,), daemon=True,
                     name="release-loop").start()
    try:
        yield
    finally:
        stop.set()


app = FastAPI(
    lifespan=_lifespan,
    title="DCTA — Direct Conversational Transaction Agent",
    description=(
        "GenAI is a generator of drafts, never an executor of funds. "
        "Scenario 1 — Voice-Enabled Payment and Transaction (DBS track)."
    ),
    version="0.3.0",
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"

# Bring an existing ledger up to date (e.g. add payees.phone) without a re-seed,
# which would wipe the user's own contact edits and registered passkeys.
_mconn = get_conn()
try:
    migrate(_mconn)
finally:
    _mconn.close()


@app.get("/")
def index():
    """Serve the confirmation overlay (plain HTML/JS, brief 8). WebAuthn works
    on localhost over HTTP; the deployed demo needs HTTPS (brief 10 warning)."""
    return FileResponse(FRONTEND_DIR / "index.html")


@app.get("/api")
def root():
    return {
        "project": "DCTA",
        "scenario": "Scenario 1 — Voice-Enabled Payment and Transaction, with KYC and basic risk control",
        "core_principle": "GenAI is a generator of drafts, never an executor of funds.",
        "milestone": "5 (policy engine: KYC + limits + velocity + anomaly)",
        "credentials_configured": settings.has_credentials,
        "webauthn": {"rp_id": settings.rp_id, "expected_origin": settings.expected_origin},
        "note": "credentials empty = running on stubs; the security core needs no Tencent creds",
    }


@app.get("/api/seed/users")
def list_users():
    """Inspect seeded users (proves the DB is live)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM users").fetchall()
        return {"users": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/accounts")
def list_accounts(user_id: str = Query("u_alice")):
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM accounts WHERE user_id = ?", (user_id,)).fetchall()
        if not rows:
            raise HTTPException(status_code=404, detail=f"no accounts for {user_id}")
        return {"accounts": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/payees")
def list_payees(user_id: str = Query("u_alice")):
    """Returns the FULL payee rows — legal names + last4 included here for
    inspection only. In the real pipeline the LLM is shown only {id, nickname};
    legal_name/last4 never enter a prompt (brief 4.3 opaque IDs)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM payees WHERE user_id = ?", (user_id,)).fetchall()
        return {"payees": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/billers")
def list_billers():
    """biller_07 carries the injection in its reference_text — the exact seed
    the M3 sanitizer test will prove never reaches a prompt (brief 4.3)."""
    conn = get_conn()
    try:
        rows = conn.execute("SELECT * FROM billers").fetchall()
        return {"billers": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/seed/headline")
def headline_arithmetic():
    """Locks the Section 13 demo arithmetic so the resolver (M4) has a target.
    All money is int cents: 842050 - 50000 = 792050 -> 32 whole AAPL shares
    @ 24150 = 772800, remainder 19250. Whole-share flooring is non-negotiable.
    No floats anywhere — the _display fields are strings for the UI only."""
    conn = get_conn()
    try:
        bal = conn.execute("SELECT balance FROM accounts WHERE id='acct_savings'").fetchone()[0]
        price = conn.execute("SELECT price FROM equities WHERE ticker='AAPL'").fetchone()[0]
    finally:
        conn.close()
    after_transfer = bal - 50000                  # 792050
    shares = after_transfer // price              # 32 — floor to whole shares
    cost = shares * price                         # 772800
    remainder = after_transfer - cost            # 19250
    from backend.display import cents_to_display
    return {
        "acct_savings_balance_cents": bal,
        "acct_savings_balance_display": cents_to_display(bal),
        "after_t1_minus_500_cents": after_transfer,
        "after_t1_minus_500_display": cents_to_display(after_transfer),
        "aapl_price_cents": price,
        "aapl_price_display": cents_to_display(price),
        "estimated_whole_shares": shares,
        "share_cost_cents": cost,
        "share_cost_display": cents_to_display(cost),
        "remainder_in_source_cents": remainder,
        "remainder_in_source_display": cents_to_display(remainder),
    }


# --------------------------------------------------------------------------- M1
# The security core, served over HTTP for the demo. Singletons share one mock
# signer + one registered demo credential ("cred_alice") so the happy path is
# exercisable end to end. Real WebAuthn (M2) swaps the signer + credential store.

_signer = MockSigner()
_credentials = MockCredentialStore()
_credentials.register("cred_alice", _signer.public_key, user_id="u_alice")   # MOCK demo credential


# The three routes below that use _signer/_gateway are the MOCK path: a
# server-held HMAC stands in for the user's biometric, and /api/auth/mock-sign
# hands that signature to anyone who asks. Left reachable, that is three HTTP
# calls from a fabricated plan to moved money — no passkey, no human. So they
# exist only when MOCK_SIGNING is on (tests, the red-team runner), and are
# otherwise indistinguishable from a route that was never defined: the same
# 404 body, absent from /docs, checked BEFORE the request body is parsed so a
# probe learns nothing about the schema either.
#
# Checked per request, not at import, so a test can flip it on one process
# without a restart. cred_alice above is reachable only through these routes;
# with them off it is inert, and the WebAuthn path never consults it.
def _require_mock_signing(request: Request) -> None:
    if not settings.mock_signing:
        logging.warning("blocked call to disabled mock-signing route %s %s",
                        request.method, request.url.path)
        raise HTTPException(status_code=404, detail="Not Found")


_MOCK_ONLY = {"dependencies": [Depends(_require_mock_signing)],
              "include_in_schema": settings.mock_signing}

if settings.mock_signing:
    logging.warning(
        "MOCK_SIGNING IS ON: /api/auth/mock-sign issues valid signatures to any "
        "caller, so payments and contact edits can be executed with NO "
        "biometric. Never run a demo or any reachable server like this.")

_nonce_store = NonceStore(ttl_seconds=120)
# Out-of-band step-up (gateway/stepup.py): an anomaly verdict needs a code sent
# to the user's phone before the gateway will execute. Shared by both gateways.
_step_up = StepUpStore()
_phone = SimulatedPhone()    # MOCK: the "phone" the code is delivered to
_audit = AuditLog(DB_PATH)
_executor = MockExecutor(DB_PATH)
# What the pipeline drafted. Built before the gateways because they consult it:
# only a `ready` draft's exact payload may execute.
_drafts = DraftStore()
_gateway = Gateway(
    signer=_signer,
    nonce_store=_nonce_store,
    audit=_audit,
    executor=_executor,
    credentials=_credentials,
    policy_db_path=DB_PATH,      # M5: policy is enforced at the chokepoint
    step_up=_step_up,
    drafts=_drafts,
    recent_change_hours=settings.recent_change_hours,
    cooling_hours=settings.credential_cooling_hours,
)


# --------------------------------------------------------------------------- M2
# Real WebAuthn path. The gateway's submit() logic is IDENTICAL to the mock
# path above (same expiry -> nonce -> signature -> execute -> log order); only
# the injected strategies differ: a DB-backed credential store returning COSE
# public keys + sign counts, and a verifier that runs
# webauthn.verify_authentication_response. The nonce store, audit log and
# executor are SHARED so a nonce issued once works for whichever path submits,
# and every event lands in one hash-chained audit. (brief 4.2: the gateway is
# the single chokepoint; here two configured instances of one class share it.)
_webauthn_credentials = WebAuthnCredentialStore(DB_PATH)
_webauthn_gateway = Gateway(
    signer=WebAuthnVerifier(
        credential_store=_webauthn_credentials,
        rp_id=settings.rp_id,
        expected_origin=settings.expected_origin,
    ),
    nonce_store=_nonce_store,     # shared
    audit=_audit,                 # shared
    executor=_executor,           # shared (one ledger)
    credentials=_webauthn_credentials,
    policy_db_path=DB_PATH,       # shared — the same limits on both paths
    step_up=_step_up,             # shared — one confirmation, either path
    drafts=_drafts,               # shared — the same drafts on both paths
    recent_change_hours=settings.recent_change_hours,
    cooling_hours=settings.credential_cooling_hours,
)

# In-memory registration challenges (user_id -> (challenge bytes, issued_at)).
# Anti-replay for the registration ceremony itself; TTL 120s like the signing
# nonce. Demo-scale; a deployment would persist + TTL-sweep this.
_registration_challenges: dict[str, tuple[bytes, float]] = {}
_REG_CHALLENGE_TTL = 120.0

# The mock demo session (brief 8: app login is a mock session). M2 registers a
# passkey FOR this user; signing verifies against it.
DEMO_USER_ID = "u_alice"


def _reported_contact(draft: Draft) -> str | None:
    """A contact change or addition whose number is now on the scam list — the
    gateway's own check (a payment's is destination_refusal's), asked before a
    signing challenge so the page doesn't ask for a fingerprint it would refuse."""
    if draft.kind == "contact_edit" and draft.resolved_change is not None:
        return contact_change_refusal(draft.resolved_change)
    if draft.kind == "contact_add" and draft.resolved_add is not None:
        return required_at_gateway(draft.resolved_add.nickname, draft.resolved_add.phone)
    return None


def _removed_from_contacts(change: ResolvedContactChange) -> str | None:
    """The contact an edit was drafted for, if it has been removed since. The
    executor refuses the edit regardless; this keeps the fingerprint unasked."""
    conn = get_conn()
    try:
        gone = destinations.removed(conn, {e.payee_id for e in change.edits})
    finally:
        conn.close()
    return next((e.payee_display for e in change.edits if e.payee_id in gone), None)


@app.get("/api/auth/nonce")
def issue_nonce(draft_id: str = Query(...)):
    """Issue a draft-bound, single-use, 120s-TTL nonce (brief 4.5).
    The nonce binds to this draft_id — a swap-after-approval fails at the gateway.

    M6 freeze (brief §6): a draft the validator froze is unsignable, not merely
    labelled frozen. Freeze = no nonce is ever issued for that draft_id, so no
    WebAuthn challenge can be created and the gateway rejects any submission. The
    validator is read-only and reaches neither gateway/ nor auth/ (CI-checked);
    it records the freeze, and this one line enforces it."""
    if draft_id in default_freeze_set:
        _traces.event(draft_id, "nonce", issued=False, reason="frozen by the validator")
        raise HTTPException(
            status_code=403,
            detail={"error": "draft frozen by validator", "draft_id": draft_id},
        )
    # At most once: a draft that already ran gets no nonce, so the page never
    # asks for a second fingerprint. (The gateway refuses a repeat regardless;
    # this is what makes a double tap harmless AND quiet.) 409 carries the
    # original outcome so the page can show what happened.
    prior = _executor.prior_execution(draft_id)
    if prior is not None and prior["outcome"] in CLOSED_OUTCOMES:
        _traces.event(draft_id, "nonce", issued=False, reason=prior["outcome"].lower())
        raise HTTPException(status_code=409, detail={
            "error": f"draft {prior['outcome'].lower()}", "draft_id": draft_id,
            "closed": True, "status": prior["outcome"].lower()})
    if prior is not None:
        _traces.event(draft_id, "nonce", issued=False, reason="already executed")
        raise HTTPException(status_code=409, detail={
            "error": "draft already executed", "draft_id": draft_id,
            "already_executed": True, "outcome": prior["outcome"],
            "execution": prior["result"], "executed_at": prior["executed_at"]})
    # A nonce only for a draft this app made that can still execute. It used to
    # be issued for ANY draft_id — which is how a payment for a draft that never
    # existed got signed. The gateway refuses those regardless; refusing here
    # keeps the page from asking for a fingerprint that cannot count.
    draft = _drafts.get(draft_id)
    if draft is None:
        _traces.event(draft_id, "nonce", issued=False, reason="no such draft")
        raise HTTPException(status_code=404, detail={
            "error": "no such draft (it expired or was never created)", "draft_id": draft_id})
    if draft.status != "ready":
        _traces.event(draft_id, "nonce", issued=False, reason=f"draft is {draft.status}")
        raise HTTPException(status_code=409, detail={
            "error": f"draft is {draft.status}", "draft_id": draft_id,
            "status": draft.status})
    # Frozen, or still on a safety hold: no signing challenge yet, so the page
    # never asks for a fingerprint that the gateway would refuse. (The gateway
    # enforces both regardless — this is what keeps the prompt honest.)
    if safety.kill_switch_engaged(draft.user_id) is not None:
        _traces.event(draft_id, "nonce", issued=False, reason="payments frozen")
        raise HTTPException(status_code=409, detail={
            "error": "payments are frozen", "draft_id": draft_id, "frozen": True})
    # A recurring occurrence's approval: only while its mandate still allows it
    # (not paused, cancelled or changed). The executor re-checks under its lock.
    occ_refusal = _occurrence_refusal(draft)
    if occ_refusal is not None:
        _traces.event(draft_id, "nonce", issued=False, reason=occ_refusal)
        raise HTTPException(status_code=409, detail={
            "error": occ_refusal, "draft_id": draft_id, "rejection": "MANDATE"})
    hold = safety.get_hold(draft_id)
    if hold and hold["status"] == "CANCELLED":
        _traces.event(draft_id, "nonce", issued=False, reason="hold cancelled")
        raise HTTPException(status_code=409, detail={
            "error": "this payment's hold was cancelled", "draft_id": draft_id})
    if (hold and draft.payload is not None
            and not safety.hold_covers(hold, payload_hash(draft.payload))):
        _traces.event(draft_id, "nonce", issued=False, reason="hold is for another payload")
        raise HTTPException(status_code=409, detail={
            "error": "this payment's safety hold was for a different payment — cancel it "
                     "and ask again", "draft_id": draft_id, "rejection": "HOLD_REQUIRED"})
    if hold and hold["status"] == "PENDING" and time.time() < hold["release_at"]:
        left = int(hold["release_at"] - time.time())
        _traces.event(draft_id, "nonce", issued=False, reason="on hold", seconds_left=left)
        raise HTTPException(status_code=409, detail={
            "error": f"on a safety hold for {left} more seconds", "draft_id": draft_id,
            "held": True, "seconds_left": left})
    if draft.kind == "payment" and draft.resolved_plan is not None:
        stale = destination_refusal(draft.resolved_plan, DB_PATH)
        if stale is not None:                  # a new number since this was drafted
            _traces.event(draft_id, "nonce", issued=False, reason=stale[0])
            raise HTTPException(status_code=409, detail={
                "error": _STALE_DESTINATION[stale[0]], "draft_id": draft_id,
                "rejection": stale[0]})
    if draft.kind == "contact_edit" and draft.resolved_change is not None:
        gone = _removed_from_contacts(draft.resolved_change)
        if gone is not None:                   # removed since it was drafted
            _traces.event(draft_id, "nonce", issued=False, reason="contact removed")
            raise HTTPException(status_code=409, detail={
                "error": f"{gone} was removed from your contacts — nothing to change",
                "draft_id": draft_id, "rejection": "REMOVED"})
    reported = _reported_contact(draft)
    if reported is not None:                   # reported since it was drafted
        _traces.event(draft_id, "nonce", issued=False, reason="reported number")
        raise HTTPException(status_code=409, detail={
            "error": reported, "draft_id": draft_id, "rejection": "POLICY"})
    if draft.kind == "payment" and draft.resolved_plan is not None and draft.scam_floor:
        fresh = _rescore(draft, draft.resolved_plan, int(time.time()))
        if (scam.rose_past_drafted(draft.scam_floor, fresh.outcome)
                or scam.asks_unasked(fresh, draft.purpose is not None)):
            _traces.event(draft_id, "nonce", issued=False, reason="riskier than drafted",
                          drafted=draft.scam_floor, now=fresh.outcome)
            raise HTTPException(status_code=409, detail={
                "error": "this payment looks riskier than when it was drafted — cancel "
                         "it and ask again", "draft_id": draft_id, "rescored": True})
    _traces.event(draft_id, "nonce", issued=True, ttl_seconds=_nonce_store.ttl)
    return {"nonce": _nonce_store.issue(draft_id),
            "draft_id": draft_id, "ttl_seconds": _nonce_store.ttl}


@app.get("/api/auth/config")
def webauthn_config():
    """The RP ID the server verifies against (M1: registration and signing must
    not disagree). The browser uses THIS for navigator.credentials.get rpId
    rather than location.hostname — reaching the app at 127.0.0.1 instead of
    localhost would otherwise register on one RP id and fail to sign on another
    with an unhelpful error. One source of truth -> the two cannot diverge."""
    return {"rp_id": settings.rp_id}


class MockSignRequest(BaseModel):
    """# MOCK — tests and the red-team runner only (MOCK_SIGNING; 404 otherwise).
    Lets an HTTP client obtain a valid signature over the canonical challenge
    without the server's mock secret, which is exactly why it must not be
    reachable on a demo: the browser signs via WebAuthn."""
    resolved_plan: ResolvedPlan | None = None
    mandate: RecurringBillMandate | None = None       # recurring terms (the same mock)
    nonce: str


@app.post("/api/auth/mock-sign", **_MOCK_ONLY)
def mock_sign(req: MockSignRequest):
    payload = req.resolved_plan if req.resolved_plan is not None else req.mandate
    if payload is None:
        raise HTTPException(422, {"error": "nothing to sign"})
    p_hash = payload_hash(payload)
    challenge = challenge_hash(p_hash, req.nonce)
    return {"signature": _signer.sign(challenge),
            "payload_hash": p_hash, "challenge": challenge,
            "credential_id": "cred_alice"}


class ExecuteRequest(BaseModel):
    """The ONLY shape the gateway accepts (brief 4.2): payload + signature + nonce.
    resolved_plan is validated into the frozen ResolvedPlan schema on the way in."""
    resolved_plan: ResolvedPlan
    signature: str | None = None
    nonce: str
    credential_id: str


@app.post("/api/gateway/execute", **_MOCK_ONLY)
def gateway_execute(req: ExecuteRequest):
    """The single execution chokepoint. Verifies nonce -> signature -> executes.
    Returns accepted=True on success; accepted=False (rejected+logged) on any
    verification failure (brief acceptance test: unsigned request rejected+logged)."""
    return _traced_gateway(req.resolved_plan.draft_id, "mock signer",
                           _gateway.submit(req.resolved_plan, req.signature,
                                           req.nonce, req.credential_id))


def _traced_gateway(draft_id: str, path: str, out: dict) -> dict:
    # The draft's state follows the ledger: once executed (or refused as a
    # repeat of one that was), it is no longer "ready". The executions table,
    # not this field, is what enforces it.
    if out.get("accepted") or out.get("rejection") == "DUPLICATE":
        draft = _drafts.get(draft_id)
        if draft is not None:
            draft.status = "scheduled" if out.get("scheduled") else "executed"
    _traces.event(draft_id, "gateway", path=path, accepted=out.get("accepted"),
                  rejection=out.get("rejection"), reason=out.get("reason"),
                  execution=out.get("execution"), payload_hash=out.get("payload_hash"))
    return out


@app.get("/api/audit/chain")
def audit_chain():
    """List the hash-chained audit log in order."""
    return {"entries": _audit.all_entries()}


@app.get("/api/audit/verify")
def audit_verify():
    """verify_chain(): ok=True or the exact entry where tampering broke the chain."""
    return _audit.verify_chain()


# --------------------------------------------------------------------------- M2: WebAuthn
def _get_user(user_id: str) -> dict:
    conn = get_conn()
    try:
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        if row is None:
            raise HTTPException(404, f"no such user {user_id}")
        return dict(row)
    finally:
        conn.close()


class RegisterBeginRequest(BaseModel):
    user_id: str = DEMO_USER_ID


@app.post("/api/auth/register/begin")
def register_begin(req: RegisterBeginRequest = RegisterBeginRequest()):
    """Begin a WebAuthn registration. UV=REQUIRED -> only a biometric-capable
    authenticator may enroll. The server-issued challenge is verified on
    completion (anti-replay for the registration ceremony)."""
    from webauthn.helpers import bytes_to_base64url  # local import: keeps M1 import-light
    user = _get_user(req.user_id)
    options_json, challenge = registration_options(
        rp_id=settings.rp_id,
        rp_name=settings.rp_name,
        user_id=user["id"],
        username=user["nickname"],
    )
    _registration_challenges[req.user_id] = (challenge, time.time())
    return {"options": options_json, "user_id": req.user_id}


class RegisterCompleteRequest(BaseModel):
    user_id: str = DEMO_USER_ID
    credential: dict   # the PublicKeyCredential JSON the browser produced


@app.post("/api/auth/register/complete")
def register_complete(req: RegisterCompleteRequest):
    """Verify the registration response and store the credential. A replayed or
    stale challenge, wrong RP/origin, or a non-UV assertion is rejected."""
    from webauthn.helpers import bytes_to_base64url
    entry = _registration_challenges.pop(req.user_id, None)
    if entry is None or (time.time() - entry[1]) > _REG_CHALLENGE_TTL:
        raise HTTPException(400, "registration challenge expired or missing")
    challenge = entry[0]
    try:
        cred_id_bytes, pubkey_bytes, sign_count = verify_registration(
            credential_payload=req.credential,
            expected_challenge=challenge,
            rp_id=settings.rp_id,
            expected_origin=settings.expected_origin,
        )
    except Exception as exc:
        raise HTTPException(400, f"registration verification failed: {exc}")
    cred_id_b64url = bytes_to_base64url(cred_id_bytes)
    _webauthn_credentials.store(cred_id_b64url, req.user_id, pubkey_bytes, sign_count)
    return {"credential_id": cred_id_b64url, "user_id": req.user_id}


@app.get("/api/auth/credentials")
def list_credentials(user_id: str = Query(DEMO_USER_ID)):
    """A user's registered passkeys (for the overlay's allowCredentials list)."""
    creds = _webauthn_credentials.list_for_user(user_id)
    return {"user_id": user_id,
            "credential_ids": [c.credential_id for c in creds]}


@app.get("/api/drafts/demo")
def demo_draft():
    """The hard-coded demo transfer (brief M2): $500 from savings to Mom.
    The resolver (M4) will produce this from speech; for M2 it is fixed so the
    signing flow can be built and tested in isolation. Fresh timestamps keep the
    authorization window valid (created_at ~ now, expires_at ~ now+300, the cap)."""
    now = int(time.time())
    return ResolvedPlan(
        schema_version="1",
        draft_id="demo",
        plan=[
            ResolvedTransfer(
                id="t1", type="TRANSFER", source_account="acct_savings",
                payee_id="payee_17", payee_display="Mom", amount_cents=50000,
            )
        ],
        transcript_hash=hash_transcript("stub: transfer five hundred to mom"),
        created_at=now,
        expires_at=now + 300,
    )


class WebAuthnExecuteRequest(BaseModel):
    """The real signing path. `assertion` is the WebAuthn AuthenticationCredential
    JSON the browser produced over sha256(payload_hash + nonce). The gateway
    re-derives the challenge from its OWN payload_hash + the nonce and verifies
    the assertion against it (brief 4.5)."""
    resolved_plan: ResolvedPlan
    assertion: dict
    nonce: str
    credential_id: str


@app.post("/api/gateway/execute-webauthn")
def webauthn_execute(req: WebAuthnExecuteRequest):
    """The single execution chokepoint, WebAuthn path. Same submit() logic as the
    mock path: expiry -> nonce -> signature -> execute -> audit. The verifier
    rejects a non-biometric assertion (UV flag unset), a wrong-origin/wrong-RP
    assertion, a stale challenge, or a replayed sign count."""
    return _traced_gateway(req.resolved_plan.draft_id, "WebAuthn",
                           _webauthn_gateway.submit(req.resolved_plan, req.assertion,
                                                    req.nonce, req.credential_id))


# --------------------------------------------------------------------------- M3: LLM parser + opaque IDs
class PlanRequest(BaseModel):
    """Text input standing in for ASR output (brief: 'text input demos the
    architecture fine'). The transcript is user speech — untrusted but
    authorized; it is defended by schema-constrained output, not secrecy."""
    transcript: str
    user_id: str = DEMO_USER_ID

    _clean = field_validator("transcript", mode="before")(
        lambda v: ingest.clean(v) if isinstance(v, str) else v)


@app.post("/api/plan", response_model=None)
def create_plan(req: PlanRequest):
    """M3 done-when: text input -> valid symbolic plan with mentions; stored
    untrusted fields never in prompt.

    Stored rows are fetched HERE (the agent package stays DB-free) and passed
    through the sanitizer, so build_context() is the single chokepoint between
    third-party data and any prompt: payee legal names, last4s, biller
    reference text, account ids and balances never leave this function.
    Returns the validated IntentPlan (mentions + symbolic amounts only), the
    provider that produced it, and the transcript hash that M4 will bind into
    the ResolvedPlan. A plan with `unresolved` entries is a VALID 200 — the
    clarify loop (M4) consumes them; guessing is what we refuse to do."""
    conn = get_conn()
    try:
        payees = [dict(r) for r in conn.execute(
            "SELECT * FROM payees WHERE user_id=? AND removed_at IS NULL",
            (req.user_id,)).fetchall()]
        billers = [dict(r) for r in conn.execute("SELECT * FROM billers").fetchall()]
        accounts = [dict(r) for r in conn.execute(
            "SELECT * FROM accounts WHERE user_id=?", (req.user_id,)).fetchall()]
        equities = [dict(r) for r in conn.execute("SELECT * FROM equities").fetchall()]
    finally:
        conn.close()

    context = build_context(payees=payees, billers=billers,
                            accounts=accounts, equities=equities)
    for flag in context.flags:   # layer-4 tripwire: log the attempt, weakest layer
        logging.warning("injection tripwire: stored field flagged: %s", flag)

    provider = get_provider(settings)
    try:
        plan = parse_transcript(req.transcript, provider=provider, context=context)
    except ProviderUnavailable as exc:
        # The upstream model could not be reached at all (bad key, rate limit,
        # timeout, transport error). That is not an internal error and not a
        # parse failure: 502, with no stack trace leaking to the caller.
        raise HTTPException(status_code=502, detail={
            "error": "LLM provider unavailable",
            "provider": provider.name,
            "attempts": exc.errors,
        })
    except ParseFailure as exc:
        # fail closed: a model that can't produce a valid plan produces no draft
        raise HTTPException(status_code=422, detail={
            "error": "could not produce a schema-valid plan within the retry budget",
            "attempts": exc.errors,
        })
    return {
        "intent_plan": plan.model_dump(mode="json"),
        "provider": provider.name,
        "transcript_hash": hash_transcript(req.transcript),
    }


# --------------------------------------------------------------------------- M6: independent validator
class ValidateRequest(BaseModel):
    """The three inputs the validator audits (brief §3): what the LLM said, what
    the resolver produced, and what the user said. The resolved_plan is what
    would be signed; the intent_plan carries the literal-vs-symbolic distinction
    that decides which amount check runs (brief §4.1)."""
    intent_plan: IntentPlan
    resolved_plan: ResolvedPlan
    transcript: str


@app.post("/api/validate", response_model=None)
def validate_draft(req: ValidateRequest):
    """M6: a second, read-only audit of the draft before the user sees it.

    Deterministic checks (beneficiary, amount) freeze on mismatch; the freeze is
    enforced at /api/auth/nonce. The LLM half uses a SEPARATE prompt via the
    existing provider interface; with no credentials it is recorded as
    'unavailable' and never freezes (brief §5)."""
    provider = get_provider(settings)
    # The user's answers from the SERVER's record of the draft — never from the
    # request, whose caller could claim any "choice". Same answers as the
    # pipeline used, so the two validation paths agree.
    stored = _drafts.get(req.resolved_plan.draft_id)
    report = validate(
        req.intent_plan, req.resolved_plan, req.transcript,
        provider=provider, audit=_audit,
        answers=stored.answers if stored is not None else None,
    )
    return {
        "verdict": report.verdict,
        "draft_id": report.draft_id,
        "frozen": report.frozen,
        "checks": report.checks,
        "soft_signals": report.soft_signals,
        "llm_check": report.llm_check,
    }


# --------------------------------------------------------------------------- M7: speech to text
class TranscribeResponse(BaseModel):
    transcript: str
    provider: str


@app.post("/api/transcribe", response_model=None)
async def transcribe(audio: UploadFile = File(...), fmt: str | None = None):
    """Server-side speech-to-text (tier 1 of 3).

    Credentials cannot reach the browser, so the Tencent path is necessarily
    browser -> here -> Tencent. With no credentials configured this returns 503
    and names the tier to fall back to; the browser then uses the Web Speech
    API, and text input always works regardless. A 503 here is NOT a product
    failure — it is the degradation path working as designed (brief §5).
    """
    provider = get_asr_provider(settings)

    # `fmt` is what the BROWSER says it recorded, so it is caller-supplied input
    # that would otherwise go straight upstream. Checked against the containers
    # THIS provider documents, on our side, before a byte leaves the building
    # — the same reason the LLM's output is validated here rather than trusted.
    # Per provider because they differ where it matters: OpenAI takes Chrome's
    # default webm, Tencent does not.
    #
    # 415 rather than 503: the service is up, this container is the problem.
    # The client treats both as "drop a tier", so the user still gets Web Speech.
    container = (fmt or settings.asr_voice_format).lower()
    if container not in provider.formats:
        raise HTTPException(status_code=415, detail={
            "error": f"unsupported audio container {container!r}; "
                     f"the {provider.name} provider accepts "
                     f"{', '.join(sorted(provider.formats))}",
            "provider": provider.name,
            "fallback": "webspeech",
        })

    raw = await audio.read()
    if not raw:
        raise HTTPException(status_code=400, detail={"error": "empty audio upload"})
    # Upstream caps a request at 60s / 5MB, so a larger body cannot succeed.
    # Refusing it here keeps an oversized upload from being forwarded (and from
    # sitting in memory any longer than the read that produced it).
    if len(raw) > MAX_AUDIO_BYTES:
        raise HTTPException(status_code=413, detail={
            "error": f"audio too large: {len(raw)} bytes exceeds the "
                     f"{MAX_AUDIO_BYTES}-byte limit (~60s)",
            "fallback": "webspeech",
        })

    try:
        text = provider.transcribe(raw, fmt=container)
    except ASRNoSpeech as exc:
        # The provider is fine; the clip held nothing it could recognise. 422,
        # NOT 503: the browser must ask the user to try again on THIS tier, not
        # conclude server ASR is down and abandon it for the session.
        logging.info("ASR heard no speech: provider=%s fmt=%s bytes=%d",
                     provider.name, container, len(raw))
        raise HTTPException(status_code=422, detail={
            "error": str(exc),
            "provider": provider.name,
            "no_speech": True,
        })
    except ASRUnavailable as exc:
        # The browser gets this detail, but it then drops a tier and moves on,
        # so without a server-side line the REASON is lost: a rejected
        # container, a silent clip and a quota error all look like "503".
        # Metadata and the upstream error only — never the audio or the words.
        logging.warning("ASR unavailable: provider=%s fmt=%s bytes=%d: %s",
                        provider.name, container, len(raw), exc)
        raise HTTPException(status_code=503, detail={
            "error": str(exc),
            "provider": provider.name,
            "fallback": "webspeech",     # the client drops a tier on this
        })
    return TranscribeResponse(transcript=text, provider=provider.name)


# --------------------------------------------------------------------------- M8: the wired pipeline
# The one endpoint that joins every milestone. Until this existed the resolver
# (M4) and the policy engine (M5) were unreachable over HTTP and the overlay
# signed a hard-coded draft, so nothing could be demonstrated end to end.
#
#   transcript -> parse (M3) -> resolve (M4) -> policy (M5) -> validate (M6)
#              -> a stored, signable draft -> nonce -> WebAuthn -> gateway (M1/M2)
#
# Each stage can stop the pipeline, and a stage that stops it produces NO
# signable draft — the fail-closed direction, every time.
_traces = TraceStore()      # MOCK/demo: what each request was told and did (/data)


class DraftRequest(BaseModel):
    """Text stands in for ASR output (brief: "text input demos the architecture
    fine"). The transcript is user speech: untrusted but authorized."""
    transcript: str
    user_id: str = DEMO_USER_ID
    # Cleaned before anything reads it (backend/ingest.py): the router, the
    # model, the rules and the transcript hash the signature binds all see the
    # same normalised text.
    _clean = field_validator("transcript", mode="before")(
        lambda v: ingest.clean(v) if isinstance(v, str) else v)
    # Set when this message answers "what's Bob's number?": the id of the draft
    # that asked (a payment that named an unknown payee, or a new contact still
    # missing its number). The server reads the name and any waiting payment
    # from ITS copy of that draft, never from the client.
    new_contact_for: str | None = None
    # The user's answer to "one payment, or a recurring one?" (asked for a bare
    # "pay my bill"). Only ever narrows: "once" can't create a mandate, and
    # "recurring" only opens the setup form, which needs its own signature.
    recurrence: Literal["once", "recurring"] | None = None
    # (typed, read as) for each word the server corrected: never sent by a
    # client, only set by _autocorrect and shown on the trace.
    _corrected: list = PrivateAttr(default_factory=list)


def _autocorrect(req: DraftRequest, *, billers: list, equities: list,
                 payees: list) -> DraftRequest:
    """The request with its typos fixed (backend/spelling.py), so every step
    after this one, from routing to the transcript hash the signature binds,
    reads the same words. Contact names are kept exactly as typed; biller
    names and tickers are a closed list, so a near miss is corrected to one."""
    fixed, changes = spelling.correct(
        req.transcript,
        names=[b["name"] for b in billers] + [e["ticker"] for e in equities],
        keep=[p["nickname"] for p in payees])
    if not changes:
        return req
    out = req.model_copy(update={"transcript": fixed})
    out._corrected = changes
    return out


def _trace_start(trace_id: str, req: DraftRequest, route: str) -> None:
    _traces.start(trace_id, transcript=req.transcript, route=route, user_id=req.user_id)
    if req._corrected:
        _traces.event(trace_id, "autocorrect", note="typos fixed before anything read them",
                      changes=[{"typed": a, "read_as": b} for a, b in req._corrected])


class ClarifyAnswer(BaseModel):
    """The ONLY thing a client sends back to answer a question: which candidate
    it picked. Never the plan, never the resolver's state — see backend/drafts.py
    for why the state stays server-side."""
    field: str
    choice_id: str


def _pipeline(draft: Draft) -> dict:
    """Run resolve -> policy -> validate over a stored draft and update it.

    Called on creation and again after every clarification answer, so an
    answered draft goes through exactly the same checks as a first-pass one —
    there is no shortcut path that skips policy or the validator."""
    plan = IntentPlan.model_validate(draft.intent_plan)
    outcome = resolve(
        plan,
        transcript=draft.transcript,
        user_id=draft.user_id,
        draft_id=draft.draft_id,          # stable across the clarify loop
        answers=draft.answers,
    )

    if isinstance(outcome, Clarify):
        draft.status = "clarify"
        draft.resolved_plan = None
        draft.question = {"question": outcome.question, "field": outcome.field,
                          "kind": outcome.kind, "choices": outcome.choices}
        offer = _new_contact_offer(plan, outcome)
        if offer:
            draft.question["new_contact"] = offer
            # Lead with the likely answer: someone new, not a typo for a contact
            # — unless the name is one typo from a contact ("Mon" / "Mom"):
            # then that contact is asked about first. Asked, never assumed.
            choices = draft.question["choices"]
            name_of = lambda c: c.get("name") or c["display"].rsplit(" ··", 1)[0]   # "Mom"
            near = spelling.closest(offer["name"], [name_of(c) for c in choices])
            if near:
                draft.question["choices"] = sorted(choices, key=lambda c: name_of(c) != near)
                same = " or ".join(c["display"] for c in choices if name_of(c) == near)
                draft.question["question"] = (
                    f"{offer['name']} isn't in your contacts. Did you mean {same}? "
                    f"Or add {offer['name']} as a new contact.")
            else:
                draft.question["question"] = (
                    f"{offer['name']} isn't in your contacts yet. Do you want to add them?"
                    + (" If you meant someone else, pick them below." if outcome.choices else ""))
        elif outcome.kind == "payee" and outcome.unknown_mention:
            # Money to "this new account": no one to add, and no guess either.
            draft.question["question"] = NO_NAME_QUESTION
        _traces.event(draft.draft_id, "resolve", outcome="question", **draft.question)
        return {"status": "clarify", "draft_id": draft.draft_id, **draft.question}

    resolved = outcome.plan
    draft.question = None
    _traces.event(draft.draft_id, "resolve", outcome="resolved",
                  resolved_plan=resolved.model_dump(mode="json"))

    # --- policy (M5). A BLOCKED draft keeps NO plan: there is nothing to sign.
    policy_ctx = load_context(draft.user_id, db_path=DB_PATH)      # reused by the reply below
    verdicts = evaluate(resolved, policy_ctx)
    draft.policy = {
        "decision": verdicts.decision.value,
        "verdicts": [{"leg_id": v.leg_id, "decision": v.decision.value,
                      "rule": v.rule, "reason": v.reason} for v in verdicts.verdicts],
    }
    _audit.append(AuditEntryType.POLICY, verdicts.to_audit_payload(draft.draft_id))
    _traces.event(draft.draft_id, "policy", **draft.policy)
    if verdicts.blocked:
        draft.status = "blocked"
        draft.resolved_plan = None
        return {"status": "blocked", "draft_id": draft.draft_id,
                "policy": draft.policy, "reasons": verdicts.reasons()}

    # --- validator (M6). A frozen draft keeps its plan for display, but
    #     /api/auth/nonce refuses a nonce, so it is unsignable.
    auditor = RecordingProvider(get_provider(settings))
    # The PARSER's intent plus the user's own answers: the validator decides for
    # itself whether an answered "$50 or $500?" covers the amount paid.
    report = validate(plan, resolved, draft.transcript, provider=auditor, audit=_audit,
                      answers=draft.answers)
    draft.llm_calls = auditor.calls           # the validator's prompts, for CONSOLE_DEBUG
    draft.validation = {"verdict": report.verdict, "frozen": report.frozen,
                        "checks": report.checks, "soft_signals": report.soft_signals,
                        "llm_check": report.llm_check}
    # The draft takes this payload (and becomes signable) only once its hold and
    # phone code are recorded, below: if anything in between fails, it keeps
    # its previous payload, never a new one behind an old, finished hold.
    status = "frozen" if report.frozen else "ready"
    p_hash = payload_hash(resolved)
    _traces.event(draft.draft_id, "validate", verdict=report.verdict, frozen=report.frozen,
                  checks=report.checks, soft_signals=report.soft_signals,
                  llm_check=report.llm_check, llm_calls=auditor.calls)

    # --- step-up. An escalated plan gets a code on the out-of-band channel,
    #     bound to THIS payload hash. The code is never in this response: the
    #     point is that it arrives somewhere the overlay cannot touch, with the
    #     transaction described from the server's copy of the plan.
    # --- scam protection (backend/policy/scam.py): rules over the ledger and the
    #     raw transcript — never the model. HOLD puts a server-enforced hold on
    #     this draft; HOLD_STEP_UP also requires the phone code (below).
    assessment = None
    hold_release = None
    if status == "ready":
        now = int(time.time())
        assessment = _rescore(draft, resolved, now)
        # Never lower than before (a clarification re-runs this): the floor.
        scam_outcome = scam.stricter(draft.scam_floor, assessment.outcome)
        warnings = list(assessment.warnings)
        if scam_outcome != assessment.outcome:
            # The floor, not today's score, sets the safeguards: say so, or
            # the card shows a hold with nothing explaining it.
            warnings.append(_FLOOR_WARNING)
        draft.scam_floor = scam_outcome
        draft.scam = {**assessment.to_dict(), "outcome": scam_outcome,
                      "scored": assessment.outcome, "warnings": warnings,
                      "payload_hash": p_hash}
        _audit.append(AuditEntryType.SCAM_ASSESSMENT,
                      {"stage": "draft", "payload_hash": p_hash, **assessment.to_audit()})
        _traces.event(draft.draft_id, "scam", **draft.scam)
        logging.info("scam assessment %s: %s (facts %s, words %s) %s", draft.draft_id,
                     assessment.outcome, assessment.facts, assessment.words,
                     [f"{x.code}+{x.weight}" for x in assessment.signals])
        asking = (scam.ASK_QUESTIONS and draft.purpose is None and assessment.asks
                  and scam_outcome != scam.BLOCK)
        # Remembered for later attempts' scores (retries, stopped payments).
        attempts.record(draft.draft_id, draft.user_id,
                        [leg for leg in resolved.plan if leg.type == "TRANSFER"],
                        outcome=scam_outcome, asked=asking or draft.purpose is not None, now=now,
                        status=attempts.STOPPED if scam_outcome == scam.BLOCK else attempts.OPEN)
        if scam_outcome == scam.BLOCK:
            # Too many signs to go ahead in the app at all: nothing to sign,
            # and the user is told to call their bank.
            draft.status = "blocked"
            draft.resolved_plan = None
            draft.question = None
            _traces.event(draft.draft_id, "scam", blocked=True, score=assessment.score)
            return {"status": "blocked", "kind": "scam", "draft_id": draft.draft_id,
                    "reasons": warnings, "scam": _public_scam(assessment, None, draft.scam)}
        if asking:
            # Threshold 1 (facts 3-9.9): ask before anything is held or
            # signable — questions picked by the facts that scored highest. The
            # answer's words are weighed at threshold 2 and re-run this
            # pipeline; the floor above means they can only add.
            draft.status = "clarify"
            draft.resolved_plan = None
            draft.question = {"question": " ".join(assessment.questions), "field": "purpose",
                              "kind": "purpose", "choices": [],
                              "questions": list(assessment.questions)}
            _traces.event(draft.draft_id, "scam", asked="purpose", score=assessment.score)
            return {"status": "clarify", "draft_id": draft.draft_id, **draft.question}
        if scam.needs_hold(scam_outcome):
            hold_release = safety.create_hold(draft.draft_id, draft.user_id,
                                              seconds=_hold_seconds(), now=now,
                                              payload_hash=p_hash)

    needs_step_up = (status == "ready"
                     and (verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION
                          or draft.scam_floor == scam.HOLD_STEP_UP))
    if needs_step_up:
        code = _step_up.issue(draft.draft_id, p_hash)
        _traces.event(draft.draft_id, "step_up", sent=True, channel="phone (simulated)",
                      reasons=verdicts.reasons())
        _phone.deliver(draft.user_id,
                       f"DCTA: to {plan_summary(resolved)}, enter code {code}. "
                       f"Valid 5 min. Never share this code. If this wasn't "
                       f"you, ignore this message.")
    draft.resolved_plan = resolved
    draft.status = status

    # --- what the assistant says about it (backend/narrate.py): built from the
    #     same checked data as the card — never LLM text — so the reply and the
    #     card cannot disagree. Only for a draft the user can actually approve.
    #     Cosmetic: a failure here must never turn a valid, signable draft (whose
    #     step-up code may already be on the user's phone) into an error — it
    #     degrades to the plain card.
    narration = None
    if draft.status == "ready":
        try:
            conn = get_conn()
            try:
                accounts = {r["id"]: {"type": r["type"], "balance": r["balance"]}
                            for r in conn.execute("SELECT id, type, balance FROM accounts "
                                                  "WHERE user_id=?", (draft.user_id,))}
            finally:
                conn.close()
            narration = narrate(plan, resolved, draft.transcript, accounts=accounts,
                                history=policy_ctx.history, answers=draft.answers,
                                extra_check=needs_step_up,
                                hold_seconds=(max(0, hold_release - int(time.time()))
                                              if hold_release is not None else None),
                                new_destination_legs=assessment.new_destination_legs)
        except Exception:
            logging.exception("narration failed for draft %s; showing the plain card",
                              draft.draft_id)

    return {
        "status": draft.status,
        "draft_id": draft.draft_id,
        "transcript": draft.transcript,       # the SERVER's copy of what was said
        "narration": narration,
        "scam": _public_scam(assessment, hold_release, draft.scam),
        "resolved_plan": resolved.model_dump(mode="json"),
        "payload_hash": p_hash,
        "policy": draft.policy,
        "validation": draft.validation,
        "requires_extra_confirmation": needs_step_up,
        "confirmation": ({"channel": "your registered phone",
                          "reasons": verdicts.reasons()}
                         if needs_step_up else None),
    }


INJECTION_REFUSAL = ("Your message had instructions aimed at the app itself, so I haven't "
                     "acted on it and nothing was drafted. To make a payment, just say it, "
                     "like \"send $50 to Mom\".")
MODEL_UNREACHABLE = ("The assistant can't be reached right now. Nothing was sent. "
                     "Try again in a moment.")
# Asked, not requested: "how much do I have?", "do I have enough for...?".
# Not "can you send mom 50": that is a request.
_ASKS = re.compile(r"^\s*(?:why|what|how|where|when|which|who|whose)\b"
                   r"|^\s*(?:did|do|does|have|has|is|are|was|were)\s+(?:i|you|we|my|it|they"
                   r"|he|she|there|that|this)\b", re.I)
MANAGE_BILLS = ("Here are your recurring payments. Tap Cancel or Pause on the one you want "
                "to change. Nothing changes until you do.")
NOTHING_HEARD = "I didn't catch anything — what would you like to do?"
TOO_LONG = ("That's too long for me. Please say one or two payments at a time, "
            "like \"send $50 to Mom\".")


@app.post("/api/drafts", response_model=None)
def create_draft(req: DraftRequest):
    """transcript -> a signable draft, a question, a policy refusal or a freeze."""
    # Nothing to read, or far more than a request: answered here, before the
    # model is called (and paid for).
    if not req.transcript or len(req.transcript) > ingest.MAX_CHARS:
        kind = "empty" if not req.transcript else "too_long"
        return {"status": "clarify", "kind": kind, "draft_id": None, "field": kind,
                "transcript": req.transcript[:ingest.MAX_CHARS], "choices": [],
                "question": NOTHING_HEARD if kind == "empty" else TOO_LONG}
    # Wording aimed at the app itself ("ignore previous instructions", "SYSTEM:",
    # "skip verification", an encoded blob): refused before the model reads it.
    # Defence in depth only. A hijacked model still couldn't move money (no
    # payee ids, a signature over the exact draft), but nothing that asks the
    # app to obey it should come back as a card to approve.
    found = [w for w in scam.scan_transcript(req.transcript)
             if w.code == "words_instruction_override"]
    if found:
        tid = "refused-" + DraftStore.new_id()
        _trace_start(tid, req, "refused")
        _traces.event(tid, "firewall", note="refused before the model was called",
                      codes=scam.phrase_codes(found))
        _audit.append(AuditEntryType.INJECTION_REFUSED, {
            "transcript_hash": hash_transcript(req.transcript), "chars": len(req.transcript),
            "codes": scam.phrase_codes(found), "user_id": req.user_id})
        out = {"status": "blocked", "kind": "injection", "draft_id": None,
               "transcript": req.transcript, "reasons": [INJECTION_REFUSAL]}
        _note_stopped(req.user_id, out)
        return out
    conn = get_conn()
    try:
        payees = [dict(r) for r in conn.execute(
            "SELECT * FROM payees WHERE user_id=? AND removed_at IS NULL",
            (req.user_id,)).fetchall()]
        billers = [dict(r) for r in conn.execute("SELECT * FROM billers").fetchall()]
        accounts = [dict(r) for r in conn.execute(
            "SELECT * FROM accounts WHERE user_id=?", (req.user_id,)).fetchall()]
        equities = [dict(r) for r in conn.execute("SELECT * FROM equities").fetchall()]
    finally:
        conn.close()

    context = build_context(payees=payees, billers=billers,
                            accounts=accounts, equities=equities)
    for flag in context.flags:
        logging.warning("injection tripwire: stored field flagged: %s", flag)
    req = _autocorrect(req, billers=billers, equities=equities, payees=payees)

    # Which pipeline. Not a security decision: every route ends at a draft the
    # user must sign, or (the list) a read-only view of their own contacts.
    # An answer to "what's Bob's number?" continues the new contact it belongs to.
    origin = _new_contact_origin(req) if req.new_contact_for else None
    route = "contact_add" if origin else classify_request(req.transcript)
    if route == "bill_ambiguous" and req.recurrence:
        route = "recurring_bill" if req.recurrence == "recurring" else "payment"
    elif req.recurrence == "recurring" and route == "payment":
        route = "recurring_bill"
    if route == "bill_ambiguous":
        # Never assumed either way: a one-time instruction is never ongoing
        # consent, and an ongoing one is never paid as a one-off.
        return {"status": "clarify", "kind": "recurrence", "draft_id": None,
                "field": "recurrence", "transcript": req.transcript,
                "question": "Is this a one-time payment, or do you want to set up a recurring "
                            "payment for this bill?",
                "choices": [{"id": "once", "display": "Just this once"},
                            {"id": "recurring", "display": "Set up a recurring payment"}]}
    if route == "recurring_bill":
        return _recurring_setup_start(req)
    if route == "recurring_manage":
        tid = "bills-" + DraftStore.new_id()
        _trace_start(tid, req, route)
        _traces.event(tid, "bills", note="the Bills list; the LLM is not called")
        return {"status": "info", "kind": "bills", "draft_id": None, "message": MANAGE_BILLS}
    if route == "payment" and (asked := answers.before_model(req.transcript, payees=payees)):
        # Read by a model, "50 USD" becomes S$50 and "-50" becomes $50.
        return _follow_up_reply(req, route, asked)
    if route == "contact_list":
        view = _contacts_view(req.user_id)
        tid = "list-" + DraftStore.new_id()
        _trace_start(tid, req, route)
        _traces.event(tid, "contacts", note="read-only; the LLM is not called",
                      count=len(view["contacts"]))
        return view

    provider = RecordingProvider(get_provider(settings))
    fallback = None
    try:
        if route == "contact_edit":
            plan = parse_contact_edit(req.transcript, provider=provider, context=context)
        elif route == "contact_add":
            plan = parse_contact_add(req.transcript, provider=provider, context=context,
                                     name_hint=origin["name"] if origin else None)
            if origin and not plan.contact.nickname:
                plan.contact.nickname = origin["name"]
        else:
            plan = parse_transcript(req.transcript, provider=provider, context=context)
            # The model dropped everything: a payment to someone who isn't a
            # contact yet still reaches "add them?" (the rules' reading).
            if not plan.plan and (rules := unknown_payee_fallback(req.transcript, context)):
                plan, fallback = rules, "rules: a payee who isn't a contact yet"
    except (ProviderUnavailable, ParseFailure) as exc:
        tid = "failed-" + DraftStore.new_id()
        _trace_start(tid, req, route)
        _traces.event(tid, "parse", provider=provider.name, llm_calls=provider.calls,
                      error=str(exc))
        if isinstance(exc, ParseFailure):
            # The model never produced a valid plan (often: no amount, which
            # the schema requires). A question ("did I pay mom?") is answered
            # as one; otherwise ask, in words the user can act on. The
            # attempts stay on the trace for /data.
            if route == "payment" and _is_question(req.transcript):
                out, _ = _answer_question(req, tid, payees=payees)
                return out
            question = (answers.follow_up(req.transcript, payees=payees, billers=billers,
                                          equities=equities)
                        if route == "payment" else None)
            return {"status": "clarify", "kind": "empty", "draft_id": None,
                    "field": "__empty__", "transcript": req.transcript, "choices": [],
                    "question": question or answers.COULD_NOT_READ}
        raise HTTPException(status_code=502, detail={
            "error": MODEL_UNREACHABLE, "provider": provider.name,
            "attempts": exc.errors})

    draft = _drafts.put(Draft(
        draft_id=DraftStore.new_id(), user_id=req.user_id,
        # A continued new contact binds EVERYTHING the user said for it: the
        # payment that named them, then the number.
        transcript=(origin["transcript"] + "\n" + req.transcript) if origin else req.transcript,
        intent_plan=plan.model_dump(),
        created_at=time.time(),
        kind=route if route in ("contact_edit", "contact_add") else "payment",
        origin_draft_id=req.new_contact_for if origin else None,
        risk={"for_payment": origin["for_payment"], "pending_cents": origin["pending_cents"]}
             if origin else None,
    ))
    _trace_start(draft.draft_id, req, route)
    _traces.event(draft.draft_id, "parse", provider=provider.name, llm_calls=provider.calls,
                  context=context.to_prompt_json(), result=plan.model_dump(mode="json"),
                  **({"fallback": fallback} if fallback else {}))

    # AuditEntryType.TRANSCRIPT exists and was reserved for M7 ("every step" —
    # brief 4.5 / docs/ARCHITECTURE.md), but nothing emitted it: the chain went
    # DRAFT -> POLICY -> VALIDATION -> SIGNATURE -> EXECUTION with no record of
    # the utterance any of it came from. The signed ResolvedPlan binds
    # transcript_hash, so without this entry the hash in the payload had nothing
    # in the log to correspond to.
    #
    # The HASH is logged, not the words. The hash is what the signature binds,
    # so it is what non-repudiation needs; storing the raw utterance would put
    # spoken account details and whatever else a microphone caught into
    # append-only storage that is deliberately hard to redact. `chars` keeps a
    # truncation or an empty transcript visible without retaining the content.
    _audit.append(AuditEntryType.TRANSCRIPT, {
        "draft_id": draft.draft_id,
        "transcript_hash": hash_transcript(req.transcript),
        "chars": len(req.transcript),
        "parser_provider": provider.name,
        "user_id": req.user_id,
        "kind": draft.kind,
    })
    out = _run(draft)
    _note_stopped(req.user_id, out)
    # No payment in it ("how much do I have?"): answer the question instead of
    # asking for a payment. A payment never reaches this — not even one the
    # parser failed to read ("send 50 to mom" still gets "I didn't catch a
    # payment") — so a payment makes no extra model call.
    question_calls: list = []
    follow = None
    if route == "payment" and out.get("status") == "clarify" and out.get("kind") == "empty":
        # About money but not yet a payment ("send mom some money", "send 50"):
        # the question that would make it one. Questions ABOUT payments
        # ("did I send 50 to mom?") still go to the question lane.
        if not _is_question(req.transcript):
            follow = answers.follow_up(req.transcript, payees=payees, billers=billers,
                                       equities=equities)
        if follow:
            draft.question = {**(draft.question or {}), "question": follow}
            out = {**out, "question": follow}
        elif not looks_like_payment(req.transcript):
            out, question_calls = _answer_question(req, draft.draft_id, payees=payees)
    # Scam-language warning even when there is no draft to review yet ("who
    # is the safe account?"): the words alone deserve it. Advisory only.
    # A refused new contact already carries its own warning: no second one.
    if out.get("status") != "ready" and not (draft.kind == "contact_add"
                                             and out.get("status") == "blocked"):
        found = scam.scan_transcript(req.transcript)
        if scam.strong_codes(found):
            out["scam_language"] = {"codes": scam.phrase_codes(found),
                                    "warning": scam.warning_for(found)}
    return _with_debug(out, draft,
                       provider.calls + question_calls + getattr(draft, "llm_calls", []))


def _follow_up_reply(req: DraftRequest, route: str, question: str) -> dict:
    """A question asked before any draft exists (no model call), on the trace."""
    tid = "asked-" + DraftStore.new_id()
    _trace_start(tid, req, route)
    _traces.event(tid, "follow_up", note="asked by the rules; the model was not called",
                  question=question)
    return {"status": "clarify", "kind": "empty", "draft_id": None, "field": "__empty__",
            "transcript": req.transcript, "choices": [], "question": question}


def _is_question(transcript: str) -> bool:
    """Asked ABOUT money, not asking to move it: "how much do I have?", "did I
    pay mom?". "Send mom the usual" names a past payment but is a request."""
    return bool(_ASKS.search(transcript)) or (
        asks_only_about_past_payments(transcript) and not answers.from_history(transcript))


def _answer_question(req: DraftRequest, trace_id: str, *,
                     payees: list[dict] | None = None) -> tuple[dict, list]:
    """Which question a request with no payment is asking. The model picks ONE
    label (backend/agent/question.py) from the user's words alone; the answer
    is fixed sentences from the ledger (backend/answers.py), or the contacts
    list itself. No model text is shown. Recorded on the trace for /data."""
    classifier = RecordingProvider(get_provider(settings))
    label = classify_question(req.transcript, provider=classifier)
    if label == "contacts":
        out = _contacts_view(req.user_id)
        said = f"the contacts list ({len(out['contacts'])} contacts)"
    else:
        # "did I pay mom?": only Mom's payments, if the question names one contact
        out = answers.reply(label, req.user_id, stopped=_stopped.get(req.user_id),
                            payee=answers.named_payee(req.transcript, payees or []))
        said = out["message"]
    _traces.event(trace_id, "question", provider=classifier.name,
                  llm_calls=classifier.calls, label=label, reply=said)
    return out, classifier.calls


# The reason sentences of each user's last stopped request (blocked, frozen, or
# a refused contact), for "why did you stop that?". Rule text the user was
# already shown — never the model's words. In memory: drafts themselves are
# swept after a few minutes, and the audit log keeps the scam checks as codes.
_stopped: dict[str, list[str]] = {}


def _note_stopped(user_id: str, out: dict) -> None:
    status = out.get("status")
    if status == "blocked" and out.get("kind") == "contact_add":
        # The rules' warnings; the model's advisory read ("ai") is left out.
        reasons = [w.get("text") for w in (out.get("risk") or {}).get("warnings") or []
                   if w.get("weight") != "ai"]
    elif status == "blocked":
        reasons = list(out.get("reasons") or [])
    elif status == "frozen":
        reasons = [c.get("say") for c in (out.get("validation") or {}).get("checks") or []
                   if c.get("outcome") == "fail"]
    else:
        return
    reasons = [r for r in reasons if isinstance(r, str) and r.strip()]
    if reasons:
        _stopped[user_id] = reasons


# The page adds "Nothing was sent." to a refused signing challenge itself.
_STALE_DESTINATION = {
    "SUPERSEDED": "the payee's payment details changed after this was drafted — ask again",
    "REMOVED": "the payee was removed from your contacts after this was drafted",
    "DESTINATION": "this transfer is not bound to a destination",
    "REPORTED": "the payee's number has been reported for scams",
}

_FLOOR_WARNING = ("This payment looked riskier earlier in this request, so the extra "
                  "checks you were shown still apply.")


_SIGN_MARGIN_S = 60        # a hold ends at least this long before its payload expires


def _hold_seconds() -> int:
    """SCAM_HOLD_SECONDS, capped so the hold ends with time left to sign: the
    payload's signed expires_at and the phone code both last MAX_AUTH_WINDOW_S
    (5 min) from when the payload was resolved (the draft lives as long as its
    payload), but the hold only starts after the validator, which may take up
    to LLM_TIMEOUT_S. A hold is never shortened to fit: a payload that runs out
    first just expires (ask again). A longer hold needs longer-lived payloads
    first."""
    return max(0, min(settings.scam_hold_seconds,
                      int(MAX_AUTH_WINDOW_S - _SIGN_MARGIN_S - settings.llm_timeout_s)))


def _rescore(draft: Draft, plan: ResolvedPlan, now: int):
    return scam.reassess(plan, draft.user_id, db_path=DB_PATH, now=now,
                         transcript=draft.scam_text,
                         recent_change_hours=settings.recent_change_hours,
                         cooling_hours=settings.credential_cooling_hours,
                         draft_id=draft.draft_id, unanswered=draft.unanswered)


def _public_scam(assessment, hold_release: int | None, stored: dict | None) -> dict | None:
    """What the page needs from a scam assessment: the outcome (never below
    what this draft was shown before), the fixed warnings and the hold's time
    left."""
    if assessment is None:
        return None
    out = {"outcome": stored["outcome"], "score": assessment.score,
           "signals": [{"code": s.code, "weight": s.weight, "detail": s.detail}
                       for s in assessment.signals],
           "warnings": stored["warnings"],
           "hold": None,
           "facts": assessment.facts, "words": assessment.words,
           "decision": assessment.decision,
           "release_delay_seconds": scam.release_delay(stored["outcome"])}
    if hold_release is not None:
        out["hold"] = {"release_at": hold_release,
                       "seconds_left": max(0, hold_release - int(time.time()))}
    return out


def _with_debug(out: dict, draft: Draft, llm_calls: list) -> dict:
    """CONSOLE_DEBUG: the scam score and every prompt sent to the model, for the
    page to print to the browser console. The /data page shows the same."""
    if not settings.console_debug:
        return out
    assessed = getattr(draft, "scam", None)
    if assessed:
        assessed = {**assessed, "thresholds": {
                        "facts_ask": assessed.get("ask_from", scam.FACTS_ASK_FROM),
                        "facts_ask_lines": {"doubt": scam.FACTS_ASK_DOUBT_FROM,
                                            "usual": scam.FACTS_ASK_FROM,
                                            "small": scam.FACTS_ASK_SMALL_FROM},
                        "facts_fail": scam.FACTS_FAIL_FROM,
                        "facts_call_bank": scam.FACTS_CALL_BANK_FROM,
                        "words_fail": scam.WORDS_FAIL_FROM, "words_serious": scam.WORDS_SERIOUS_FROM,
                        "words_call_bank": scam.WORDS_CALL_BANK_FROM},
                    "breakdown": scam.breakdown(
            assessed["signals"], recent_change_hours=settings.recent_change_hours,
            cooling_hours=settings.credential_cooling_hours)}
    out["debug"] = {"scam": assessed,
                    "scam_language": scam.phrase_codes(scam.scan_transcript(draft.transcript)),
                    "words": scam.word_score(draft.scam_text),
                    "llm_calls": llm_calls}
    return out


def _run(draft: Draft) -> dict:
    if draft.kind == "contact_add":
        return _contact_add_pipeline(draft)
    return _contact_pipeline(draft) if draft.kind == "contact_edit" else _pipeline(draft)


# --------------------------------------------------------------------------- adding a contact
NO_NAME_QUESTION = ("I can only send money to people saved in your contacts. "
                    "Who is it for?")


def _new_contact_offer(plan: IntentPlan, q: Clarify) -> dict | None:
    """A payment named someone who is not a contact: offer to add them, next to
    the existing contacts. Transfers only — a bill or a share has no "new
    contact" to add."""
    if q.kind != "payee" or not q.unknown_mention:
        return None
    leg = next((l for l in plan.plan if q.field == f"{l.id}.target"), None)
    if leg is None or leg.type != "TRANSFER":
        return None
    name = contact_name(q.unknown_mention)
    if name is None:                      # "this new account" names no one
        return None
    return {"name": name, "awaiting": "phone"}


def _new_contact_origin(req: DraftRequest) -> dict:
    """The draft a "what's their number?" answer continues, read from OUR copy:
    the name, whether a payment is waiting, and how much. 404/409 rather than a
    guess if it is gone or was not asking."""
    d = _drafts.get(req.new_contact_for)
    if d is None or d.user_id != req.user_id:
        raise HTTPException(404, {"error": "that question has expired — please say it again"})
    offer = (d.question or {}).get("new_contact")
    if d.status != "clarify" or not offer:
        raise HTTPException(409, {"error": "that draft isn't waiting for a new contact's number"})
    if d.kind == "payment":
        field = (d.question or {}).get("field", "")
        leg = next((l for l in IntentPlan.model_validate(d.intent_plan).plan
                    if field == f"{l.id}.target"), None)
        amount = getattr(getattr(leg, "amount", None), "literal_cents", None)
        return {"name": offer["name"], "transcript": d.transcript,
                "for_payment": True, "pending_cents": amount}
    ctx = d.risk or {}
    return {"name": offer["name"], "transcript": d.transcript,
            "for_payment": bool(ctx.get("for_payment")), "pending_cents": ctx.get("pending_cents")}


def _contact_add_pipeline(draft: Draft) -> dict:
    """resolve -> risk (rules + the LLM's advisory read) -> refuse, or a
    signable draft with the safeguards the risk calls for -> validate ->
    (phone code). Re-run in full on every pass, like the other pipelines."""
    plan = ContactAddPlan.model_validate(draft.intent_plan)
    outcome = resolve_contact_add(plan, user_id=draft.user_id)
    ctx = draft.risk or {}
    if isinstance(outcome, Clarify):
        draft.status = "clarify"
        draft.resolved_add = None
        draft.question = {"question": outcome.question, "field": outcome.field,
                          "kind": outcome.kind, "choices": []}
        if outcome.kind in ("need_phone", "invalid_phone") and outcome.unknown_mention:
            draft.question["new_contact"] = {"name": outcome.unknown_mention, "awaiting": "phone"}
        draft.risk = {"for_payment": ctx.get("for_payment", False),
                      "pending_cents": ctx.get("pending_cents")}
        _traces.event(draft.draft_id, "resolve", outcome="question", **draft.question)
        return {"status": "clarify", "kind": "contact_add", "draft_id": draft.draft_id,
                **draft.question}
    new: NewContact = outcome

    conn = get_conn()
    try:
        # Removed contacts too, in both: "remove Mom, then add Mom on a new
        # number" is still a name clash, and removing doesn't undo an addition.
        existing = [dict(r) for r in conn.execute(
            "SELECT nickname, phone FROM payees WHERE user_id=?", (draft.user_id,))]
        recent = conn.execute(
            "SELECT COUNT(*) FROM payees WHERE user_id=? AND added_at > ?",
            (draft.user_id, int(time.time()) - 86400)).fetchone()[0]
    finally:
        conn.close()
    facts = NewContactFacts(nickname=new.nickname, phone=new.phone, existing=existing,
                            added_last_24h=recent, conversation=draft.transcript,
                            pending_cents=ctx.get("pending_cents"),
                            for_payment=bool(ctx.get("for_payment")))

    # The LLM's read of the conversation — advisory. It sees the user's words
    # and a few facts, never the number, an account or a balance.
    provider = RecordingProvider(get_provider(settings))
    llm_facts = {
        "new_contact_name": new.nickname,
        "number_is_overseas": not new.phone.startswith("+65 "),
        "same_name_as_an_existing_contact_with_a_different_number": any(
            c["nickname"].lower() == new.nickname.lower() for c in existing),
        "contacts_added_in_the_last_24_hours": recent,
        "payment_waiting_for_this_contact": (
            "$" + cents_to_display(facts.pending_cents) if facts.pending_cents
            else ("yes (amount not stated)" if facts.for_payment else None)),
    }
    try:
        assessment = assess_scam_risk(draft.transcript, facts=llm_facts, provider=provider)
        ai_risk, ai_signals, ai_error = assessment.risk, list(assessment.signals), None
    except (ProviderUnavailable, ParseFailure) as exc:
        assessment, ai_risk, ai_signals, ai_error = None, None, [], str(exc)
    decision = decide_new_contact(facts, ai_risk=ai_risk, ai_signals=ai_signals,
                                  hold_minutes=settings.new_contact_hold_minutes)
    warnings = [{"code": w.code, "text": w.text, "weight": w.weight} for w in decision.warnings]
    draft.risk = {"for_payment": facts.for_payment, "pending_cents": facts.pending_cents,
                  "rung": decision.rung, "ai_risk": decision.ai_risk, "warnings": warnings}
    _audit.append(AuditEntryType.POLICY, decision.to_audit_payload(draft.draft_id))
    _traces.event(draft.draft_id, "scam_check", provider=provider.name,
                  llm_calls=provider.calls, facts=llm_facts,
                  assessment=assessment.model_dump() if assessment else None,
                  error=ai_error, rung=decision.rung, warnings=[w["code"] for w in warnings])
    risk_view = {"rung": decision.rung, "ai_risk": decision.ai_risk, "warnings": warnings,
                 "for_payment": facts.for_payment}

    if decision.refused:
        draft.status = "blocked"
        draft.resolved_add = None
        return {"status": "blocked", "kind": "contact_add", "draft_id": draft.draft_id,
                "contact": {"display": new.display}, "risk": risk_view}

    now = int(time.time())
    add = ResolvedContactAdd(
        draft_id=draft.draft_id, user_id=draft.user_id, nickname=new.nickname,
        phone=new.phone, payee_display=new.display, safeguards=list(decision.safeguards),
        hold_minutes=decision.hold_minutes, warnings=[w["code"] for w in warnings],
        transcript_hash=hash_transcript(draft.transcript),
        created_at=now, expires_at=now + MAX_AUTH_WINDOW_S)
    report = validate_contact_add(add, draft.transcript, audit=_audit)
    draft.validation = {"verdict": report.verdict, "frozen": report.frozen,
                        "checks": report.checks}
    draft.resolved_add = add
    draft.question = None
    draft.status = "frozen" if report.frozen else "ready"
    p_hash = payload_hash(add)
    _traces.event(draft.draft_id, "validate", verdict=report.verdict, frozen=report.frozen,
                  checks=report.checks, llm_check=report.llm_check, llm_calls=[])

    needs_code = draft.status == "ready" and "PHONE_CODE" in add.safeguards
    reasons = [w["text"] for w in warnings if w["weight"] != "ai"] or [
        "A code on your phone makes sure it's really you adding this contact."]
    if needs_code:
        code = _step_up.issue(draft.draft_id, p_hash)
        _traces.event(draft.draft_id, "step_up", sent=True, channel="phone (simulated)",
                      reasons=reasons)
        _phone.deliver(draft.user_id,
                       f"DCTA: to {add_summary(add)}, enter code {code}. Valid 5 min. "
                       f"Never share this code. If someone asked you to add this "
                       f"contact, stop and call 1799 (ScamShield).")
    return {
        "status": draft.status,
        "kind": "contact_add",
        "draft_id": draft.draft_id,
        "contact_add": add.model_dump(mode="json"),
        "payload_hash": p_hash,
        "validation": draft.validation,
        "risk": risk_view,
        "requires_extra_confirmation": needs_code,
        "confirmation": ({"channel": "your registered phone", "reasons": []}
                         if needs_code else None),
    }


def _contacts_view(user_id: str) -> dict:
    """The user's own contacts, read-only. Never the legal name (it stays
    server-side, like everywhere else) and never an id."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT nickname, last4, phone, hold_until FROM payees WHERE user_id=? "
            "AND removed_at IS NULL ORDER BY nickname, last4", (user_id,)).fetchall()
    finally:
        conn.close()
    return {"status": "info", "kind": "contacts", "contacts": [
        {"display": f"{r['nickname']} ··{r['last4']}", "nickname": r["nickname"],
         "last4": r["last4"], "phone": r["phone"] or "",
         "hold_until": r["hold_until"] if (r["hold_until"] or 0) > time.time() else None}
        for r in rows]}


_REPORTED_CHANGE = ("That number has been reported for scams, so it can't be saved. If "
                    "someone asked you to change this contact's number, stop and call the "
                    "ScamShield Helpline (1799).")


def _contact_pipeline(draft: Draft) -> dict:
    """resolve -> validate -> (step-up) over a contact-edit draft. Same shape
    as _pipeline: re-run in full after every clarification answer."""
    plan = ContactEditPlan.model_validate(draft.intent_plan)
    outcome = resolve_contact_edit(plan, transcript=draft.transcript, user_id=draft.user_id,
                                   draft_id=draft.draft_id, answers=draft.answers)
    if isinstance(outcome, Clarify):
        draft.status = "clarify"
        draft.resolved_change = None
        draft.question = {"question": outcome.question, "field": outcome.field,
                          "kind": outcome.kind, "choices": outcome.choices}
        _traces.event(draft.draft_id, "resolve", outcome="question", **draft.question)
        # `kind` here is the QUESTION's kind (payee / invalid_phone / ...), as
        # for payment questions.
        return {"status": "clarify", "draft_id": draft.draft_id, **draft.question}

    change = outcome.change
    draft.question = None
    _traces.event(draft.draft_id, "resolve", outcome="resolved",
                  contact_change=change.model_dump(mode="json"))
    # A number on the scam list is never saved (the gateway re-checks): like a
    # BLOCKED payment, the draft keeps nothing to sign.
    stop = contact_change_refusal(change)
    if stop:
        draft.status = "blocked"
        draft.resolved_change = None
        # The shape a refused contact_add is logged in (ContactDecision).
        _audit.append(AuditEntryType.POLICY, {"draft_id": draft.draft_id, "kind": "contact_edit",
                                              "rung": "REFUSE", "warnings": ["reported_number"]})
        _traces.event(draft.draft_id, "policy", decision="BLOCK", rule="reported_number")
        return {"status": "blocked", "kind": "contact_edit", "draft_id": draft.draft_id,
                "reasons": [_REPORTED_CHANGE]}
    report = validate_contact_change(plan, change, draft.transcript,
                                     answers=draft.answers, audit=_audit)
    draft.validation = {"verdict": report.verdict, "frozen": report.frozen,
                        "checks": report.checks}
    draft.resolved_change = change
    draft.status = "frozen" if report.frozen else "ready"
    p_hash = payload_hash(change)
    _traces.event(draft.draft_id, "validate", verdict=report.verdict, frozen=report.frozen,
                  checks=report.checks, llm_check=report.llm_check, llm_calls=[])

    reasons = contact_change_step_up(change)
    needs_step_up = draft.status == "ready" and bool(reasons)
    if needs_step_up:
        code = _step_up.issue(draft.draft_id, p_hash)
        _traces.event(draft.draft_id, "step_up", sent=True, channel="phone (simulated)",
                      reasons=reasons)
        _phone.deliver(draft.user_id,
                       f"DCTA: to {change_summary(change)}, enter code {code}. "
                       f"Valid 5 min. Never share this code. If this wasn't "
                       f"you, ignore this message.")
    return {
        "status": draft.status,
        "kind": "contact_edit",
        "draft_id": draft.draft_id,
        "contact_change": change.model_dump(mode="json"),
        "payload_hash": p_hash,
        "validation": draft.validation,
        "requires_extra_confirmation": needs_step_up,
        "confirmation": ({"channel": "your registered phone", "reasons": reasons}
                         if needs_step_up else None),
    }


@app.post("/api/drafts/{draft_id}/clarify", response_model=None)
def answer_clarification(draft_id: str, answer: ClarifyAnswer):
    """Answer one question by candidate id. The server re-resolves against its
    OWN stored IntentPlan, and the resolver still refuses an id the mention does
    not justify — so an answer can narrow a choice, never widen it."""
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    # A final draft stays final: answering a question would otherwise re-run
    # the pipeline and flip a declined or executed draft back to `ready`.
    if draft.status in FINAL_STATUSES:
        raise HTTPException(409, {"error": f"draft is {draft.status}", "draft_id": draft_id,
                                  "status": draft.status})
    draft.answers[answer.field] = answer.choice_id
    _traces.event(draft_id, "answer", field=answer.field, choice_id=answer.choice_id)
    out = _run(draft)
    _note_stopped(draft.user_id, out)
    return _with_debug(out, draft, getattr(draft, "llm_calls", []))


@app.get("/api/drafts/{draft_id}/release", response_model=None)
def release_status(draft_id: str):
    """Where a scheduled (large) payment is: PENDING with seconds left, SENT
    with what ran, or CANCELLED. Runs anything due first, so the page sees
    the money move on time even between release-loop ticks."""
    _gateway.release_due()
    row = safety.get_release(draft_id)
    if row is None:
        raise HTTPException(404, {"error": "no scheduled payment for this draft",
                                  "draft_id": draft_id})
    out = {"draft_id": draft_id, "status": row["status"],
           "seconds_left": max(0, int(row["release_at"]) - int(time.time()))}
    prior = _executor.prior_execution(draft_id)
    if row["status"] == "SENT" and prior is not None:
        out["execution"] = prior["result"]
    return out


def _release_loop(stop: threading.Event) -> None:
    """Send scheduled (large) payments when their wait is over, and run any
    recurring bill that has fallen due (every RECURRING_TICK_S)."""
    last_recurring = 0.0
    while not stop.wait(2):
        try:
            _gateway.release_due()
        except Exception:
            logging.exception("release loop failed; retrying")
        if time.time() - last_recurring >= RECURRING_TICK_S:
            last_recurring = time.time()
            try:
                _recurring_tick()
            except Exception:
                logging.exception("recurring run failed; nothing was paid by the failed run")


class PurposeAnswer(BaseModel):
    """The user's own words for what a risky payment is for."""
    answer: str = Field(min_length=1, max_length=300)

    _clean = field_validator("answer", mode="before")(
        lambda v: ingest.clean(v) if isinstance(v, str) else v)


@app.post("/api/drafts/{draft_id}/purpose", response_model=None)
def answer_purpose(draft_id: str, body: PurposeAnswer):
    """Answer "what is this payment for?". The answer is scored by the scam rules
    (never the model) and the pipeline runs again: it can only add friction."""
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    if draft.status in FINAL_STATUSES:
        raise HTTPException(409, {"error": f"draft is {draft.status}", "draft_id": draft_id,
                                  "status": draft.status})
    if (draft.question or {}).get("kind") != "purpose" or not body.answer.strip():
        raise HTTPException(409, {"error": "this draft isn't waiting for what the payment "
                                           "is for", "draft_id": draft_id})
    # Typos fixed so the scam words in it are seen ("urgnet"); no names here.
    reply, changes = spelling.correct(body.answer.strip())
    draft.replies.append(reply)
    _traces.event(draft_id, "answer", field="purpose", answer=reply,
                  **({"autocorrect": [{"typed": a, "read_as": b} for a, b in changes]}
                     if changes else {}))
    # A reply that doesn't answer ("no", "ok") is asked again, never taken as
    # a calm answer; out of tries, the missing answer is scored as risk. One
    # with scam wording in it is scored now: it has said enough.
    missing = scam.unanswered(draft.question["questions"], reply)
    out_of_tries = len(draft.replies) >= scam.ANSWER_TRIES
    if missing and not out_of_tries and not scam.word_score(reply)["points"]:
        draft.question = {**draft.question, "question": " ".join(missing),
                          "questions": list(missing), "note": scam.REASK_NOTE}
        _traces.event(draft_id, "scam", asked_again=list(missing), tries=len(draft.replies))
        return {"status": "clarify", "draft_id": draft_id, **draft.question}
    draft.purpose = "\n".join(draft.replies)
    draft.unanswered = bool(missing) and out_of_tries
    out = _run(draft)
    _note_stopped(draft.user_id, out)
    return _with_debug(out, draft, getattr(draft, "llm_calls", []))


# --------------------------------------------------------------------------- decline / cancel
# Saying no, on the server. Before this the only way to refuse a draft was to
# leave it alone, and it stayed signable for its whole window. Both are FINAL,
# audited, and recorded in the same durable table as executions — so a decline
# racing a signature is settled by whichever reaches the ledger first, and the
# user is never told "nothing was sent" about money that was.
#   decline — the user says no to the card before confirming (the page's Cancel)
#   cancel  — the user withdraws a draft that has not run (the hold window)
FINAL_STATUSES = frozenset({"executed", "declined", "cancelled"})


def _close_draft(draft_id: str, outcome: str, entry: AuditEntryType, *,
                 by: str | None = None) -> dict:
    prior = _executor.prior_execution(draft_id)
    if prior is not None and prior["outcome"] in CLOSED_OUTCOMES:
        # Already closed (a double tap): say so, change nothing.
        return {"draft_id": draft_id, "status": prior["outcome"].lower(), "sent": False}
    if prior is not None:
        raise HTTPException(409, {
            "error": "already sent — it can no longer be cancelled", "draft_id": draft_id,
            "already_executed": True, "execution": prior["result"],
            "executed_at": prior["executed_at"]})
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (it expired or was never created)",
                                  "draft_id": draft_id})
    p_hash = payload_hash(draft.payload) if draft.payload is not None else ""
    try:
        _executor.close(draft_id, draft.kind, p_hash, outcome)
    except AlreadyExecuted as exc:          # a signature reached the ledger first
        raise HTTPException(409, {
            "error": "already sent — it can no longer be cancelled", "draft_id": draft_id,
            "already_executed": True, "execution": exc.prior["result"],
            "executed_at": exc.prior["executed_at"]})
    was = draft.status
    draft.status = outcome.lower()
    label = {"by": by} if by else {}
    _audit.append(entry, {"draft_id": draft_id, "payload_hash": p_hash, "prior_status": was,
                          **label})
    if safety.cancel_hold(draft_id):                 # a held payment, stopped in its hold
        _audit.append(AuditEntryType.HOLD_CANCELLED, {"draft_id": draft_id,
                                                      "payload_hash": p_hash, **label})
    # A large payment waiting to run: the executions row above already stops
    # it; this keeps the release loop from picking it up at all.
    safety.set_release_status(draft_id, ("PENDING",), "CANCELLED")
    if draft.kind == "payment":
        attempts.mark(draft_id, attempts.STOPPED, now=int(time.time()))
    _traces.event(draft_id, outcome.lower(), prior_status=was)
    return {"draft_id": draft_id, "status": outcome.lower(), "sent": False}


@app.post("/api/drafts/{draft_id}/decline", response_model=None)
def decline_draft(draft_id: str):
    """The user says no to this draft before confirming. Nothing is sent, ever."""
    return _close_draft(draft_id, "DECLINED", AuditEntryType.DRAFT_DECLINED)


@app.post("/api/drafts/{draft_id}/cancel", response_model=None)
def cancel_draft(draft_id: str):
    """The user withdraws a draft that has not run. Nothing is sent, ever."""
    return _close_draft(draft_id, "CANCELLED", AuditEntryType.DRAFT_CANCELLED)


# --------------------------------------------------------------------------- kill switch
# One tap freezes every outgoing payment: no signature, because making things
# safer should be easy. Unfreezing needs a code sent to the phone, so a
# scammer steering the page cannot simply undo it.
class KillSwitchRequest(BaseModel):
    user_id: str = DEMO_USER_ID


class KillSwitchRelease(BaseModel):
    user_id: str = DEMO_USER_ID
    code: str


def _kill_switch_id(user_id: str) -> str:
    return f"killswitch:{user_id}"


@app.get("/api/killswitch", response_model=None)
def kill_switch_state(user_id: str = Query(DEMO_USER_ID)):
    engaged = safety.kill_switch_engaged(user_id)
    return {"user_id": user_id, "engaged": engaged is not None, "engaged_at": engaged}


def _cancel_open_drafts(user_id: str, by: str) -> tuple[list[str], list[str], list[str]]:
    """Cancel every draft of this user that could still be signed, and every
    pending hold. Returns (cancelled, already_sent, failed): a payment that
    executed while this ran is reported, never silently skipped, and so is a
    draft that couldn't be cancelled (e.g. the ledger was locked) — one draft
    failing doesn't stop the others, or turn the whole request into a 500."""
    cancelled, sent, failed = [], [], []
    for draft_id in _drafts.open_ids(user_id):
        try:
            _close_draft(draft_id, "CANCELLED", AuditEntryType.DRAFT_CANCELLED, by=by)
            cancelled.append(draft_id)
        except HTTPException as exc:
            if isinstance(exc.detail, dict) and exc.detail.get("already_executed"):
                sent.append(draft_id)
        except Exception:
            logging.exception("could not cancel draft %s (%s)", draft_id, by)
            failed.append(draft_id)
    # Holds whose drafts have already expired from memory.
    for draft_id in safety.cancel_user_holds(user_id):
        _audit.append(AuditEntryType.HOLD_CANCELLED, {"draft_id": draft_id, "by": by})
    return cancelled, sent, failed


_kill_switch_lock = threading.Lock()     # in-memory stores are shared across request threads


@app.post("/api/killswitch", response_model=None)
def engage_kill_switch(req: KillSwitchRequest = KillSwitchRequest()):
    """Freeze. Everything in flight stops too: every draft that could still be
    signed is cancelled (its hold with it), and every signing challenge issued
    to this user is revoked — so unfreezing later cannot revive an old card.

    The freeze is on from its first line. A draft that then can't be cancelled
    is reported (cancel_failed), not a 500: the frozen gateway refuses it
    anyway, and the page mustn't say "couldn't freeze" about a freeze that
    happened."""
    with _kill_switch_lock:
        newly = safety.engage_kill_switch(req.user_id, now=int(time.time()))
        revoked = _nonce_store.revoke(lambda draft_id: (
            (d := _drafts.get(draft_id)) is not None and d.user_id == req.user_id))
        cancelled, sent, failed = _cancel_open_drafts(req.user_id, by="kill switch")
    _audit.append(AuditEntryType.KILL_SWITCH_ENGAGED, {
        "user_id": req.user_id, "newly": newly, "drafts_cancelled": cancelled,
        "already_sent": sent, "cancel_failed": failed, "nonces_revoked": revoked})
    return {"engaged": True, "newly": newly, "drafts_cancelled": len(cancelled),
            "already_sent": len(sent), "cancel_failed": len(failed),
            "nonces_revoked": revoked}


# Unfreeze codes: at most this many per user per hour. Each code allows three
# guesses, so someone steering the page gets 9 guesses an hour at a 6-digit
# code, not an unlimited stream of fresh codes. A successful unfreeze clears
# the count. (The demo has no login, so anyone who can reach the server can
# also press Freeze for any user — a real deployment authenticates these.)
UNFREEZE_CODES_PER_HOUR = 3
_unfreeze_requests: dict[str, list[float]] = {}


@app.post("/api/killswitch/release/begin", response_model=None)
def begin_kill_switch_release(req: KillSwitchRequest = KillSwitchRequest()):
    if safety.kill_switch_engaged(req.user_id) is None:
        return {"engaged": False}
    now = time.time()
    with _kill_switch_lock:
        recent = [t for t in _unfreeze_requests.get(req.user_id, []) if now - t < 3600]
        if len(recent) >= UNFREEZE_CODES_PER_HOUR:
            wait = int(3600 - (now - recent[0])) + 1
            raise HTTPException(429, {"error": "too many unfreeze codes — try again later",
                                      "retry_after_seconds": wait})
        _unfreeze_requests[req.user_id] = recent + [now]
    code = _step_up.issue(_kill_switch_id(req.user_id), "release")
    _phone.deliver(req.user_id, f"DCTA: to unfreeze your payments, enter code {code}. "
                                f"Valid 5 min. If you didn't ask for this, ignore it — "
                                f"your payments stay frozen.")
    return {"engaged": True, "code_sent": True, "channel": "your registered phone"}


@app.post("/api/killswitch/release", response_model=None)
def release_kill_switch(req: KillSwitchRelease):
    try:
        _step_up.confirm(_kill_switch_id(req.user_id), req.code)
    except StepUpError as exc:
        raise HTTPException(400, {"error": str(exc), "attempts_left": exc.attempts_left})
    _step_up.consume(_kill_switch_id(req.user_id))
    with _kill_switch_lock:
        _unfreeze_requests.pop(req.user_id, None)
        # Unfreezing starts clean: anything drafted WHILE frozen is cancelled
        # too — its hold ran out during the freeze, so it would otherwise be
        # signable at once, with no cooling-off.
        cancelled, sent, failed = _cancel_open_drafts(req.user_id, by="unfreeze")
        if failed:
            # One of them is still signable, with no cooling-off: stay frozen.
            raise HTTPException(503, {
                "error": "couldn't cancel what was asked for while frozen, so your "
                         "payments are still frozen — try again", "engaged": True})
        if safety.release_kill_switch(req.user_id, now=int(time.time())):
            _audit.append(AuditEntryType.KILL_SWITCH_RELEASED, {
                "user_id": req.user_id, "drafts_cancelled": cancelled})
    return {"engaged": False, "drafts_cancelled": len(cancelled)}


class ConfirmRequest(BaseModel):
    code: str


@app.post("/api/drafts/{draft_id}/confirm", response_model=None)
def confirm_draft(draft_id: str, req: ConfirmRequest):
    """Enter the out-of-band code for an escalated draft. Records the
    confirmation (bound to the draft's payload hash) for the gateway, and logs
    the attempt either way. Three wrong codes burn the challenge."""
    draft = _drafts.get(draft_id)
    if draft is None or draft.payload is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    p_hash = payload_hash(draft.payload)
    try:
        _step_up.confirm(draft_id, req.code)
    except StepUpError as exc:
        _traces.event(draft_id, "confirm", ok=False, error=str(exc),
                      attempts_left=exc.attempts_left)
        _audit.append(AuditEntryType.CONFIRMATION, {
            "draft_id": draft_id, "payload_hash": p_hash,
            "confirmed": False, "attempts_left": exc.attempts_left})
        raise HTTPException(400, {"error": str(exc),
                                  "attempts_left": exc.attempts_left})
    _audit.append(AuditEntryType.CONFIRMATION, {
        "draft_id": draft_id, "payload_hash": p_hash, "confirmed": True})
    _traces.event(draft_id, "confirm", ok=True)
    return {"confirmed": True, "draft_id": draft_id}


@app.get("/api/phone/messages", response_model=None)
def phone_messages(user_id: str = Query(DEMO_USER_ID)):
    """# MOCK: the simulated phone's inbox, rendered by /phone and by the
    drop-down banner on the assistant page (phone-notify.js). Stands in for an
    SMS gateway so the demo can show the second channel.
    Would NOT exist in a deployment — like /api/auth/mock-sign."""
    return {"user_id": user_id, "messages": _phone.messages(user_id)}


@app.get("/phone")
def phone_page():
    """The simulated phone (open it in a second window for the demo)."""
    return FileResponse(FRONTEND_DIR / "phone.html")


@app.get("/api/drafts/{draft_id}", response_model=None)
def get_draft(draft_id: str):
    """The stored draft. The overlay renders `resolved_plan` from this and
    recomputes payload_hash itself (frontend/canonical.js)."""
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    return {
        "status": draft.status, "draft_id": draft.draft_id, "kind": draft.kind,
        "transcript": draft.transcript,
        "contact_change": (draft.resolved_change.model_dump(mode="json")
                           if draft.resolved_change else None),
        "mandate": (draft.resolved_mandate.model_dump(mode="json")
                    if draft.resolved_mandate else None),
        "resolved_plan": (draft.resolved_plan.model_dump(mode="json")
                          if draft.resolved_plan else None),
        "policy": draft.policy, "validation": draft.validation,
        "question": draft.question,
    }


# --------------------------------------------------------------------------- /data: request traces
@app.get("/api/data", response_model=None)
def data_traces():
    """# MOCK/demo: the last requests, step by step — the exact prompts sent to
    the LLM, its raw replies, and what every deterministic step did next."""
    return {"provider": get_provider(settings).name, "traces": _traces.recent()}


@app.get("/data")
def data_page():
    return FileResponse(FRONTEND_DIR / "data.html")


# --------------------------------------------------------------------------- contacts
@app.get("/api/contacts", response_model=None)
def list_contacts(user_id: str = Query(DEMO_USER_ID)):
    """The user's contacts (nickname, last 4, phone) — read-only."""
    return _contacts_view(user_id)


class ContactApplyRequest(BaseModel):
    """Mock-signer path, like /api/gateway/execute: payload + signature + nonce."""
    contact_change: ResolvedContactChange
    signature: str | None = None
    nonce: str
    credential_id: str


@app.post("/api/contacts/apply", **_MOCK_ONLY)
def contacts_apply(req: ContactApplyRequest):
    return _traced_gateway(req.contact_change.draft_id, "mock signer",
                           _gateway.submit_contact_change(req.contact_change, req.signature,
                                                          req.nonce, req.credential_id))


class ContactApplyWebAuthnRequest(BaseModel):
    """The real path: a WebAuthn assertion over sha256(payload_hash + nonce)."""
    contact_change: ResolvedContactChange
    assertion: dict
    nonce: str
    credential_id: str


@app.post("/api/contacts/apply-webauthn")
def contacts_apply_webauthn(req: ContactApplyWebAuthnRequest):
    """The only route by which a contact's name or number changes."""
    return _traced_gateway(req.contact_change.draft_id, "WebAuthn",
                           _webauthn_gateway.submit_contact_change(req.contact_change, req.assertion,
                                                                   req.nonce, req.credential_id))


class ContactAddRequest(BaseModel):
    """Mock-signer path (tests / red-team only, like /api/contacts/apply)."""
    contact_add: ResolvedContactAdd
    signature: str | None = None
    nonce: str
    credential_id: str


@app.post("/api/contacts/add", **_MOCK_ONLY)
def contacts_add(req: ContactAddRequest):
    return _traced_gateway(req.contact_add.draft_id, "mock signer",
                           _gateway.submit_contact_add(req.contact_add, req.signature,
                                                       req.nonce, req.credential_id))


class ContactAddWebAuthnRequest(BaseModel):
    contact_add: ResolvedContactAdd
    assertion: dict
    nonce: str
    credential_id: str


class ContactRemoveRequest(BaseModel):
    """The contact as the card shows it: name and last 4 digits (the list
    never carries ids)."""
    nickname: str
    last4: str
    user_id: str = DEMO_USER_ID


@app.post("/api/contacts/remove")
def contacts_remove(req: ContactRemoveRequest):
    """A confirm tap, not a signature: removing someone only narrows who can be
    paid. The row stays (history and the scam rules point at it); the contact
    leaves the list, payments and edits, and anything drafted to them before
    now is refused as REMOVED (backend/gateway/gateway.py)."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT id FROM payees WHERE user_id=? AND nickname=? AND last4=? "
            "AND removed_at IS NULL", (req.user_id, req.nickname, req.last4)).fetchall()
        if len(rows) != 1:
            # Two the same on the card: removing either could be the wrong one.
            raise HTTPException(404 if not rows else 409,
                                "No such contact." if not rows else
                                "Two contacts have that name and number ending. "
                                "Rename one first.")
        # Only if still there: two taps racing each other remove (and audit) once.
        if conn.execute("UPDATE payees SET removed_at=? WHERE id=? AND removed_at IS NULL",
                        (int(time.time()), rows[0]["id"])).rowcount != 1:
            raise HTTPException(404, "No such contact.")
        conn.commit()
    finally:
        conn.close()
    # The id, not the name or number: the chain is append-only (as CONTACT_ADD).
    _audit.append(AuditEntryType.CONTACT_REMOVE, {"payee_id": rows[0]["id"],
                                                  "outcome": "REMOVED"})
    return {"removed": f"{req.nickname} \u00b7\u00b7{req.last4}"}


@app.post("/api/contacts/add-webauthn")
def contacts_add_webauthn(req: ContactAddWebAuthnRequest):
    """The only route by which a new contact is saved."""
    return _traced_gateway(req.contact_add.draft_id, "WebAuthn",
                           _webauthn_gateway.submit_contact_add(req.contact_add, req.assertion,
                                                                req.nonce, req.credential_id))


# --------------------------------------------------------------------------- recurring bill payments
# docs/RECURRING_BILLS.md. Setup is read by rules (backend/recurring/parse.py,
# never the model) and confirmed field by field on a form; the terms are a
# RecurringBillMandate the user signs with their passkey. The first payments
# are ordinary one-payment drafts the user signs one by one; later ones — only
# if the signed terms say so — are paid by Gateway.run_mandate_occurrence().
RECURRING_TICK_S = 10
_mirrored_notification = 0      # the last notification already sent to the demo phone


def _recurring_tick() -> list[dict]:
    """Run what has fallen due (the recurring clock: real time unless the demo
    clock is on), then copy new notifications to the demo phone."""
    events = run_due(recurring_clock.now(), gateway=_webauthn_gateway)
    _mirror_notifications()
    return events


def _mirror_notifications() -> None:
    """# MOCK: the durable notifications, also delivered to the simulated phone
    (its drop-down banner). Text only — no link in a notification approves
    anything; the pending payment is approved in the app, with the passkey."""
    global _mirrored_notification
    conn = get_conn()
    try:
        rows = conn.execute("SELECT id, user_id, title, body FROM notifications WHERE id>? "
                            "ORDER BY id", (_mirrored_notification,)).fetchall()
    finally:
        conn.close()
    for r in rows:
        _phone.deliver(r["user_id"], f"DCTA: {r['title']}. {r['body']}")
        _mirrored_notification = r["id"]


def _start_mirror_after_existing() -> None:
    """Startup: don't replay old notifications to the phone."""
    global _mirrored_notification
    conn = get_conn()
    try:
        row = conn.execute("SELECT COALESCE(MAX(id), 0) AS n FROM notifications").fetchone()
        _mirrored_notification = int(row["n"])
    finally:
        conn.close()


_start_mirror_after_existing()


def _occurrence_refusal(draft: Draft) -> str | None:
    """For a recurring occurrence's approval draft: why it can't be signed now
    (the executor's own check, read-only), else None."""
    if draft.kind != "payment" or draft.resolved_plan is None:
        return None
    conn = get_conn()
    try:
        occ = recurring_store.occurrence_for_draft(conn, draft.draft_id)
        if occ is None:
            return None
        return recurring_store.execution_refusal(conn, occ, draft.resolved_plan,
                                                 authority=recurring_store.SIGNATURE,
                                                 now=recurring_clock.now())
    finally:
        conn.close()


def _setup_options(conn, user_id: str) -> dict:
    """The choices the setup form offers — ids the server issued, labels from
    the DB (billers' references masked to digits; never the raw text)."""
    return {
        "billers": [{"id": b.biller_id, "name": b.name, "reference": b.masked}
                    for b in _billers.all_billers(conn)],
        "accounts": [{"id": r["id"], "label": account_label(r["id"])} for r in conn.execute(
            "SELECT id FROM accounts WHERE user_id=? AND type IN ('savings','joint') ORDER BY id",
            (user_id,))],
        "frequencies": [{"id": recurring_schedule.MONTHLY, "label": "Monthly"},
                        {"id": recurring_schedule.WEEKLY, "label": "Weekly"}],
        "max_occurrences": recurring_terms.MAX_OCCURRENCES,
        "approvals": recurring_terms.SUPERVISED_APPROVALS,
    }


def _setup_body(draft: Draft, *, errors: dict | None = None) -> dict:
    setup = draft.setup or {}
    fields = setup.get("fields", {})
    missing = setup.get("missing", [])
    now = recurring_clock.now()
    conn = get_conn()
    try:
        options = _setup_options(conn, draft.user_id)
    finally:
        conn.close()
    return {"status": "recurring_setup", "kind": "recurring_setup", "draft_id": draft.draft_id,
            "transcript": draft.transcript, "fields": fields, "missing": missing,
            "questions": [recurring_parse.QUESTIONS[m] for m in missing],
            "notes": setup.get("notes", []), "errors": errors or {}, "options": options,
            "timezone": DEFAULT_TIMEZONE, "due_time": recurring_schedule.DUE_LOCAL_TIME,
            "today": recurring_schedule.local_date(now, DEFAULT_TIMEZONE).isoformat()}


def _recurring_setup_start(req: DraftRequest) -> dict:
    """A recurring request: read what the rules can, and ask for the rest on a
    form. No model, no terms yet, nothing to sign."""
    now = recurring_clock.now()
    conn = get_conn()
    try:
        billers = _billers.all_billers(conn)
        nicknames = [r["nickname"] for r in conn.execute(
            "SELECT nickname FROM payees WHERE user_id=?", (req.user_id,))]
    finally:
        conn.close()
    fields = recurring_parse.extract(req.transcript, billers=billers,
                                     today=recurring_schedule.local_date(now, DEFAULT_TIMEZONE))
    tid = DraftStore.new_id()
    _trace_start(tid, req, "recurring_bill")
    _traces.event(tid, "recurring_parse", note="rules only; the model is not called",
                  fields=fields.to_dict(), missing=fields.missing())
    import re as _re
    if fields.biller_id is None and any(
            _re.search(r"\b" + _re.escape(n) + r"\b", req.transcript, _re.I) for n in nicknames):
        # Recurring transfers to people aren't offered: a bill's destination
        # is a registered biller; a person's number can change under you.
        return {"status": "info", "kind": "recurring_unsupported",
                "message": "I can set up recurring payments for bills only. A payment to a "
                           "person has to be made, and approved, each time."}
    draft = _drafts.put(Draft(
        draft_id=tid, user_id=req.user_id, transcript=req.transcript, intent_plan={},
        created_at=time.time(), kind="recurring_setup", status="clarify",
        setup={"fields": fields.to_dict(), "missing": fields.missing(), "notes": fields.notes,
               "mandate_id": recurring_terms.new_mandate_id()}))
    _audit.append(AuditEntryType.TRANSCRIPT, {
        "draft_id": draft.draft_id, "transcript_hash": hash_transcript(req.transcript),
        "chars": len(req.transcript), "parser_provider": "rules", "user_id": req.user_id,
        "kind": "recurring_setup"})
    return _setup_body(draft)


class RecurringSetupForm(BaseModel):
    """The user's confirmed choices. Ids are ones the setup form offered; the
    server checks every one against the ledger (backend/recurring/terms.py)."""
    biller_id: str | None = Field(default=None, max_length=64)
    source_account: str | None = Field(default=None, max_length=64)
    amount: str | None = Field(default=None, max_length=20)
    frequency: str | None = Field(default=None, max_length=16)
    start_date: str | None = Field(default=None, max_length=10)
    occurrence_count: int | None = None
    end_date: str | None = Field(default=None, max_length=10)
    # No default on purpose: missing is an error, never "no" and never "yes".
    auto_after_supervised: bool | None = None


@app.post("/api/recurring/setup/{draft_id}", response_model=None)
def recurring_setup(draft_id: str, form: RecurringSetupForm):
    """Confirmed setup fields -> the terms to review and sign, or the form
    again with what's wrong."""
    draft = _drafts.get(draft_id)
    if draft is None or draft.kind not in ("recurring_setup", "mandate"):
        raise HTTPException(404, {"error": "that setup has expired — please ask again",
                                  "draft_id": draft_id})
    if draft.status in FINAL_STATUSES:
        raise HTTPException(409, {"error": f"this setup is {draft.status}", "draft_id": draft_id})
    conn = get_conn()
    try:
        terms, errors = recurring_terms.build(
            form.model_dump(), conn=conn, user_id=draft.user_id, draft_id=draft_id,
            mandate_id=draft.setup["mandate_id"], transcript=draft.transcript,
            now=recurring_clock.now(), sign_now=int(time.time()))
    finally:
        conn.close()
    _traces.event(draft_id, "recurring_terms", ok=terms is not None, errors=errors)
    if terms is None:
        draft.kind, draft.status, draft.resolved_mandate = "recurring_setup", "clarify", None
        draft.setup = {**draft.setup, "fields": {**draft.setup["fields"],
                                                 **{k: v for k, v in form.model_dump().items()
                                                    if v is not None}},
                       "missing": []}
        return _setup_body(draft, errors=errors)
    draft.kind, draft.status, draft.resolved_mandate = "mandate", "ready", terms
    p_hash = payload_hash(terms)
    _audit.append(AuditEntryType.DRAFT, {"draft_id": draft_id, "kind": "mandate",
                                         "payload_hash": p_hash, "mandate_id": terms.mandate_id})
    return {"status": "ready", "kind": "mandate", "draft_id": draft_id,
            "mandate": terms.model_dump(mode="json"), "payload_hash": p_hash,
            "preview": recurring_terms.preview(terms), "transcript": draft.transcript}


class MandateEnrollRequest(BaseModel):
    """Mock-signer path (tests / red-team only, like /api/gateway/execute)."""
    mandate: RecurringBillMandate
    signature: str | None = None
    nonce: str
    credential_id: str


@app.post("/api/recurring/mandates/enroll", **_MOCK_ONLY)
def recurring_enroll(req: MandateEnrollRequest):
    return _traced_gateway(req.mandate.draft_id, "mock signer",
                           _gateway.submit_mandate(req.mandate, req.signature, req.nonce,
                                                   req.credential_id))


class MandateEnrollWebAuthnRequest(BaseModel):
    mandate: RecurringBillMandate
    assertion: dict
    nonce: str
    credential_id: str


@app.post("/api/recurring/mandates/enroll-webauthn")
def recurring_enroll_webauthn(req: MandateEnrollWebAuthnRequest):
    """The only route by which a recurring arrangement is created."""
    out = _webauthn_gateway.submit_mandate(req.mandate, req.assertion, req.nonce,
                                           req.credential_id)
    _mirror_notifications()
    return _traced_gateway(req.mandate.draft_id, "WebAuthn", out)


def _mandate_view(m: dict, occs: list[dict], now: int) -> dict:
    """An arrangement as the detail page shows it — from the signed terms and
    the server's own counters."""
    terms = recurring_store.load_terms(m)
    if terms is None:
        return {"mandate_id": m["mandate_id"], "status": m["status"], "broken": True,
                "status_reason": "this arrangement's record doesn't match what you signed"}
    tz = terms.timezone
    left = max(0, terms.supervised_approvals - m["supervised_successes"])
    if not terms.auto_after_supervised:
        auto = "Never — you approve every payment yourself."
    elif m["mode"] == "AUTO":
        auto = "On — payments are made automatically on their due date."
    else:
        auto = (f"After {left} more approved payment{'s' if left != 1 else ''}, the rest are "
                f"paid automatically.")
    upcoming = next((o for o in occs if o["status"] in recurring_store.OPEN), None)
    return {
        "mandate_id": m["mandate_id"], "version": m["version"], "status": m["status"],
        "status_reason": m["status_reason"], "mode": m["mode"],
        "biller": terms.biller_display, "reference": terms.biller_reference_masked,
        "account": terms.source_display, "amount_cents": terms.amount_cents,
        "amount_display": "$" + cents_to_display(terms.amount_cents),
        "frequency": terms.frequency, "count": terms.occurrence_count,
        "paid_count": m["paid_count"],
        "paid_total_display": "$" + cents_to_display(m["paid_total_cents"]),
        "total_cap_display": "$" + cents_to_display(terms.total_cap_cents),
        "auto_after_supervised": terms.auto_after_supervised,
        "supervised_successes": m["supervised_successes"],
        "approvals_left": left if terms.auto_after_supervised and m["mode"] != "AUTO" else None,
        "automatic": auto,
        "next_due": (recurring_schedule.label(recurring_schedule.parse_date(upcoming["due_date"]))
                     if upcoming else None),
        "timezone": tz, "due_time": terms.due_local_time,
        "start_date": recurring_schedule.label(recurring_schedule.parse_date(terms.start_date)),
        "final_date": recurring_schedule.label(recurring_schedule.parse_date(terms.end_date)),
        "occurrences": [{
            "seq": o["seq"], "due": recurring_schedule.label(recurring_schedule.parse_date(o["due_date"])),
            "status": o["status"], "phase": o["phase"], "reason": o["reason"],
            "approvable": (m["status"] == "ACTIVE" and o["status"] in recurring_store.APPROVABLE
                           and o["due_at"] <= now <= o["review_until"]),
            "review_until": recurring_schedule.label(
                recurring_schedule.local_date(o["review_until"], tz)),
        } for o in occs],
    }


@app.get("/api/recurring/mandates", response_model=None)
def recurring_list(user_id: str = Query(DEMO_USER_ID)):
    now = recurring_clock.now()
    conn = get_conn()
    try:
        out = [_mandate_view(m, recurring_store.occurrences(conn, m["mandate_id"]), now)
               for m in recurring_store.mandates_for(conn, user_id)]
    finally:
        conn.close()
    return {"user_id": user_id, "mandates": out}


@app.get("/api/recurring/mandates/{mandate_id}", response_model=None)
def recurring_detail(mandate_id: str, user_id: str = Query(DEMO_USER_ID)):
    now = recurring_clock.now()
    conn = get_conn()
    try:
        m = recurring_store.get_mandate(conn, mandate_id)
        if m is None or m["user_id"] != user_id:
            raise HTTPException(404, {"error": "no such recurring payment"})
        view = _mandate_view(m, recurring_store.occurrences(conn, mandate_id), now)
        view["activity"] = [n for n in recurring_store.notifications(conn, user_id, limit=200)
                            if n["mandate_id"] == mandate_id][:30]
    finally:
        conn.close()
    return view


class MandateAction(BaseModel):
    user_id: str = DEMO_USER_ID


def _mandate_action(mandate_id: str, user_id: str, action) -> dict:
    out = action(mandate_id, user_id, now=recurring_clock.now())
    if out is None:
        raise HTTPException(404, {"error": "no such recurring payment"})
    _audit.append(AuditEntryType.MANDATE_STATUS, {"mandate_id": mandate_id,
                                                  "status": out["status"], "by": "user"})
    _mirror_notifications()
    return {"mandate_id": mandate_id, "status": out["status"]}


@app.post("/api/recurring/mandates/{mandate_id}/pause", response_model=None)
def recurring_pause(mandate_id: str, req: MandateAction = MandateAction()):
    """Pause at once: nothing is paid while paused, and what falls due is
    skipped, not paid later. No signature — making things safer is easy."""
    return _mandate_action(mandate_id, req.user_id, recurring_store.pause)


@app.post("/api/recurring/mandates/{mandate_id}/cancel", response_model=None)
def recurring_cancel(mandate_id: str, req: MandateAction = MandateAction()):
    """Cancel for good. No signature needed."""
    return _mandate_action(mandate_id, req.user_id, recurring_store.cancel)


def _resume_id(mandate_id: str) -> str:
    return f"mandate-resume:{mandate_id}"


@app.post("/api/recurring/mandates/{mandate_id}/resume/begin", response_model=None)
def recurring_resume_begin(mandate_id: str, req: MandateAction = MandateAction()):
    """Resuming switches payments back on, so — like unfreezing — it takes a
    code sent to the user's phone, not one tap someone steering the page could
    make."""
    conn = get_conn()
    try:
        m = recurring_store.get_mandate(conn, mandate_id)
    finally:
        conn.close()
    if m is None or m["user_id"] != req.user_id:
        raise HTTPException(404, {"error": "no such recurring payment"})
    if m["status"] != "PAUSED":
        raise HTTPException(409, {"error": f"this arrangement is {m['status'].lower()}"})
    code = _step_up.issue(_resume_id(mandate_id), "resume")
    _phone.deliver(req.user_id, f"DCTA: to resume your recurring payment, enter code {code}. "
                                f"Valid 5 min. If you didn't ask for this, ignore it.")
    return {"code_sent": True, "channel": "your registered phone"}


class MandateResume(BaseModel):
    user_id: str = DEMO_USER_ID
    code: str


@app.post("/api/recurring/mandates/{mandate_id}/resume", response_model=None)
def recurring_resume(mandate_id: str, req: MandateResume):
    try:
        _step_up.confirm(_resume_id(mandate_id), req.code)
    except StepUpError as exc:
        raise HTTPException(400, {"error": str(exc), "attempts_left": exc.attempts_left})
    _step_up.consume(_resume_id(mandate_id))
    return _mandate_action(mandate_id, req.user_id, recurring_store.resume)


def _pending_view(conn, occ: dict) -> dict:
    m = recurring_store.get_mandate(conn, occ["mandate_id"])
    terms = recurring_store.load_terms(m)
    return {"mandate_id": occ["mandate_id"], "seq": occ["seq"], "status": occ["status"],
            "reason": occ["reason"], "biller": terms.biller_display if terms else None,
            "count": terms.occurrence_count if terms else None,
            "amount_display": "$" + cents_to_display(terms.amount_cents) if terms else None,
            "account": terms.source_display if terms else None,
            "due": recurring_schedule.label(recurring_schedule.parse_date(occ["due_date"])),
            "review_until": recurring_schedule.label(recurring_schedule.local_date(
                occ["review_until"], terms.timezone if terms else DEFAULT_TIMEZONE))}


@app.get("/api/recurring/pending", response_model=None)
def recurring_pending(user_id: str = Query(DEMO_USER_ID)):
    """Bills waiting for the user's approval. Durable: they stay here when the
    app was closed when they fell due."""
    now = recurring_clock.now()
    conn = get_conn()
    try:
        return {"user_id": user_id, "pending": [
            _pending_view(conn, o) for o in recurring_store.pending_for(conn, user_id, now)]}
    finally:
        conn.close()


@app.post("/api/recurring/occurrences/{mandate_id}/{seq}/review", response_model=None)
def recurring_review(mandate_id: str, seq: int, req: MandateAction = MandateAction()):
    """Open a pending bill: a fresh one-payment draft built from the mandate,
    checked like any payment, for the user to approve with their passkey (the
    normal /api/auth/nonce + /api/gateway/execute-webauthn flow)."""
    try:
        draft, terms, verdicts, assessment = recurring_approve.build_draft(
            mandate_id, seq, user_id=req.user_id, db_path=DB_PATH, now=recurring_clock.now(),
            recent_change_hours=settings.recent_change_hours,
            cooling_hours=settings.credential_cooling_hours, executor=_executor)
    except recurring_approve.NotApprovable as exc:
        raise HTTPException(exc.status, exc.detail)
    _audit.append(AuditEntryType.POLICY, verdicts.to_audit_payload(draft.draft_id))
    _audit.append(AuditEntryType.SCAM_ASSESSMENT, {"stage": "recurring_review",
                                                   **assessment.to_audit()})
    _traces.start(draft.draft_id, transcript=draft.transcript, route="recurring_review",
                  user_id=req.user_id)
    _traces.event(draft.draft_id, "recurring_review", status=draft.status,
                  policy=draft.policy, scam=assessment.outcome)
    info = {"mandate_id": mandate_id, "seq": seq, "count": terms.occurrence_count,
            "biller": terms.biller_display}
    if draft.status != "ready":
        reasons = verdicts.reasons() or list(assessment.warnings) or [
            "This payment needs extra checks that a recurring approval can't do."]
        return {"status": "blocked", "kind": "recurring_review", "draft_id": draft.draft_id,
                "recurring": info, "reasons": reasons,
                "message": "This payment wasn't paid. If you still want to pay it, make it as a "
                           "one-time payment, where every check runs in full."}
    _drafts.put(draft)
    p_hash = payload_hash(draft.resolved_plan)
    _audit.append(AuditEntryType.MANDATE_OCCURRENCE, {
        "mandate_id": mandate_id, "seq": seq, "draft_id": draft.draft_id,
        "payload_hash": p_hash, "stage": "review_drafted"})
    return {"status": "ready", "kind": "payment", "draft_id": draft.draft_id,
            "transcript": draft.transcript, "narration": None,
            "scam": _public_scam(assessment, None, draft.scam),
            "resolved_plan": draft.resolved_plan.model_dump(mode="json"),
            "payload_hash": p_hash, "policy": draft.policy, "validation": draft.validation,
            "requires_extra_confirmation": False, "confirmation": None, "recurring": info}


@app.get("/api/recurring/notifications", response_model=None)
def recurring_notifications(user_id: str = Query(DEMO_USER_ID), after_id: int = Query(0)):
    conn = get_conn()
    try:
        return {"user_id": user_id,
                "notifications": recurring_store.notifications(conn, user_id, after_id=after_id)}
    finally:
        conn.close()


@app.post("/api/recurring/run-due", response_model=None)
def recurring_run_due():
    """Run whatever has fallen due NOW, by the server's clock — the same thing
    the background loop and `python -m backend.recurring run-due` do. Nothing
    can be run early from here: there is no `now` to pass."""
    return {"events": _recurring_tick(), "now": recurring_clock.now()}


@app.get("/api/recurring/clock", response_model=None)
def recurring_clock_state():
    now = recurring_clock.now()
    return {"demo": recurring_clock.demo_enabled(), "now": now,
            "offset_s": recurring_clock.offset(),
            "today": recurring_schedule.label(recurring_schedule.local_date(now, DEFAULT_TIMEZONE))}


def _require_demo_clock(request: Request) -> None:
    if not recurring_clock.demo_enabled():
        logging.warning("blocked call to disabled demo-clock route %s", request.url.path)
        raise HTTPException(status_code=404, detail="Not Found")


class ClockAdvance(BaseModel):
    user_id: str = DEMO_USER_ID


@app.post("/api/recurring/clock/advance", dependencies=[Depends(_require_demo_clock)],
          include_in_schema=False)
def recurring_clock_advance(req: ClockAdvance = ClockAdvance()):
    """DEMO ONLY (RECURRING_DEMO_CLOCK=1; 404 otherwise): jump the recurring
    clock to the user's next due payment and run it."""
    now = recurring_clock.now()
    conn = get_conn()
    try:
        row = conn.execute(
            "SELECT MIN(o.due_at) AS t FROM mandate_occurrences o JOIN mandates m "
            "USING (mandate_id) WHERE m.user_id=? AND m.status IN ('ACTIVE','PAUSED') "
            "AND o.status='SCHEDULED'", (req.user_id,)).fetchone()
    finally:
        conn.close()
    if row is None or row["t"] is None:
        raise HTTPException(409, {"error": "no payment is waiting to fall due"})
    recurring_clock.advance_to(max(int(row["t"]), now))
    return {"events": _recurring_tick(), "now": recurring_clock.now(),
            "today": recurring_schedule.label(recurring_schedule.local_date(
                recurring_clock.now(), DEFAULT_TIMEZONE))}


# Serve frontend assets (canonical.js, app.js, style.css). Mounted LAST so the
# API routes above match first.
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
