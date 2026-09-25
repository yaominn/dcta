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
import time

from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import settings
from backend.data.db import DB_PATH, get_conn, migrate
from backend.audit import AuditLog
from backend.audit.log import AuditEntryType
from backend.audit.canonical import payload_hash, challenge_hash, hash_transcript
from backend.gateway.gateway import CLOSED_OUTCOMES
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
from backend.agent import (ParseFailure, ProviderUnavailable, build_context,
                           classify_request, get_provider, parse_contact_edit,
                           parse_transcript)
from backend.models.contacts import ContactEditPlan, ResolvedContactChange
from backend.policy import contact_change_step_up
from backend.resolver.contacts import resolve_contact_edit
from backend.validator.contacts import validate_contact_change
from backend.asr import (MAX_AUDIO_BYTES,
                         ASRNoSpeech, ASRUnavailable, get_asr_provider)
from backend.resolver import Clarify, resolve
from backend.validator import default_freeze_set, validate
from backend.resolver import Clarify, Resolved, resolve
from backend.policy import Decision, evaluate, load_context
from backend.drafts import Draft, DraftStore
from backend.trace import RecordingProvider, TraceStore
from backend.display import change_summary, plan_summary

from pathlib import Path

app = FastAPI(
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
_credentials.register("cred_alice", _signer.public_key)   # MOCK demo credential


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
)

# In-memory registration challenges (user_id -> (challenge bytes, issued_at)).
# Anti-replay for the registration ceremony itself; TTL 120s like the signing
# nonce. Demo-scale; a deployment would persist + TTL-sweep this.
_registration_challenges: dict[str, tuple[bytes, float]] = {}
_REG_CHALLENGE_TTL = 120.0

# The mock demo session (brief 8: app login is a mock session). M2 registers a
# passkey FOR this user; signing verifies against it.
DEMO_USER_ID = "u_alice"


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
    resolved_plan: ResolvedPlan
    nonce: str


@app.post("/api/auth/mock-sign", **_MOCK_ONLY)
def mock_sign(req: MockSignRequest):
    p_hash = payload_hash(req.resolved_plan)
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
            draft.status = "executed"
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
            "SELECT * FROM payees WHERE user_id=?", (req.user_id,)).fetchall()]
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
    report = validate(
        req.intent_plan, req.resolved_plan, req.transcript,
        provider=provider, audit=_audit,
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
        _traces.event(draft.draft_id, "resolve", outcome="question", **draft.question)
        return {"status": "clarify", "draft_id": draft.draft_id, **draft.question}

    resolved = outcome.plan
    draft.question = None
    _traces.event(draft.draft_id, "resolve", outcome="resolved",
                  resolved_plan=resolved.model_dump(mode="json"))

    # --- policy (M5). A BLOCKED draft keeps NO plan: there is nothing to sign.
    verdicts = evaluate(resolved, load_context(draft.user_id, db_path=DB_PATH))
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
    report = validate(plan, resolved, draft.transcript, provider=auditor, audit=_audit)
    draft.validation = {"verdict": report.verdict, "frozen": report.frozen,
                        "checks": report.checks, "soft_signals": report.soft_signals,
                        "llm_check": report.llm_check}
    draft.resolved_plan = resolved
    draft.status = "frozen" if report.frozen else "ready"
    p_hash = payload_hash(resolved)
    _traces.event(draft.draft_id, "validate", verdict=report.verdict, frozen=report.frozen,
                  checks=report.checks, soft_signals=report.soft_signals,
                  llm_check=report.llm_check, llm_calls=auditor.calls)

    # --- step-up. An escalated plan gets a code on the out-of-band channel,
    #     bound to THIS payload hash. The code is never in this response: the
    #     point is that it arrives somewhere the overlay cannot touch, with the
    #     transaction described from the server's copy of the plan.
    needs_step_up = (draft.status == "ready"
                     and verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION)
    if needs_step_up:
        code = _step_up.issue(draft.draft_id, p_hash)
        _traces.event(draft.draft_id, "step_up", sent=True, channel="phone (simulated)",
                      reasons=verdicts.reasons())
        _phone.deliver(draft.user_id,
                       f"DCTA: to {plan_summary(resolved)}, enter code {code}. "
                       f"Valid 5 min. Never share this code. If this wasn't "
                       f"you, ignore this message.")

    return {
        "status": draft.status,
        "draft_id": draft.draft_id,
        "resolved_plan": resolved.model_dump(mode="json"),
        "payload_hash": p_hash,
        "policy": draft.policy,
        "validation": draft.validation,
        "requires_extra_confirmation": needs_step_up,
        "confirmation": ({"channel": "your registered phone",
                          "reasons": verdicts.reasons()}
                         if needs_step_up else None),
    }


@app.post("/api/drafts", response_model=None)
def create_draft(req: DraftRequest):
    """transcript -> a signable draft, a question, a policy refusal or a freeze."""
    conn = get_conn()
    try:
        payees = [dict(r) for r in conn.execute(
            "SELECT * FROM payees WHERE user_id=?", (req.user_id,)).fetchall()]
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

    # Which pipeline. Not a security decision: every route ends at a draft the
    # user must sign, or (the list) a read-only view of their own contacts.
    route = classify_request(req.transcript)
    if route == "contact_list":
        view = _contacts_view(req.user_id)
        tid = "list-" + DraftStore.new_id()
        _traces.start(tid, transcript=req.transcript, route=route, user_id=req.user_id)
        _traces.event(tid, "contacts", note="read-only; the LLM is not called",
                      count=len(view["contacts"]))
        return view

    provider = RecordingProvider(get_provider(settings))
    try:
        if route == "contact_edit":
            plan = parse_contact_edit(req.transcript, provider=provider, context=context)
        else:
            plan = parse_transcript(req.transcript, provider=provider, context=context)
    except (ProviderUnavailable, ParseFailure) as exc:
        tid = "failed-" + DraftStore.new_id()
        _traces.start(tid, transcript=req.transcript, route=route, user_id=req.user_id)
        _traces.event(tid, "parse", provider=provider.name, llm_calls=provider.calls,
                      error=str(exc))
        if isinstance(exc, ParseFailure):
            raise HTTPException(status_code=422, detail={
                "error": "could not produce a schema-valid plan within the retry budget",
                "attempts": exc.errors})
        raise HTTPException(status_code=502, detail={
            "error": "LLM provider unavailable", "provider": provider.name,
            "attempts": exc.errors})

    draft = _drafts.put(Draft(
        draft_id=DraftStore.new_id(), user_id=req.user_id,
        transcript=req.transcript, intent_plan=plan.model_dump(),
        created_at=time.time(),
        kind="contact_edit" if route == "contact_edit" else "payment",
    ))
    _traces.start(draft.draft_id, transcript=req.transcript, route=route, user_id=req.user_id)
    _traces.event(draft.draft_id, "parse", provider=provider.name, llm_calls=provider.calls,
                  context=context.to_prompt_json(), result=plan.model_dump(mode="json"))

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
    return _run(draft)


def _run(draft: Draft) -> dict:
    return _contact_pipeline(draft) if draft.kind == "contact_edit" else _pipeline(draft)


def _contacts_view(user_id: str) -> dict:
    """The user's own contacts, read-only. Never the legal name (it stays
    server-side, like everywhere else) and never an id."""
    conn = get_conn()
    try:
        rows = conn.execute(
            "SELECT nickname, last4, phone FROM payees WHERE user_id=? ORDER BY nickname, last4",
            (user_id,)).fetchall()
    finally:
        conn.close()
    return {"status": "info", "kind": "contacts", "contacts": [
        {"display": f"{r['nickname']} ··{r['last4']}", "nickname": r["nickname"],
         "last4": r["last4"], "phone": r["phone"] or ""} for r in rows]}


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
    return _run(draft)


# --------------------------------------------------------------------------- decline / cancel
# Saying no, on the server. Before this the only way to refuse a draft was to
# leave it alone, and it stayed signable for its whole window. Both are FINAL,
# audited, and recorded in the same durable table as executions — so a decline
# racing a signature is settled by whichever reaches the ledger first, and the
# user is never told "nothing was sent" about money that was.
#   decline — the user says no to the card before confirming (the page's Cancel)
#   cancel  — the user withdraws a draft that has not run (the hold window)
FINAL_STATUSES = frozenset({"executed", "declined", "cancelled"})


def _close_draft(draft_id: str, outcome: str, entry: AuditEntryType) -> dict:
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
    _audit.append(entry, {"draft_id": draft_id, "payload_hash": p_hash, "prior_status": was})
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
    """# MOCK: the simulated phone's inbox, rendered by /phone. Stands in for
    an SMS gateway so the demo can show the second channel on a second screen.
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


# Serve frontend assets (canonical.js, app.js, style.css). Mounted LAST so the
# API routes above match first.
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
