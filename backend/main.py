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

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from backend.config import settings
from backend.data.db import DB_PATH, get_conn
from backend.audit import AuditLog
from backend.audit.log import AuditEntryType
from backend.audit.canonical import payload_hash, challenge_hash, hash_transcript
from backend.gateway import Gateway, NonceStore, MockSigner, MockExecutor, WebAuthnVerifier
from backend.auth import (
    MockCredentialStore,
    WebAuthnCredentialStore,
    registration_options,
    verify_registration,
)
from backend.models.schemas import IntentPlan, ResolvedPlan, ResolvedTransfer
from backend.agent import (ParseFailure, ProviderUnavailable, build_context,
                           get_provider, parse_transcript)
from backend.validator import default_freeze_set, validate
from backend.resolver import Clarify, Resolved, resolve
from backend.policy import Decision, evaluate, load_context
from backend.drafts import Draft, DraftStore

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

_nonce_store = NonceStore(ttl_seconds=120)
_audit = AuditLog(DB_PATH)
_executor = MockExecutor(DB_PATH)
_gateway = Gateway(
    signer=_signer,
    nonce_store=_nonce_store,
    audit=_audit,
    executor=_executor,
    credentials=_credentials,
    policy_db_path=DB_PATH,      # M5: policy is enforced at the chokepoint
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
        raise HTTPException(
            status_code=403,
            detail={"error": "draft frozen by validator", "draft_id": draft_id},
        )
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
    """# MOCK dev-only convenience to demo the happy path. Would NOT exist in M2,
    where the browser signs via WebAuthn. Lets an HTTP client obtain a valid
    signature over the canonical challenge without the server's mock secret."""
    resolved_plan: ResolvedPlan
    nonce: str


@app.post("/api/auth/mock-sign")
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


@app.post("/api/gateway/execute")
def gateway_execute(req: ExecuteRequest):
    """The single execution chokepoint. Verifies nonce -> signature -> executes.
    Returns accepted=True on success; accepted=False (rejected+logged) on any
    verification failure (brief acceptance test: unsigned request rejected+logged)."""
    return _gateway.submit(req.resolved_plan, req.signature, req.nonce, req.credential_id)


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
    return _webauthn_gateway.submit(req.resolved_plan, req.assertion, req.nonce, req.credential_id)


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
_drafts = DraftStore()


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
        return {"status": "clarify", "draft_id": draft.draft_id, **draft.question}

    resolved = outcome.plan
    draft.question = None

    # --- policy (M5). A BLOCKED draft keeps NO plan: there is nothing to sign.
    verdicts = evaluate(resolved, load_context(draft.user_id, db_path=DB_PATH))
    draft.policy = {
        "decision": verdicts.decision.value,
        "verdicts": [{"leg_id": v.leg_id, "decision": v.decision.value,
                      "rule": v.rule, "reason": v.reason} for v in verdicts.verdicts],
    }
    _audit.append(AuditEntryType.POLICY, verdicts.to_audit_payload(draft.draft_id))
    if verdicts.blocked:
        draft.status = "blocked"
        draft.resolved_plan = None
        return {"status": "blocked", "draft_id": draft.draft_id,
                "policy": draft.policy, "reasons": verdicts.reasons()}

    # --- validator (M6). A frozen draft keeps its plan for display, but
    #     /api/auth/nonce refuses a nonce, so it is unsignable.
    report = validate(plan, resolved, draft.transcript,
                      provider=get_provider(settings), audit=_audit)
    draft.validation = {"verdict": report.verdict, "frozen": report.frozen,
                        "checks": report.checks, "soft_signals": report.soft_signals,
                        "llm_check": report.llm_check}
    draft.resolved_plan = resolved
    draft.status = "frozen" if report.frozen else "ready"

    return {
        "status": draft.status,
        "draft_id": draft.draft_id,
        "resolved_plan": resolved.model_dump(mode="json"),
        "payload_hash": payload_hash(resolved),
        "policy": draft.policy,
        "validation": draft.validation,
        "requires_extra_confirmation":
            verdicts.decision is Decision.REQUIRE_EXTRA_CONFIRMATION,
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

    provider = get_provider(settings)
    try:
        plan = parse_transcript(req.transcript, provider=provider, context=context)
    except ProviderUnavailable as exc:
        raise HTTPException(status_code=502, detail={
            "error": "LLM provider unavailable", "provider": provider.name,
            "attempts": exc.errors})
    except ParseFailure as exc:
        raise HTTPException(status_code=422, detail={
            "error": "could not produce a schema-valid plan within the retry budget",
            "attempts": exc.errors})

    draft = _drafts.put(Draft(
        draft_id=DraftStore.new_id(), user_id=req.user_id,
        transcript=req.transcript, intent_plan=plan.model_dump(),
        created_at=time.time(),
    ))
    return _pipeline(draft)


@app.post("/api/drafts/{draft_id}/clarify", response_model=None)
def answer_clarification(draft_id: str, answer: ClarifyAnswer):
    """Answer one question by candidate id. The server re-resolves against its
    OWN stored IntentPlan, and the resolver still refuses an id the mention does
    not justify — so an answer can narrow a choice, never widen it."""
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    draft.answers[answer.field] = answer.choice_id
    return _pipeline(draft)


@app.get("/api/drafts/{draft_id}", response_model=None)
def get_draft(draft_id: str):
    """The stored draft. The overlay renders `resolved_plan` from this and
    recomputes payload_hash itself (frontend/canonical.js)."""
    draft = _drafts.get(draft_id)
    if draft is None:
        raise HTTPException(404, {"error": "no such draft (or it expired)",
                                  "draft_id": draft_id})
    return {
        "status": draft.status, "draft_id": draft.draft_id,
        "transcript": draft.transcript,
        "resolved_plan": (draft.resolved_plan.model_dump(mode="json")
                          if draft.resolved_plan else None),
        "policy": draft.policy, "validation": draft.validation,
        "question": draft.question,
    }


# Serve frontend assets (canonical.js, app.js, style.css). Mounted LAST so the
# API routes above match first.
app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")
