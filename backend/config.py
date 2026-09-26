"""
Configuration. Secrets come from the environment / a local .env file — never
hardcoded, never committed. (brief: swappable LLM provider; no real creds.)

For Milestone 0 nothing needs real credentials: the stubs don't call Tencent.
Wire real keys here when we reach M3 (LLM) and M7 (ASR) — the code just reads
these env vars, so swapping stub -> real is one config change, no code edit.
"""
from __future__ import annotations

import os
from pathlib import Path

# Best-effort .env loading so local dev "just works". python-dotenv is optional.
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except Exception:
    pass  # .env is a convenience; env vars set directly also work.


def env_flag(name: str) -> bool:
    """A boolean env var. ON only for an explicit 1/true/yes/on — anything
    else, including unset or a typo, is OFF. For a flag that WEAKENS security,
    failing closed on an unrecognised value is the only safe reading."""
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "on"}


class Settings:
    # Tencent Cloud credentials — LEFT EMPTY in M0. Fill .env locally to go live.
    tencent_secret_id: str = os.getenv("TENCENTCLOUD_SECRET_ID", "")
    tencent_secret_key: str = os.getenv("TENCENTCLOUD_SECRET_KEY", "")

    # Services (regions/models). Singapore is the spike-confirmed region for ASR.
    asr_region: str = os.getenv("TENCENT_ASR_REGION", "ap-singapore")
    asr_endpoint: str = os.getenv("TENCENT_ASR_ENDPOINT", "asr.ap-singapore.tencentcloudapi.com")
    # Engine must match the spoken language: 16k_en English, 16k_zh Mandarin.
    asr_engine: str = os.getenv("ASR_ENGINE", "16k_en")
    # Container the browser uploads. Chrome's MediaRecorder gives webm-opus,
    # which shares a codec but NOT a container with the documented ogg-opus —
    # configurable because that is the likeliest first-call failure.
    asr_voice_format: str = os.getenv("ASR_VOICE_FORMAT", "mp3")
    asr_timeout_s: float = float(os.getenv("ASR_TIMEOUT_S", "20"))
    hunyuan_model: str = os.getenv("HUNYUAN_MODEL", "hunyuan-functioncall")

    # --- TokenHub (the live LLM endpoint) ---
    # Tencent decommissioned the hunyuan.tencentcloudapi.com ChatCompletions
    # API; every model on it now answers "该模型已下线" and the platform shuts
    # down 2026-09-30. TokenHub is the replacement: OpenAI-compatible wire
    # format, and a bearer API KEY that is a SEPARATE credential from
    # TENCENTCLOUD_SECRET_ID/KEY (those still authenticate ASR, but carry no
    # authority here). Generate one in the TokenHub console.
    tokenhub_api_key: str = os.getenv("TOKENHUB_API_KEY", "")
    tokenhub_base_url: str = os.getenv("TOKENHUB_BASE_URL", "https://tokenhub.tencentmaas.com/v1")
    tokenhub_model: str = os.getenv("TOKENHUB_MODEL", "hy3-preview")

    # --- OpenAI (GPT) — alternative LLM, LLM_PROVIDER=openai ---
    # Default model accepts temperature=0; GPT-5-series reasoning models reject
    # it with HTTP 400, so running one of those needs LLM_TEMPERATURE=1.
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_base_url: str = os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")

    # --- Speech-to-text provider ---
    # "openai" | "tencent" | "none" | "auto" (default: Tencent when its
    # credential pair exists, else OpenAI when OPENAI_API_KEY exists, else
    # none). With none, /api/transcribe answers 503 and the browser uses Web
    # Speech — degradation, not failure.
    asr_provider: str = os.getenv("ASR_PROVIDER", "auto")
    # OpenAI transcription reuses OPENAI_API_KEY / OPENAI_BASE_URL above.
    openai_asr_model: str = os.getenv("OPENAI_ASR_MODEL", "gpt-4o-mini-transcribe")
    # ISO-639-1. Pinned because short command-length clips are exactly where
    # auto-detection guesses wrong. Empty = let the model detect.
    openai_asr_language: str = os.getenv("OPENAI_ASR_LANGUAGE", "en")

    # --- LLM behaviour (provider-independent) ---
    # "tokenhub" | "openai" | "hunyuan" | "stub" | "auto" (default: the live provider
    # whose credentials exist). Pinning a live provider makes a missing key
    # fail loudly rather than silently serving stub output, which would look
    # like the model working. "hunyuan" is retained only to reach a
    # self-hosted/legacy endpoint; the public one is gone.
    llm_provider: str = os.getenv("LLM_PROVIDER", "auto")
    # Structured extraction, not prose: near-zero so the same transcript yields
    # the same plan and the retry budget is spent on real ambiguity, not
    # sampling noise.
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))

    # How long payments to a new contact are held when it was added with the
    # HOLD safeguard (backend/policy/new_contact.py). 12 hours by default; set
    # it to a few minutes for a rehearsal that needs to see the hold lift.
    new_contact_hold_minutes: int = int(os.getenv("NEW_CONTACT_HOLD_MINUTES", "720"))

    # --- Scam protection (backend/policy/scam.py) ---
    # How long a HOLD / HOLD_STEP_UP payment is held by the server before it can
    # be confirmed. 30 s for the demo; capped at 4 min (main._hold_seconds) so a
    # held draft can still be signed inside its 5-minute window. Longer holds
    # (a deployment might want hours) need longer-lived drafts first.
    scam_hold_seconds: int = int(os.getenv("SCAM_HOLD_SECONDS", "30"))
    # A destination changed (or added) this recently counts as a recent change.
    recent_change_hours: int = int(os.getenv("RECENT_CHANGE_HOURS", "24"))
    # A passkey added this recently (and not the user's first) is a risk signal.
    credential_cooling_hours: int = int(os.getenv("CREDENTIAL_COOLING_HOURS", "12"))
    # Log each draft's scam score and every prompt sent to the model to the
    # BROWSER console (and the score to the server log). On for the demo — the
    # /data page shows the same prompts; set CONSOLE_DEBUG=0 for a public deploy.
    console_debug: bool = os.getenv("CONSOLE_DEBUG", "1").strip().lower() not in {"0", "false", "no", "off"}
    # A hung upstream call must not hold the HTTP request open indefinitely.
    llm_timeout_s: float = float(os.getenv("LLM_TIMEOUT_S", "30"))
    hunyuan_region: str = os.getenv("TENCENT_HUNYUAN_REGION", "ap-guangzhou")

    # DB
    db_path: Path = Path(__file__).resolve().parent / "data" / "dcta.db"

    # --- WebAuthn (M2, transaction signing) ---
    # RP ID must match the origin's host (no port, no scheme). "localhost" is
    # the one host where WebAuthn works over plain HTTP -- on a deployed demo
    # link this MUST be the HTTPS origin's domain (brief 10 WebAuthn warning:
    # a passkey registered on localhost will not work on the deployed origin).
    rp_id: str = os.getenv("WEBAUTHN_RP_ID", "localhost")
    rp_name: str = os.getenv("WEBAUTHN_RP_NAME", "DCTA")
    # The origin the browser actually speaks. localhost over HTTP for dev;
    # https://<host> for the deployed demo. Verified against clientDataJSON.
    expected_origin: str = os.getenv("WEBAUTHN_EXPECTED_ORIGIN", "http://localhost:8000")

    # --- Mock signing (tests and the red-team runner ONLY) ---
    # Enables /api/auth/mock-sign, /api/gateway/execute and /api/contacts/apply:
    # a server-held HMAC stands in for the user's biometric. /api/auth/mock-sign
    # hands that signature to ANY caller, so with this on, three HTTP calls
    # move money with no passkey and no human. OFF by default, and it must stay
    # off on any server a person can reach. The test-suite and
    # `python -m backend.redteam` switch it on in their own process only.
    mock_signing: bool = env_flag("MOCK_SIGNING")

    @property
    def has_credentials(self) -> bool:
        """True only if real Tencent creds are present. Stubs are used while False.

        This gates ASR (and the legacy Hunyuan endpoint), which still sign with
        SecretId/SecretKey. The LLM has its own gate below — the two are
        separate credentials and one can be present without the other.
        """
        return bool(self.tencent_secret_id and self.tencent_secret_key)

    @property
    def has_llm_credentials(self) -> bool:
        """True when a live LLM provider can authenticate."""
        return bool(self.tokenhub_api_key or self.openai_api_key)


settings = Settings()
