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


class Settings:
    # Tencent Cloud credentials — LEFT EMPTY in M0. Fill .env locally to go live.
    tencent_secret_id: str = os.getenv("TENCENTCLOUD_SECRET_ID", "")
    tencent_secret_key: str = os.getenv("TENCENTCLOUD_SECRET_KEY", "")

    # Services (regions/models). Singapore is the spike-confirmed region for ASR.
    asr_region: str = os.getenv("TENCENT_ASR_REGION", "ap-singapore")
    asr_endpoint: str = os.getenv("TENCENT_ASR_ENDPOINT", "asr.ap-singapore.tencentcloudapi.com")
    hunyuan_model: str = os.getenv("HUNYUAN_MODEL", "hunyuan-functioncall")

    # --- OpenAI (alternative LLM provider) ---
    # Present so development is not blocked while Hunyuan access is pending.
    # `auto` selection still prefers Hunyuan when its credentials exist: the
    # hackathon judges "use of AI tools" and the tracks are built on Tencent
    # Cloud services. Set LLM_PROVIDER=openai to pin this one explicitly.
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    # --- LLM behaviour (provider-independent) ---
    # "hunyuan" | "openai" | "stub" | "auto" (default: pick by credentials).
    llm_provider: str = os.getenv("LLM_PROVIDER", "auto")
    # Structured extraction, not prose: near-zero so the same transcript yields
    # the same plan and the retry budget is spent on real ambiguity, not
    # sampling noise.
    llm_temperature: float = float(os.getenv("LLM_TEMPERATURE", "0"))
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

    @property
    def has_openai_credentials(self) -> bool:
        """True only if a real OpenAI key is present."""
        return bool(self.openai_api_key)

    @property
    def has_credentials(self) -> bool:
        """True only if real Tencent creds are present. Stubs are used while False."""
        return bool(self.tencent_secret_id and self.tencent_secret_key)


settings = Settings()
