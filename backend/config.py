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

    # DB
    db_path: Path = Path(__file__).resolve().parent / "data" / "dcta.db"

    @property
    def has_credentials(self) -> bool:
        """True only if real Tencent creds are present. Stubs are used while False."""
        return bool(self.tencent_secret_id and self.tencent_secret_key)


settings = Settings()
