"""
TokenHubProvider — Tencent's TokenHub chat completions. (brief Section 8)

This replaces HunyuanProvider. The legacy `hunyuan.tencentcloudapi.com`
ChatCompletions API that provider serves was decommissioned: every model on it
(hunyuan-functioncall, -turbo, -turbos-latest, -t1-latest, -standard, -lite,
-pro, -large) answers `code:2000 该模型已下线` — "this model is offline, migrate
to TokenHub". The old platform shuts down entirely on 2026-09-30.

Three things changed at once, which is why this is a new provider rather than a
new model string on the old one:

    endpoint   hunyuan.tencentcloudapi.com  ->  tokenhub.tencentmaas.com/v1
    auth       SecretId + SecretKey         ->  a bearer API key
    wire       Tencent SDK's signed POST    ->  OpenAI-compatible JSON

The API key is a DIFFERENT credential from TENCENTCLOUD_SECRET_ID/KEY: those
still authenticate (ASR continues to use them) but carry no authority on
TokenHub. Generate one in the TokenHub console.

The wire handling is shared with OpenAIProvider in openai_compat.py.
"""
from __future__ import annotations

from backend.agent.openai_compat import OpenAICompatibleProvider


class TokenHubProvider(OpenAICompatibleProvider):
    name = "tokenhub"
    label = "TokenHub"
    missing_key = (
        "TOKENHUB_API_KEY is not set — the TokenHub provider cannot "
        "authenticate. Generate a key at "
        "https://console.cloud.tencent.com/tokenhub/apikey and put it "
        "in .env. Note this is NOT TENCENTCLOUD_SECRET_ID/KEY, which "
        "carry no authority on TokenHub."
    )

    def __init__(self, settings):
        super().__init__(
            api_key=settings.tokenhub_api_key,
            base_url=settings.tokenhub_base_url,
            model=settings.tokenhub_model,
            timeout=settings.llm_timeout_s,
            temperature=settings.llm_temperature,
        )
