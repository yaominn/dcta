"""
HunyuanProvider — Tencent Hunyuan chat completions. (brief Section 8)

Selected by get_provider() ONLY when settings.has_credentials is True. The SDK
import is lazy (inside complete()) so constructing/selecting this provider
never requires the SDK or the network — the test-suite exercises selection
without either.

Schema-constrained output is NOT delegated to the provider: even if a
provider-side structured-output mode exists, the parser still validates every
response against the frozen Pydantic schema and retries on rejection (brief 8:
"this carries the schema-constraint requirement regardless of provider-side
enforcement").
"""
from __future__ import annotations


class HunyuanProvider:
    name = "hunyuan"

    def __init__(self, settings):
        self._secret_id = settings.tencent_secret_id
        self._secret_key = settings.tencent_secret_key
        self._model = settings.hunyuan_model
        self._region = settings.hunyuan_region

    def complete(self, *, system: str, user: str) -> str:
        try:
            from tencentcloud.common import credential
            from tencentcloud.hunyuan.v20230901 import hunyuan_client, models
        except ImportError as exc:  # pragma: no cover - only hit in live mode without deps
            raise RuntimeError(
                "tencentcloud-sdk-python is required for the Hunyuan provider "
                "(pip install -r requirements.txt), or unset credentials to use the stub."
            ) from exc

        client = hunyuan_client.HunyuanClient(
            credential.Credential(self._secret_id, self._secret_key), self._region
        )
        req = models.ChatCompletionsRequest()
        req.Model = self._model
        req.Messages = [
            {"Role": "system", "Content": system},
            {"Role": "user", "Content": user},
        ]
        resp = client.ChatCompletions(req)
        return resp.Choices[0].Message.Content
