"""
Shared wire code for OpenAI-compatible chat completions.

TokenHub and OpenAI speak the same protocol — POST {base}/chat/completions
with a bearer key, {"choices": [{"message": {"content": ...}}]} back — so the
HTTP handling lives here once. Each provider supplies only its endpoint, its
key, and what to tell someone whose key is missing.

stdlib urllib, not an SDK: the wire format is plain JSON over HTTPS, and the
security suite's import-boundary test is happier with one fewer transitive
dependency in backend/agent/.

Schema-constrained output is NOT delegated to the provider: the parser still
validates every response against the frozen Pydantic schema and retries on
rejection (brief 8: "this carries the schema-constraint requirement regardless
of provider-side enforcement").
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

from backend.agent.errors import ProviderError


class OpenAICompatibleProvider:
    name: str           # the LLM_PROVIDER value that selects this provider
    label: str          # human name for error messages
    missing_key: str    # the ProviderError text when no key is configured

    def __init__(self, *, api_key: str, base_url: str, model: str,
                 timeout: float, temperature: float):
        self._api_key = api_key
        self._base_url = base_url.rstrip("/")
        self._model = model
        self._timeout = timeout
        self._temperature = temperature

    def complete(self, *, system: str, user: str) -> str:
        # Checked at call time, not construction: selection must stay free of
        # network and credentials so the test-suite can exercise it, and so a
        # pinned-but-unkeyed provider fails LOUDLY here rather than silently
        # degrading to stub output that looks like the model working.
        if not self._api_key:
            raise ProviderError(self.missing_key)

        body = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            # Structured extraction, not prose: near-zero so the same
            # transcript yields the same plan and the retry budget is spent on
            # real ambiguity rather than sampling noise.
            "temperature": self._temperature,
            "stream": False,   # explicit: a streamed response has no .choices
        }).encode("utf-8")

        req = urllib.request.Request(
            f"{self._base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json",
            },
        )

        try:
            # A hung upstream call must not hold the HTTP request open.
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            # The response body carries the actual reason (bad key, retired
            # model, quota, unsupported parameter). Surfacing only "HTTP 401"
            # would send someone hunting the wrong problem, which is exactly
            # how the dead-model outage stayed invisible behind the stub.
            try:
                detail = exc.read().decode("utf-8", "replace")[:500]
            except Exception:
                detail = ""
            raise ProviderError(
                f"{self.label} request failed: HTTP {exc.code} {exc.reason}: {detail}"
            ) from exc
        except Exception as exc:    # timeout, DNS, TLS, malformed JSON
            raise ProviderError(
                f"{self.label} request failed: {type(exc).__name__}: {exc}"
            ) from exc

        # An OpenAI-shaped error body can arrive with HTTP 200.
        if isinstance(payload.get("error"), dict):
            raise ProviderError(f"{self.label} returned an error: {payload['error']}")

        choices = payload.get("choices")
        if not choices:
            raise ProviderError(f"{self.label} returned no choices")
        content = (choices[0].get("message") or {}).get("content")
        if not content:
            raise ProviderError(f"{self.label} returned an empty message")
        return content
