"""
TokenHub provider: selection, loud failure, and response handling.

Context for why this file exists: the legacy hunyuan.tencentcloudapi.com
ChatCompletions API was decommissioned (every model answers "该模型已下线") while
.env had LLM_PROVIDER=stub, so the pipeline served stub plans and *looked*
fine. Two defects, one symptom. What is pinned here is that neither can recur
silently — a missing key or a dead endpoint must surface as a ProviderError
(-> 502), never as plausible stub output.

No network and no key: the HTTP call is stubbed at urllib.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from backend.agent.errors import ProviderError
from backend.agent.provider import get_provider
from backend.agent.stub import StubProvider
from backend.agent.tokenhub import TokenHubProvider


class _Settings:
    """Minimal stand-in for backend.config.Settings."""
    def __init__(self, *, tokenhub_key="", tencent=False, provider="auto"):
        self.tencent_secret_id = "id" if tencent else ""
        self.tencent_secret_key = "key" if tencent else ""
        self.tokenhub_api_key = tokenhub_key
        self.tokenhub_base_url = "https://tokenhub.example/v1"
        self.tokenhub_model = "hy3-preview"
        self.hunyuan_model = "hunyuan-functioncall"
        self.hunyuan_region = "ap-guangzhou"
        self.llm_provider = provider
        self.llm_temperature = 0.0
        self.llm_timeout_s = 30.0

    @property
    def has_credentials(self):
        return bool(self.tencent_secret_id and self.tencent_secret_key)


# --------------------------------------------------------------------------- selection
def test_pinned_tokenhub_is_selected():
    assert get_provider(_Settings(provider="tokenhub")).name == "tokenhub"


def test_auto_prefers_tokenhub_when_its_key_exists():
    assert get_provider(_Settings(tokenhub_key="sk-x")).name == "tokenhub"


def test_auto_prefers_tokenhub_over_the_decommissioned_hunyuan_path():
    """Both credentials present: the live endpoint wins. Selecting Hunyuan here
    would spend the entire retry budget discovering it is offline."""
    assert get_provider(_Settings(tokenhub_key="sk-x", tencent=True)).name == "tokenhub"


def test_auto_falls_back_to_hunyuan_when_only_tencent_creds_exist():
    """Unchanged legacy behaviour — a self-hosted endpoint still reachable."""
    assert get_provider(_Settings(tencent=True)).name == "hunyuan"


def test_auto_with_no_credentials_is_the_stub():
    assert isinstance(get_provider(_Settings()), StubProvider)


def test_selection_never_requires_a_key_or_network():
    """Construction must stay free of both, so the failure surfaces at call
    time as a 502 rather than at import/selection time as a crash."""
    assert get_provider(_Settings(provider="tokenhub")).name == "tokenhub"


# --------------------------------------------------------------------------- loud failure
def test_missing_api_key_fails_loudly_and_names_the_variable():
    """The regression that started this: a pinned live provider with no key
    must raise, NOT quietly serve stub output that looks like the model."""
    with pytest.raises(ProviderError) as exc:
        TokenHubProvider(_Settings(provider="tokenhub")).complete(system="s", user="u")
    assert "TOKENHUB_API_KEY" in str(exc.value)


def test_missing_key_message_distinguishes_the_two_credentials():
    """Someone with working ASR will reasonably assume the LLM is keyed too."""
    with pytest.raises(ProviderError) as exc:
        TokenHubProvider(_Settings(tencent=True)).complete(system="s", user="u")
    assert "TENCENTCLOUD_SECRET_ID" in str(exc.value)


# --------------------------------------------------------------------------- the wire
class _FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.fixture
def capture(monkeypatch):
    """Intercept the HTTP call; hand back a canned payload, keep the request."""
    seen = {}

    def _install(payload):
        def fake_urlopen(req, timeout=None):
            seen["request"] = req
            seen["timeout"] = timeout
            seen["body"] = json.loads(req.data.decode())
            return _FakeResponse(payload)
        monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
        return seen

    return _install


def _provider():
    return TokenHubProvider(_Settings(tokenhub_key="sk-test"))


def test_successful_completion_returns_the_message_content(capture):
    capture({"choices": [{"message": {"content": "hello"}}]})
    assert _provider().complete(system="s", user="u") == "hello"


def test_request_is_openai_shaped_and_carries_the_bearer_key(capture):
    seen = capture({"choices": [{"message": {"content": "ok"}}]})
    _provider().complete(system="SYS", user="USR")
    req, body = seen["request"], seen["body"]

    assert req.full_url == "https://tokenhub.example/v1/chat/completions"
    assert req.get_method() == "POST"
    assert req.get_header("Authorization") == "Bearer sk-test"
    assert body["model"] == "hy3-preview"
    assert body["messages"] == [
        {"role": "system", "content": "SYS"},
        {"role": "user", "content": "USR"},
    ]
    # Structured extraction, not prose: sampling noise would waste the retry
    # budget that exists for real ambiguity.
    assert body["temperature"] == 0.0
    # A streamed response has no .choices — this parser cannot read one.
    assert body["stream"] is False
    # A hung upstream call must not hold the HTTP request open.
    assert seen["timeout"] == 30.0


def test_base_url_trailing_slash_does_not_double_up(capture):
    seen = capture({"choices": [{"message": {"content": "ok"}}]})
    s = _Settings(tokenhub_key="sk-test")
    s.tokenhub_base_url = "https://tokenhub.example/v1/"
    TokenHubProvider(s).complete(system="s", user="u")
    assert seen["request"].full_url == "https://tokenhub.example/v1/chat/completions"


@pytest.mark.parametrize("payload,reason", [
    ({"choices": []},                                   "no choices"),
    ({},                                                "missing choices"),
    ({"choices": [{"message": {"content": ""}}]},       "empty content"),
    ({"choices": [{"message": {}}]},                    "no content key"),
])
def test_unusable_responses_raise_provider_error(capture, payload, reason):
    capture(payload)
    with pytest.raises(ProviderError):
        _provider().complete(system="s", user="u")


def test_openai_shaped_error_body_with_http_200_is_not_treated_as_success(capture):
    """An error delivered with a 200 must not slip through as model output."""
    capture({"error": {"message": "model has been taken offline", "code": 2000}})
    with pytest.raises(ProviderError) as exc:
        _provider().complete(system="s", user="u")
    assert "taken offline" in str(exc.value)


def test_http_error_surfaces_the_body_not_just_the_status(monkeypatch):
    """"HTTP 401" alone sends people hunting the wrong problem — which is how
    the dead-model outage stayed invisible behind the stub."""
    def fake_urlopen(req, timeout=None):
        raise urllib.error.HTTPError(
            req.full_url, 401, "Unauthorized", {},
            __import__("io").BytesIO(b'{"error":{"message":"invalid api key"}}'))
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ProviderError) as exc:
        _provider().complete(system="s", user="u")
    assert "401" in str(exc.value)
    assert "invalid api key" in str(exc.value)


def test_transport_failure_is_a_provider_error_not_a_raw_exception(monkeypatch):
    """Retried and mapped to 502 by the parser — only if it is a ProviderError."""
    def fake_urlopen(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ProviderError):
        _provider().complete(system="s", user="u")
