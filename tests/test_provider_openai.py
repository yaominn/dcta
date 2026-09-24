"""
OpenAI provider: selection precedence, loud failure, and the request it sends.

The wire handling (error bodies, empty choices, timeouts) is shared with
TokenHub in openai_compat.py and pinned in test_provider_tokenhub.py. What is
specific to OpenAI — and pinned here — is how it is selected, what it says
when its key is missing, and where the request goes.

No network and no key: the HTTP call is stubbed at urllib.
"""
from __future__ import annotations

import json
import urllib.request

import pytest

from backend.agent.errors import ProviderError
from backend.agent.openai_provider import OpenAIProvider
from backend.agent.provider import UnknownProvider, get_provider


class _Settings:
    """Minimal stand-in for backend.config.Settings."""
    def __init__(self, *, openai_key="", tokenhub_key="", tencent=False, provider="auto"):
        self.tencent_secret_id = "id" if tencent else ""
        self.tencent_secret_key = "key" if tencent else ""
        self.tokenhub_api_key = tokenhub_key
        self.tokenhub_base_url = "https://tokenhub.example/v1"
        self.tokenhub_model = "hy3-preview"
        self.openai_api_key = openai_key
        self.openai_base_url = "https://api.openai.com/v1"
        self.openai_model = "gpt-4.1-mini"
        self.hunyuan_model = "hunyuan-functioncall"
        self.hunyuan_region = "ap-guangzhou"
        self.llm_provider = provider
        self.llm_temperature = 0.0
        self.llm_timeout_s = 30.0

    @property
    def has_credentials(self):
        return bool(self.tencent_secret_id and self.tencent_secret_key)


# --------------------------------------------------------------------------- selection
def test_pinned_openai_is_selected():
    assert get_provider(_Settings(provider="openai")).name == "openai"


def test_pinned_openai_is_case_and_space_insensitive():
    assert get_provider(_Settings(provider="  OpenAI ")).name == "openai"


def test_pinned_openai_wins_even_when_tokenhub_is_keyed():
    """LLM_PROVIDER pins the choice regardless of which credentials exist."""
    assert get_provider(_Settings(openai_key="sk-o", tokenhub_key="sk-t",
                                  provider="openai")).name == "openai"


def test_auto_selects_openai_when_it_is_the_only_llm_key():
    assert get_provider(_Settings(openai_key="sk-o")).name == "openai"


def test_auto_selects_openai_over_the_decommissioned_hunyuan_path():
    """Tencent creds present for ASR must not drag the LLM onto a dead API."""
    assert get_provider(_Settings(openai_key="sk-o", tencent=True)).name == "openai"


def test_auto_prefers_tokenhub_when_both_llm_keys_exist():
    """Documented precedence; pin LLM_PROVIDER to choose otherwise."""
    assert get_provider(_Settings(openai_key="sk-o", tokenhub_key="sk-t")).name == "tokenhub"


def test_gpt_is_not_an_alias():
    """One name per provider. A near-miss must fail loudly, not guess."""
    with pytest.raises(UnknownProvider):
        get_provider(_Settings(provider="gpt"))


# --------------------------------------------------------------------------- loud failure
def test_missing_key_fails_loudly_and_names_the_variable():
    with pytest.raises(ProviderError) as exc:
        OpenAIProvider(_Settings(provider="openai")).complete(system="s", user="u")
    assert "OPENAI_API_KEY" in str(exc.value)


def test_missing_openai_key_is_not_masked_by_a_present_tokenhub_key():
    """Pinned to OpenAI with only a TokenHub key: fail, don't quietly switch."""
    p = get_provider(_Settings(tokenhub_key="sk-t", provider="openai"))
    with pytest.raises(ProviderError) as exc:
        p.complete(system="s", user="u")
    assert "OPENAI_API_KEY" in str(exc.value)


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


def test_request_goes_to_openai_with_the_bearer_key_and_model(monkeypatch):
    seen = {}

    def fake_urlopen(req, timeout=None):
        seen["request"], seen["body"] = req, json.loads(req.data.decode())
        return _FakeResponse({"choices": [{"message": {"content": "ok"}}]})
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    out = OpenAIProvider(_Settings(openai_key="sk-o")).complete(system="SYS", user="USR")

    assert out == "ok"
    assert seen["request"].full_url == "https://api.openai.com/v1/chat/completions"
    assert seen["request"].get_header("Authorization") == "Bearer sk-o"
    assert seen["body"]["model"] == "gpt-4.1-mini"
    assert seen["body"]["temperature"] == 0.0


def test_errors_are_labelled_openai_not_tokenhub(monkeypatch):
    """Shared wire code must not tell someone debugging GPT to go fix TokenHub."""
    def fake_urlopen(req, timeout=None):
        raise TimeoutError("timed out")
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(ProviderError) as exc:
        OpenAIProvider(_Settings(openai_key="sk-o")).complete(system="s", user="u")
    assert str(exc.value).startswith("OpenAI request failed")
