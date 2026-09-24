"""
Provider selection + provider-failure handling.

Two things are pinned here, neither needing a network or a key:

1. Which provider get_provider() returns, for every combination of explicit
   LLM_PROVIDER and available credentials. Hunyuan wins `auto` whenever its
   credentials exist — the hackathon judges "use of AI tools" and the tracks
   are built on Tencent Cloud services. OpenAI exists so development is not
   blocked while that access is pending.

2. That a provider FAILURE is retried and then reported as an upstream problem
   (502), never as a bad plan (422) and never as an unhandled 500. Previously
   provider.complete() sat outside the retry loop's try block, so a bad key or
   a rate limit escaped the loop entirely and surfaced as a stack trace.
"""
from __future__ import annotations

import pytest

from backend.agent import ProviderError, ProviderUnavailable, parse_transcript
from backend.agent.provider import UnknownProvider, get_provider
from backend.agent.stub import StubProvider


class _Settings:
    """Minimal stand-in for backend.config.Settings."""
    def __init__(self, *, tencent=False, openai=False, provider="auto"):
        self.tencent_secret_id = "id" if tencent else ""
        self.tencent_secret_key = "key" if tencent else ""
        self.openai_api_key = "sk-test" if openai else ""
        self.openai_model = "gpt-4o-mini"
        self.hunyuan_model = "hunyuan-functioncall"
        self.hunyuan_region = "ap-guangzhou"
        self.llm_provider = provider
        self.llm_temperature = 0.0
        self.llm_timeout_s = 30.0

    @property
    def has_credentials(self):
        return bool(self.tencent_secret_id and self.tencent_secret_key)

    @property
    def has_openai_credentials(self):
        return bool(self.openai_api_key)


# --------------------------------------------------------------------------- selection
@pytest.mark.parametrize("tencent,openai,expected", [
    (False, False, "stub"),      # no keys at all -> deterministic stub
    (True,  False, "hunyuan"),
    (False, True,  "openai"),
    (True,  True,  "hunyuan"),   # BOTH present -> Tencent wins (judged dimension)
])
def test_auto_selection_prefers_hunyuan(tencent, openai, expected):
    assert get_provider(_Settings(tencent=tencent, openai=openai)).name == expected


@pytest.mark.parametrize("pinned", ["stub", "hunyuan", "openai"])
def test_explicit_provider_overrides_credentials(pinned):
    """LLM_PROVIDER pins the choice even when other credentials are present."""
    s = _Settings(tencent=True, openai=True, provider=pinned)
    assert get_provider(s).name == pinned


def test_explicit_provider_is_case_and_space_insensitive():
    assert get_provider(_Settings(openai=True, provider="  OpenAI ")).name == "openai"


def test_unknown_provider_name_is_rejected():
    """A typo in LLM_PROVIDER must fail loudly, not silently fall back to the
    stub — silently serving stub output in live mode would look like the model
    working while it is not running at all."""
    with pytest.raises(UnknownProvider):
        get_provider(_Settings(openai=True, provider="gpt4"))


def test_selection_never_imports_an_sdk():
    """Selecting the stub must not require the Tencent or OpenAI SDKs — CI and
    the security suite run without either configured."""
    assert isinstance(get_provider(_Settings()), StubProvider)


# --------------------------------------------------------------------------- provider failure
class _AlwaysFails:
    name = "always-fails"

    def __init__(self):
        self.calls = 0

    def complete(self, *, system, user):
        self.calls += 1
        raise ProviderError("simulated: 401 invalid api key")


class _FailsThenWorks:
    """Fails once (a transient blip), then returns what the stub would."""
    name = "flaky"

    def __init__(self):
        self.calls = 0
        self._stub = StubProvider()

    def complete(self, *, system, user):
        self.calls += 1
        if self.calls == 1:
            raise ProviderError("simulated: timeout")
        return self._stub.complete(system=system, user=user)


def _ctx():
    from backend.agent import build_context
    return build_context(
        payees=[{"id": "payee_17", "nickname": "Mom",
                 "legal_name": "Jane Tan", "last4": "3310"}],
        billers=[],
        accounts=[{"id": "acct_savings", "type": "savings", "balance": 842050}],
        equities=[{"ticker": "AAPL", "price": 24150}],
    )


def test_provider_failure_is_retried_then_reported_as_unavailable():
    """Every attempt fails -> ProviderUnavailable (mapped to 502), NOT
    ParseFailure and not an unhandled exception."""
    p = _AlwaysFails()
    with pytest.raises(ProviderUnavailable) as exc:
        parse_transcript("pay mom five hundred", provider=p, context=_ctx())
    assert p.calls > 1, "a transient provider failure must be retried"
    assert all("provider unavailable" in e for e in exc.value.errors)


def test_transient_provider_failure_recovers():
    """One blip then success: the retry loop absorbs it and returns a plan."""
    p = _FailsThenWorks()
    plan = parse_transcript("pay mom five hundred", provider=p, context=_ctx())
    assert p.calls == 2
    assert plan is not None
