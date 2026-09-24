"""
Provider selection + provider-failure handling.

Two things are pinned here, neither needing a network or a key:

1. Which provider get_provider() returns, for every combination of explicit
   LLM_PROVIDER and available credentials. Pinning "hunyuan" matters for the
   demo: a missing key must fail loudly rather than silently serving stub
   output, which would look exactly like the model working.

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
    def __init__(self, *, tencent=False, provider="auto"):
        self.tencent_secret_id = "id" if tencent else ""
        self.tencent_secret_key = "key" if tencent else ""
        self.hunyuan_model = "hunyuan-functioncall"
        self.hunyuan_region = "ap-guangzhou"
        self.llm_provider = provider
        self.llm_temperature = 0.0
        self.llm_timeout_s = 30.0

    @property
    def has_credentials(self):
        return bool(self.tencent_secret_id and self.tencent_secret_key)


# --------------------------------------------------------------------------- selection
@pytest.mark.parametrize("tencent,expected", [
    (False, "stub"),      # no credentials -> deterministic stub
    (True,  "hunyuan"),
])
def test_auto_selection_follows_credentials(tencent, expected):
    assert get_provider(_Settings(tencent=tencent)).name == expected


@pytest.mark.parametrize("pinned", ["stub", "hunyuan"])
def test_explicit_provider_overrides_credentials(pinned):
    """LLM_PROVIDER pins the choice regardless of which credentials exist."""
    assert get_provider(_Settings(tencent=True, provider=pinned)).name == pinned


def test_explicit_provider_is_case_and_space_insensitive():
    assert get_provider(_Settings(tencent=True, provider="  Hunyuan ")).name == "hunyuan"


def test_pinned_hunyuan_without_credentials_does_not_fall_back_to_stub():
    """The demo-safety property: pinning hunyuan with no key must NOT quietly
    serve stub output. Selection still succeeds (construction needs no SDK or
    network); the failure surfaces at call time as a ProviderError -> 502,
    rather than as plausible-looking stub plans."""
    assert get_provider(_Settings(tencent=False, provider="hunyuan")).name == "hunyuan"


def test_unknown_provider_name_is_rejected():
    """A typo in LLM_PROVIDER must fail loudly, not silently fall back to the
    stub — silently serving stub output in live mode would look like the model
    working while it is not running at all."""
    with pytest.raises(UnknownProvider):
        get_provider(_Settings(tencent=True, provider="gpt4"))


def test_selection_never_imports_an_sdk():
    """Selecting the stub must not require the Tencent SDK — CI and the
    security suite run without credentials configured."""
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
