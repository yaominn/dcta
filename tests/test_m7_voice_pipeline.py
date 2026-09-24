"""
M7: speech-to-text tiers + the end-to-end draft pipeline.

Two things are pinned here:

1. The ASR degradation path. With no Tencent credentials, /api/transcribe must
   say so in a way the browser can act on — 503 with {"fallback": "webspeech"} —
   rather than returning an empty transcript (which looks like the user said
   nothing) or a canned one (which looks like recognition working while nothing
   ran).

2. /api/draft, the first place parse -> resolve -> validate are wired together.
   Its three outcomes must be distinguishable by a caller: a signable draft, a
   clarifying question, or a validator freeze.
"""
from __future__ import annotations

import io

import pytest
from fastapi.testclient import TestClient

from backend.asr import ASRUnavailable, UnavailableASR, get_asr_provider
from backend.config import settings
from backend.main import app

client = TestClient(app)


# --------------------------------------------------------------------------- ASR tiers
def test_no_credentials_selects_the_unavailable_provider():
    """Tier 1 is only selected when credentials exist. No keys -> no Tencent."""
    assert isinstance(get_asr_provider(settings), UnavailableASR)


def test_unavailable_provider_raises_rather_than_faking_a_transcript():
    """It must NOT return "" (looks like silence) or a canned string (looks like
    recognition working). Saying so is the only honest option."""
    with pytest.raises(ASRUnavailable):
        UnavailableASR().transcribe(b"audio", fmt="mp3")


def test_transcribe_reports_503_and_names_the_fallback_tier():
    """The browser reads `fallback` to decide which tier to drop to. A 503 here
    is the designed degradation path, not a product failure."""
    r = client.post("/api/transcribe",
                    files={"audio": ("u.webm", io.BytesIO(b"\x00\x01"), "audio/webm")})
    assert r.status_code == 503
    detail = r.json()["detail"]
    assert detail["fallback"] == "webspeech"
    assert detail["provider"] == "unavailable"


def test_transcribe_rejects_an_empty_upload():
    """An empty body is a client bug, not a degradation case — 400, not 503."""
    r = client.post("/api/transcribe",
                    files={"audio": ("u.webm", io.BytesIO(b""), "audio/webm")})
    assert r.status_code == 400


# --------------------------------------------------------------------------- the pipeline
def _draft(transcript: str, **kw):
    return client.post("/api/draft", json={"transcript": transcript,
                                           "user_id": kw.pop("user_id", "u_alice"), **kw})


def test_draft_returns_a_signable_plan():
    r = _draft("transfer five hundred from my savings to mom")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "draft"
    leg = body["plan"]["plan"][0]
    assert leg["payee_display"] == "Mom ··3310"
    assert leg["amount_cents"] == 50000
    assert body["validation"]["verdict"] == "pass"


def test_draft_asks_rather_than_guessing_an_unnamed_account():
    """The system refuses to guess which account an unspecified payment leaves
    from. Asking is the correct outcome, and it is a 200 — needing to clarify is
    a normal conversational result, not an error."""
    r = _draft("pay mom five hundred")
    assert r.status_code == 200
    assert r.json()["status"] == "clarify"


def test_draft_disambiguates_two_johns():
    r = _draft("send fifty to john from savings")
    body = r.json()
    assert body["status"] == "clarify"
    assert len(body["choices"]) == 2
    assert {c["display"] for c in body["choices"]} == {"John ··4521", "John ··8892"}


def test_clarify_resumes_via_answers():
    """The round trip the UI performs: ask, the user picks, resubmit."""
    first = _draft("send fifty to john from savings").json()
    second = _draft("send fifty to john from savings",
                    answers={first["field"]: "payee_22"}).json()
    assert second["status"] == "draft"
    assert second["plan"]["plan"][0]["payee_id"] == "payee_22"


def test_empty_utterance_asks_and_builds_no_plan():
    body = _draft("mmmm").json()
    assert body["status"] == "clarify"
    assert "plan" not in body
