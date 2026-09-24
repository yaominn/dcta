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


# --------------------------------------------------------------------------- the pipeline, from a voice/typed utterance
# These exercise the same server-side draft API the overlay uses (/api/drafts).
# M7 owns the CLIENT tiers above; the draft resource itself is M8's.
def _draft(transcript: str, user_id: str = "u_alice"):
    return client.post("/api/drafts", json={"transcript": transcript, "user_id": user_id})


def test_utterance_produces_a_signable_draft():
    r = _draft("transfer five hundred from my savings to mom")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ready"
    leg = body["resolved_plan"]["plan"][0]
    assert leg["payee_display"] == "Mom ··3310"
    assert leg["amount_cents"] == 50000


def test_ambiguous_payee_asks_rather_than_guessing():
    body = _draft("send fifty to john from savings").json()
    assert body["status"] == "clarify"
    assert {c["display"] for c in body["choices"]} == {"John ··4521", "John ··8892"}


def test_clarify_round_trip_the_ui_performs():
    """Ask -> the user picks -> the draft completes. The client sends only
    {field, choice_id} for a draft_id; it never holds or returns the plan."""
    first = _draft("send fifty to john from savings").json()
    second = client.post(
        f"/api/drafts/{first['draft_id']}/clarify",
        json={"field": first["field"], "choice_id": "payee_22"},
    ).json()
    assert second["status"] == "ready"
    assert second["resolved_plan"]["plan"][0]["payee_id"] == "payee_22"


def test_unparseable_utterance_asks_and_builds_no_plan():
    body = _draft("mmmm").json()
    assert body["status"] == "clarify"
    assert body.get("resolved_plan") is None


def test_every_outcome_is_http_200():
    """clarify and blocked/frozen are successful requests whose ANSWER is "no".
    The HTTP layer reports whether we could respond; the body reports what the
    answer was. A client that only checks the status code must not mistake a
    clarification for a failure."""
    for t in ["transfer five hundred from my savings to mom",
              "send fifty to john from savings",
              "mmmm"]:
        assert _draft(t).status_code == 200
