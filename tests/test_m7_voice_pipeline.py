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
import json

import pytest
from fastapi.testclient import TestClient

from backend.asr import ASRUnavailable, UnavailableASR, get_asr_provider
from backend.data.seed import seed
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


# --------------------------------------------------------------------------- M7 review additions
def test_unsupported_container_is_refused_before_it_is_forwarded():
    """Chrome's MediaRecorder produces audio/webm;codecs=opus, which shares a
    codec but NOT a container with the documented ogg-opus. The browser now
    reports what it actually recorded, and we refuse it HERE rather than paying
    for an upstream call that cannot succeed — 415, naming the fallback tier."""
    from backend.asr import SUPPORTED_VOICE_FORMATS
    assert "webm" not in SUPPORTED_VOICE_FORMATS

    client = TestClient(app)
    r = client.post("/api/transcribe?fmt=webm",
                    files={"audio": ("utterance", b"\x1aE\xdf\xa3fake-webm", "audio/webm")})
    assert r.status_code == 415
    detail = r.json()["detail"]
    assert detail["fallback"] == "webspeech"
    assert "webm" in detail["error"]


def test_a_caller_supplied_format_cannot_reach_the_upstream_request():
    """`fmt` is browser-supplied input that would otherwise go straight into a
    paid upstream call as VoiceFormat. Validated on our side, like the LLM's
    output — not trusted because it came from our own page."""
    client = TestClient(app)
    r = client.post("/api/transcribe?fmt=../../etc/passwd",
                    files={"audio": ("utterance", b"audio-bytes", "audio/wav")})
    assert r.status_code == 415


def test_oversized_audio_is_refused():
    """Upstream caps a request at ~60s / 5MB, so a larger body cannot succeed."""
    from backend.asr import MAX_AUDIO_BYTES
    client = TestClient(app)
    r = client.post("/api/transcribe?fmt=wav",
                    files={"audio": ("utterance", b"\x00" * (MAX_AUDIO_BYTES + 1),
                                     "audio/wav")})
    assert r.status_code == 413
    assert r.json()["detail"]["fallback"] == "webspeech"


def test_a_supported_container_reaches_the_provider():
    """The guard must not swallow a legitimate request: a documented container
    gets through to the provider, which (with no credentials) answers 503."""
    client = TestClient(app)
    r = client.post("/api/transcribe?fmt=wav",
                    files={"audio": ("utterance", b"RIFFfake-wav", "audio/wav")})
    assert r.status_code == 503                      # reached the provider
    assert r.json()["detail"]["fallback"] == "webspeech"


def test_the_utterance_is_recorded_in_the_audit_chain():
    """AuditEntryType.TRANSCRIPT was reserved for M7 and nothing emitted it, so
    the chain had no record of the utterance every later entry derives from.
    The signed ResolvedPlan binds transcript_hash; this is what that hash
    corresponds to."""
    from backend.audit.canonical import hash_transcript
    # reset_audit: verify_chain() reports the FIRST break, so a dev DB whose
    # chain an earlier tamper demo broke would fail this for the wrong reason.
    seed(reset_audit=True)
    client = TestClient(app)
    transcript = "pay mom five hundred then buy aapl with the rest"
    draft = client.post("/api/drafts", json={"transcript": transcript}).json()
    assert draft["status"] == "ready"

    entries = client.get("/api/audit/chain").json()["entries"]
    transcripts = [json.loads(e["payload"]) for e in entries
                   if e["entry_type"] == "TRANSCRIPT"]
    mine = [t for t in transcripts if t["draft_id"] == draft["draft_id"]]
    assert len(mine) == 1, "the utterance was not recorded in the audit chain"
    assert mine[0]["transcript_hash"] == hash_transcript(transcript)
    # the same hash the user signs, so the payload and the log correspond
    assert mine[0]["transcript_hash"] == draft["resolved_plan"]["transcript_hash"]
    assert client.get("/api/audit/verify").json()["ok"] is True


def test_the_audit_log_stores_the_hash_not_the_words():
    """A microphone catches more than the instruction. The hash is what the
    signature binds, so it is what non-repudiation needs; the raw utterance
    would put spoken details into append-only storage that is deliberately hard
    to redact."""
    seed()
    client = TestClient(app)
    secret = "pay mom five hundred my passport number is X1234567Z"
    client.post("/api/drafts", json={"transcript": secret})
    entries = client.get("/api/audit/chain").json()["entries"]
    blob = json.dumps(entries)
    assert "X1234567Z" not in blob
    assert "passport" not in blob
