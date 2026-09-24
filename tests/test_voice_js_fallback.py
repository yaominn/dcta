"""
How frontend/voice.js reacts to each /api/transcribe answer.

The bug this pins: ANY refusal from server ASR (503/415/413) used to switch the
page to the browser tier for the rest of the session. One quiet clip — OpenAI
returning no text — was enough, and in Safari without Dictation the browser
tier does not work at all, so the mic went dead until a reload.

Now there are three distinct reactions, and which one fires is the contract:

  heard nothing (422 + no_speech)   -> onText("") : "I didn't catch that", STAY on tier 1
  cannot ever work here             -> onFallback sticky   (no provider; container)
  might work next press             -> onFallback transient (upstream error; too long)

Runs voice.js itself under Node (tests/js/voice_runner.js), so what is tested
is the file the browser loads, not a Python paraphrase of it.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tests" / "js" / "voice_runner.js"

pytestmark = pytest.mark.skipif(not shutil.which("node"), reason="node is not installed")


@pytest.fixture(scope="module")
def reactions():
    out = subprocess.run(["node", str(RUNNER)], capture_output=True, text=True,
                         timeout=60, check=True)
    return json.loads(out.stdout)


def test_a_transcript_is_delivered(reactions):
    assert reactions["ok"] == [["text", "pay mom fifty dollars", "openai"]]


def test_silence_asks_again_and_does_not_abandon_server_asr(reactions):
    """The regression. Empty text reaches onText, which the page renders as
    "I didn't catch that" — never onFallback, which would switch tiers."""
    assert reactions["no_speech"] == [["text", "", "server"]]


def test_a_malformed_request_422_is_an_error_not_silence(reactions):
    """422 is also FastAPI's validation answer. Only the no_speech flag means a
    quiet room; anything else is a bug and must surface as one."""
    assert reactions["malformed_422"] == [["error", "transcription failed: 422"]]


def test_no_provider_configured_is_sticky(reactions):
    """Retrying cannot help, so stop recording audio the server will refuse."""
    assert reactions["unconfigured_503"] == [["fallback", True]]


def test_an_unsupported_container_is_sticky(reactions):
    """This browser will produce the same container on every press."""
    assert reactions["container_415"] == [["fallback", True]]


def test_an_upstream_failure_is_transient(reactions):
    """A 429 or a timeout from a configured provider may clear by the next press."""
    assert reactions["upstream_503"] == [["fallback", False]]


def test_an_over_long_clip_is_transient(reactions):
    """The next utterance may well be short enough."""
    assert reactions["too_long_413"] == [["fallback", False]]
