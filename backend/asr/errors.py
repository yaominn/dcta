"""ASR-layer error types."""
from __future__ import annotations


class ASRUnavailable(RuntimeError):
    """Speech-to-text could not be performed on the server.

    Raised when no Tencent credentials are configured, or the upstream call
    failed. It is deliberately NOT an error condition for the product: the
    browser degrades to the Web Speech API, and text input always works. The
    endpoint reports 503 with a machine-readable `fallback` so the client knows
    which tier to drop to, rather than surfacing a failure to the user.
    """


class ASRNoSpeech(ASRUnavailable):
    """The provider ran and recognised nothing — silence, noise, a clip cut off.

    A subclass so every existing `except ASRUnavailable` still holds, but the
    endpoint catches it FIRST and answers 422, not 503. The difference is the
    whole point: 503 tells the browser "this tier is down, drop to the next",
    and the page then stops trying server ASR. A quiet clip is not an outage —
    treating it as one turned a single mis-tap into a mic that stayed on the
    browser tier (dead in Safari without Dictation) for the rest of the session.
    """
