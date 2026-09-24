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
