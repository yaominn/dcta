"""
Request traces for the /data page: what the model was told, what it said, and
what every deterministic step then did with it.

One trace per request (keyed by draft_id), as an ordered list of events:

    request -> parse (the exact prompts + raw replies) -> resolve -> policy
            -> validate -> step_up -> answer / confirm / nonce -> gateway

It exists to make the core claim inspectable rather than asserted: the LLM's
entire contribution is one JSON draft, and everything after it is code and the
user's signature.

# MOCK / demo only. Traces hold the user's transcript, so this is an in-memory
  ring buffer (last MAX_TRACES requests, gone on restart) and /data would not
  exist in a deployment — same status as /api/auth/mock-sign and /phone. The
  one-time code is never recorded here; it exists only on the phone.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from threading import Lock
from typing import Any

MAX_TRACES = 50


class RecordingProvider:
    """Wraps an LLM provider and records every call verbatim: the system
    prompt, the user prompt, the raw reply (or the error) and how long it took.
    Otherwise transparent — `name` and any other attribute pass through, so the
    parser and validator behave exactly as they would unwrapped."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.calls: list[dict] = []

    def complete(self, *, system: str, user: str) -> str:
        t0 = time.perf_counter()
        call = {"system": system, "user": user}
        try:
            out = self._inner.complete(system=system, user=user)
            call["output"] = out
            return out
        except Exception as exc:
            call["error"] = f"{type(exc).__name__}: {exc}"
            raise
        finally:
            call["ms"] = round((time.perf_counter() - t0) * 1000)
            self.calls.append(call)

    def __getattr__(self, item):
        return getattr(self._inner, item)


class TraceStore:
    def __init__(self, max_traces: int = MAX_TRACES):
        self._max = max_traces
        self._traces: "OrderedDict[str, dict]" = OrderedDict()
        self._lock = Lock()

    def start(self, trace_id: str, *, transcript: str, route: str, user_id: str) -> None:
        with self._lock:
            self._traces[trace_id] = {"id": trace_id, "started_at": time.time(),
                                      "transcript": transcript, "route": route,
                                      "user_id": user_id, "events": []}
            self._traces.move_to_end(trace_id)
            while len(self._traces) > self._max:
                self._traces.popitem(last=False)

    def event(self, trace_id: str, step: str, **data) -> None:
        """Append to a trace. Unknown ids (a hand-assembled gateway call for a
        draft that never went through /api/drafts) get a trace of their own, so
        they are visible rather than silently dropped."""
        with self._lock:
            tr = self._traces.get(trace_id)
            if tr is None:
                tr = {"id": trace_id, "started_at": time.time(), "transcript": None,
                      "route": "direct", "user_id": None, "events": []}
                self._traces[trace_id] = tr
            tr["events"].append({"step": step, "at": time.time(), **data})
            self._traces.move_to_end(trace_id)
            while len(self._traces) > self._max:
                self._traces.popitem(last=False)

    def recent(self) -> list[dict]:
        with self._lock:
            return list(reversed(self._traces.values()))

    def clear(self) -> None:
        with self._lock:
            self._traces.clear()
