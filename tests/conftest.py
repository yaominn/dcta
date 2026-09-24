"""Shared fixtures: a running DCTA server on a free port.

Re-seeds the mock ledger (known balance, no passkeys) so every test starts from
the same clean slate, starts uvicorn with WEBAUTHN_EXPECTED_ORIGIN matching the
chosen port (localhost over HTTP is a secure context for WebAuthn), waits for
health, then tears down + re-seeds so the repo DB is left clean.

Used by the overlay XSS test and the WebAuthn e2e test so neither duplicates the
server-lifecycle boilerplate.
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

REPO = Path(__file__).resolve().parent.parent


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _wait_for_health(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        try:
            r = requests.get(url + "/api", timeout=2)
            if r.status_code == 200:
                return
            last = f"status {r.status_code}"
        except Exception as exc:
            last = str(exc)
        time.sleep(0.3)
    raise RuntimeError(f"server at {url} did not become healthy: {last}")


@pytest.fixture
def server_url():
    """A live DCTA server on a free port, clean-seeded before and after."""
    from backend.data.seed import seed

    seed()  # clean slate before the run

    port = _free_port()
    origin = f"http://localhost:{port}"
    env = {**os.environ,
           "WEBAUTHN_EXPECTED_ORIGIN": origin, "WEBAUTHN_RP_ID": "localhost"}
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app",
         "--host", "127.0.0.1", "--port", str(port), "--no-access-log"],
        cwd=str(REPO), env=env,
    )
    url = f"http://localhost:{port}"
    try:
        _wait_for_health(url)
        yield url
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        seed()  # restore clean slate after the run
