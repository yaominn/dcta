"""Cross-language canonicalization acceptance test (M2 binding constraint).

The JS canonicalizer (frontend/canonical.js) — the SAME one the browser overlay
uses to recompute payload_hash from the rendered ResolvedPlan — must produce a
byte-identical canonical string and hash to Python's canonical_json +
payload_hash. This is the "do not skip this one" test from the M2 review:

a ResolvedPlan whose payee_display contains non-ASCII (accented + CJK).
Unicode escaping is exactly where two independent canonicalizers drift, and
ASCII-only test data would never surface it.

payee_display is built by the resolver from OUR database (user nickname + last
4) — never from an LLM and never from a third-party legal-name/reference field
(those are attacker-controllable, and this string renders on the one surface we
told the user to trust). The M4 resolver carries that forward; this test pins
the canonicalization contract the resolver's output must satisfy.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from backend.audit.canonical import canonical_json, payload_hash
from backend.models.schemas import ResolvedPlan, ResolvedTransfer

REPO = Path(__file__).resolve().parents[1]
RUNNER = REPO / "tests" / "js" / "canonical_runner.js"

# Node.js is not a pip dependency, so `pip install -r requirements.txt` cannot
# supply it. Skip (not error) on a clean checkout without Node so the suite is
# green; the README "Test prerequisites" section installs Node so this test
# actually RUNS — a skip guard alone would let the "do not skip this one" test
# silently never run anywhere, which is worse than failing loudly.
pytestmark = pytest.mark.skipif(
    not shutil.which("node"),
    reason="Node.js not found; required for the cross-language canonicalizer "
           "test (see README Test prerequisites).",
)


def _js_hash(plan_dict: dict) -> tuple[str, str]:
    """Pipe the plan to the Node runner; return (canonical, hash) it computed."""
    proc = subprocess.run(
        ["node", str(RUNNER)],
        input=json.dumps(plan_dict).encode("utf-8"),
        capture_output=True,
        check=True,
    )
    out = json.loads(proc.stdout)
    return out["canonical"], out["hash"]


def _plan() -> ResolvedPlan:
    # non-ASCII payee_display: accented (Müller) + CJK (张三). created_at/expires_at
    # use a valid 300s window (the schema cap) so the plan constructs.
    return ResolvedPlan(
        schema_version="1",
        draft_id="d_unicode",
        plan=[
            ResolvedTransfer(
                id="t1",
                type="TRANSFER",
                source_account="acct_savings",
                payee_id="payee_17",
                payee_display="Müller 张三",  # <-- accented + CJK
                amount_cents=50000,
            )
        ],
        transcript_hash="a" * 64,  # valid 64-hex; content irrelevant to this test
        created_at=1_700_000_000,
        expires_at=1_700_000_300,
    )


def test_canonical_strings_match_python_byte_for_byte():
    """The JS canonical string must equal Python's, character for character."""
    plan = _plan()
    py = canonical_json(plan.model_dump())
    js, _ = _js_hash(plan.model_dump())
    assert js == py, f"canonical strings diverge:\n  py={py}\n  js={js}"


def test_payload_hashes_match_python_byte_for_byte():
    """The JS-computed payload_hash must equal Python's payload_hash."""
    plan = _plan()
    py = payload_hash(plan)
    _, js = _js_hash(plan.model_dump())
    assert js == py, f"payload hashes diverge:\n  py={py}\n  js={js}"


def test_non_ascii_survives_literal_not_unicode_escaped():
    """The whole point: non-ASCII survives as raw UTF-8 in BOTH languages, not
    as \\uXXXX. If either side escaped and the other did not, the hashes would
    diverge silently — which is why ASCII-only test data can never surface this."""
    plan = _plan()
    py = canonical_json(plan.model_dump())
    assert "Müller" in py, "accented char must appear literally in Python canonical"
    assert "张三" in py, "CJK must appear literally in Python canonical"
    assert "\\u" not in py, "Python must not unicode-escape non-ASCII"
    js, _ = _js_hash(plan.model_dump())
    assert "Müller" in js, "accented char must appear literally in JS canonical"
    assert "张三" in js, "CJK must appear literally in JS canonical"
    assert "\\u" not in js, "JS must not unicode-escape non-ASCII"
