"""
Import-boundary test (REAL). (brief Section 4.2 + 5.4 — "enforced, not asserted")

Walks the module import graph and enforces every trust boundary:
  - any module under backend/agent/ that transitively imports backend/gateway/
    or backend/auth/ is a violation — the agent (the untrusted LLM side) must have
    no code path to execution or to signing keys.
  - any module under backend/resolver/ that transitively imports backend/agent/
    is a violation (M4) — the resolver is deterministic by definition and must
    not reach the LLM side.
  - any module under backend/policy/ that transitively imports backend/agent/
    is a violation (M5) — a risk decision must have no path to the LLM.

Pure static AST analysis (no modules imported/executed, so no side effects).
Runs in CI.

Real tests, not a trivially-green stub:
  1. the real backend tree respects every boundary                      (passes)
  2. a planted DIRECT agent->gateway forbidden import is flagged        (proves it catches)
  3. a TRANSITIVE violation (agent -> backend.utils -> gateway) is       (proves the BFS
     flagged                                                              follows edges)
  4. a planted resolver->agent forbidden import is flagged (M4)         (proves the new
                                                                         boundary catches)
  5. a planted policy->agent forbidden import is flagged (M5)           (same, for policy)
  6. clean agent->resolver and resolver->data imports stay green        (proves it doesn't
                                                                         false-fire)
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

# Trust boundaries: each entry is (root_prefix, forbidden_prefixes). A module
# under root_prefix that transitively imports anything starting with a forbidden
# prefix is a TRUST BOUNDARY VIOLATION. Enumerating them here makes each "must
# not" a CI-checked property, not a docstring claim (brief 5.4).
#
#   - agent   must not reach gateway/ or auth/  (the untrusted LLM side has no
#     code path to execution or signing keys)
#   - resolver must not reach agent/             (M4: the resolver is LLM-free by
#     construction; "deterministic" is enforced, not asserted)
BOUNDARIES = [
    ("backend.agent", ("backend.gateway", "backend.auth")),
    ("backend.resolver", ("backend.agent",)),
    ("backend.policy", ("backend.agent",)),
]


# --------------------------------------------------------------------------- static import graph
def _mod_parts(py_path: Path, repo_root: Path) -> list[str]:
    """Dotted module name parts for a .py file relative to the repo root.
    backend/agent/parser.py -> ['backend','agent','parser']
    backend/agent/__init__.py -> ['backend','agent']"""
    rel = py_path.relative_to(repo_root)
    parts = [p[:-3] if p.endswith(".py") else p for p in rel.parts]
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return parts


def _resolve_relative(file_parts: list[str], level: int, module: str | None) -> str:
    """Resolve `from . import x` / `from ..pkg import y` to an absolute dotted name.
    Python semantics: level 1 = current package (file's parent); level N drops N-1
    parts off the current package."""
    pkg = file_parts[:-1]                       # the package containing this module
    drop = max(0, level - 1)
    base = pkg[: max(0, len(pkg) - drop)]
    if module:
        base = base + [module]
    return ".".join(base)


def _imports_of(py_path: Path, repo_root: Path) -> set[str]:
    """Fully-qualified imported module names that are under backend.* ."""
    tree = ast.parse(py_path.read_text())
    file_parts = _mod_parts(py_path, repo_root)
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                if n.name.startswith("backend."):
                    out.add(n.name)
        elif isinstance(node, ast.ImportFrom):
            resolved = (
                _resolve_relative(file_parts, node.level, node.module)
                if node.level and node.level > 0
                else (node.module or "")
            )
            if resolved.startswith("backend."):
                out.add(resolved)
    return out


def _build_graph(repo_root: Path) -> dict[str, set[str]]:
    """module -> set of backend.* modules it imports."""
    backend = repo_root / "backend"
    graph: dict[str, set[str]] = {}
    for py in backend.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        mod = ".".join(_mod_parts(py, repo_root))
        graph.setdefault(mod, set())
        graph[mod] |= _imports_of(py, repo_root)
    return graph


def find_violations(repo_root: Path, boundaries=BOUNDARIES) -> list[dict]:
    """BFS from every module under each boundary's root_prefix; return violations
    where a reachable import starts with a forbidden prefix for THAT boundary.
    Each: {root: origin_root_module, reaches: forbidden_target, found_in: module}.

    One graph is built for the whole backend tree; each boundary is a separate
    BFS over it. Roots under `backend.agent` forbid gateway/auth; roots under
    `backend.resolver` forbid agent. A module reachable from both roots is
    checked under each boundary independently."""
    graph = _build_graph(repo_root)
    violations: list[dict] = []
    seen_all: set[tuple[str, str]] = set()
    for root_prefix, forbidden in boundaries:
        roots = [m for m in graph if m.startswith(root_prefix)]
        seen: set[str] = set()
        queue: list[tuple[str, str]] = [(r, r) for r in roots]   # (module, origin_root)
        while queue:
            mod, origin = queue.pop(0)
            if mod in seen:
                continue
            seen.add(mod)
            for target in graph.get(mod, ()):
                if any(target.startswith(f) for f in forbidden):
                    key = (origin, target)
                    if key not in seen_all:
                        seen_all.add(key)
                        violations.append(
                            {"root": origin, "reaches": target, "found_in": mod}
                        )
                    continue                          # reaching a forbidden module IS the violation
                if target.startswith("backend.") and target in graph and target not in seen:
                    queue.append((target, origin))    # traverse non-forbidden backend modules
    return violations


# --------------------------------------------------------------------------- tests
def test_no_violations_in_real_repo():
    """The real backend tree respects every trust boundary: agent reaches neither
    gateway nor auth, and resolver reaches no agent (brief 4.2 + 5.4)."""
    assert find_violations(REPO_ROOT) == [], (
        "TRUST BOUNDARY VIOLATION: see find_violations(REPO_ROOT). "
        "agent must not reach gateway/auth (brief 4.2); resolver must not reach "
        "agent (brief 5.4)."
    )


def _make_repo(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "repo"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
    return root


def test_planted_direct_violation_is_flagged(tmp_path):
    """Proves the checker actually catches a forbidden import (not trivially green)."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/agent/evil.py": "import backend.gateway\n",   # direct forbidden import
        "backend/gateway/__init__.py": "",
    })
    v = find_violations(root)
    assert len(v) >= 1
    assert v[0]["root"].startswith("backend.agent")
    assert v[0]["reaches"].startswith("backend.gateway")


def test_planted_transitive_violation_is_flagged(tmp_path):
    """Proves the BFS follows edges: agent -> backend.utils -> backend.gateway."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/agent/a.py": "import backend.utils\n",        # not forbidden itself
        "backend/utils.py": "import backend.gateway\n",        # ...but it reaches gateway
        "backend/gateway/__init__.py": "",
    })
    v = find_violations(root)
    assert any(
        x["root"] == "backend.agent.a"
        and x["reaches"].startswith("backend.gateway")
        and x["found_in"] == "backend.utils"
        for x in v
    ), v


def test_planted_resolver_agent_violation_is_flagged(tmp_path):
    """M4 (brief 5.4): the resolver must not reach the agent (it is LLM-free by
    construction). Proves the new boundary catches a resolver->agent import."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/resolver/__init__.py": "",
        "backend/resolver/evil.py": "import backend.agent\n",   # resolver must not reach agent
    })
    v = find_violations(root)
    assert any(
        x["root"].startswith("backend.resolver")
        and x["reaches"].startswith("backend.agent")
        for x in v
    ), v


def test_clean_resolver_passes(tmp_path):
    """A non-forbidden resolver import (backend.data) must NOT trip the checker —
    only agent is forbidden to the resolver."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/resolver/__init__.py": "",
        "backend/resolver/clean.py": "import backend.data\n",   # allowed
        "backend/data/__init__.py": "",
    })
    assert find_violations(root) == []


def test_agent_importing_resolver_is_allowed(tmp_path):
    """The agent -> resolver direction is ALLOWED (the API wires the resolver into
    the pipeline after the parser). Only gateway/auth are forbidden to the agent,
    and only agent is forbidden to the resolver — so this must stay green."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/agent/clean.py": "import backend.resolver\n",
        "backend/resolver/__init__.py": "",
    })
    assert find_violations(root) == []


def test_planted_policy_agent_violation_is_flagged(tmp_path):
    """M5: the policy engine must not reach the agent. A risk decision that could
    consult the LLM is not a deterministic risk decision. Proves the boundary
    catches, so "no LLM in policy/" is CI-checked rather than asserted."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/policy/__init__.py": "",
        "backend/policy/evil.py": "from backend.agent import parse_transcript\n",
    })
    v = find_violations(root)
    assert any(
        x["root"].startswith("backend.policy")
        and x["reaches"].startswith("backend.agent")
        for x in v
    ), v


def test_clean_policy_passes(tmp_path):
    """policy -> data / models / display are all allowed; only agent is forbidden."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/policy/__init__.py": "",
        "backend/policy/engine.py": "import backend.models.schemas\n",
        "backend/policy/context.py": "import backend.data.db\n",
        "backend/models/__init__.py": "",
        "backend/models/schemas.py": "",
        "backend/data/__init__.py": "",
        "backend/data/db.py": "",
    })
    assert find_violations(root) == []
