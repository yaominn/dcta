"""
Import-boundary test (REAL). (brief Section 4.2 — "enforced, not asserted")

Walks the module import graph: any module under backend/agent/ that transitively
imports backend/gateway/ or backend/auth/ is a TRUST BOUNDARY VIOLATION — the
agent (the untrusted LLM side) must have no code path to execution or to signing
keys.

Pure static AST analysis (no modules imported/executed, so no side effects).
Runs in CI.

Three real tests, not a trivially-green stub:
  1. the real backend/agent/ tree has no forbidden imports          (passes)
  2. a deliberately planted DIRECT forbidden import is flagged       (proves it catches)
  3. a TRANSITIVE violation (agent -> backend.utils -> gateway) is  (proves the BFS
     flagged                                                          follows edges)
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN = ("backend.gateway", "backend.auth")


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


def find_violations(repo_root: Path, forbidden=FORBIDDEN) -> list[dict]:
    """BFS from every backend.agent.* module; return violations where a reachable
    import starts with a forbidden prefix. Each: {agent, reaches, found_in}."""
    graph = _build_graph(repo_root)
    roots = [m for m in graph if m.startswith("backend.agent")]
    violations: list[dict] = []
    seen: set[str] = set()
    queue: list[tuple[str, str]] = [(r, r) for r in roots]   # (module, origin_agent)
    while queue:
        mod, origin = queue.pop(0)
        if mod in seen:
            continue
        seen.add(mod)
        for target in graph.get(mod, ()):
            if any(target.startswith(f) for f in forbidden):
                violations.append({"agent": origin, "reaches": target, "found_in": mod})
                continue                          # reaching a forbidden module IS the violation
            if target.startswith("backend.") and target in graph and target not in seen:
                queue.append((target, origin))    # traverse non-forbidden backend modules
    return violations


# --------------------------------------------------------------------------- tests
def test_no_violations_in_real_agent():
    assert find_violations(REPO_ROOT) == [], (
        "TRUST BOUNDARY VIOLATION: backend/agent/ transitively imports gateway/ or "
        "auth/ (brief Section 4.2). See find_violations(REPO_ROOT)."
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
    assert v[0]["agent"].startswith("backend.agent")
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
        x["agent"] == "backend.agent.a"
        and x["reaches"].startswith("backend.gateway")
        and x["found_in"] == "backend.utils"
        for x in v
    ), v


def test_clean_agent_passes(tmp_path):
    """A non-forbidden import (backend.resolver) must NOT trip the checker."""
    root = _make_repo(tmp_path, {
        "backend/__init__.py": "",
        "backend/agent/__init__.py": "",
        "backend/agent/clean.py": "import backend.resolver\n",
        "backend/resolver/__init__.py": "",
    })
    assert find_violations(root) == []
