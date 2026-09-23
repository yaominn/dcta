"""
Import-boundary test. (brief Section 4.2)

Walks the module import graph under backend/agent/ and FAILS if anything
there transitively imports backend/gateway/ or backend/auth/.

This is the "enforced, not asserted" layer: the agent has no code path to
execution and no gateway credentials, by construction. Runs in CI.

Note: right now (M0) the agent package is a stub importing nothing, so this
test is trivially green. It becomes meaningful in M3 when the agent gains
real imports. It is included early so the contract is documented from day one.
"""
from __future__ import annotations

import ast
import importlib
import pkgutil
from pathlib import Path

import backend.agent as agent_pkg

FORBIDDEN_PREFIXES = ("backend.gateway", "backend.auth")


def _modules_in_package(pkg_name: str) -> list[str]:
    """Return all importable submodule names in a package."""
    try:
        pkg = importlib.import_module(pkg_name)
    except ImportError:
        return []
    names = []
    for mod in pkgutil.walk_packages(pkg.__path__, prefix=f"{pkg_name}."):
        names.append(mod.name)
    return names


def _imported_top_level(module_name: str) -> set[str]:
    """Static-parse a module's source and collect all imported module roots."""
    mod = importlib.import_module(module_name)
    src_file = getattr(mod, "__file__", None)
    if not src_file or not Path(src_file).exists():
        return set()
    tree = ast.parse(Path(src_file).read_text())
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for n in node.names:
                roots.add(n.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                roots.add(node.module.split(".")[0])
    return roots


def test_agent_does_not_import_gateway_or_auth():
    agent_modules = ["backend.agent"] + _modules_in_package("backend.agent")
    for mod in agent_modules:
        roots = _imported_top_level(mod)
        for r in roots:
            assert not r.startswith(FORBIDDEN_PREFIXES), (
                f"TRUST BOUNDARY VIOLATION: {mod} imports {r} — agent/ must not "
                f"reach gateway/ or auth/ (brief Section 4.2)."
            )
