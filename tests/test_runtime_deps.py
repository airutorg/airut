# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Test that all third-party imports in lib/ are declared as runtime deps.

Catches missing runtime dependencies by statically scanning lib/ source
files for imports and verifying each one is either stdlib, internal, or
provided by a declared runtime dependency (including transitive deps).
"""

import ast
import re
import sys
import tomllib
from importlib.metadata import packages_distributions, requires
from pathlib import Path


# Root of the project
PROJECT_ROOT = Path(__file__).parent.parent
LIB_DIR = PROJECT_ROOT / "airut"

# Directories excluded from runtime import scanning.
# Proxy code runs inside its own container with independent deps.
EXCLUDED_DIRS = {LIB_DIR / "_bundled" / "proxy"}


def _collect_imports(source_dir: Path) -> set[str]:
    """Collect top-level import names from Python files.

    Parses all .py files in source_dir (recursively, excluding
    EXCLUDED_DIRS) using the ast module and returns the set of
    top-level module names that are imported.
    """
    imports: set[str] = set()
    for py_file in source_dir.rglob("*.py"):
        if any(py_file.is_relative_to(d) for d in EXCLUDED_DIRS):
            continue
        tree = ast.parse(py_file.read_text(), filename=str(py_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom):
                if node.module and node.level == 0:
                    imports.add(node.module.split(".")[0])
    return imports


def _resolve_runtime_distributions() -> set[str]:
    """Resolve all distribution names reachable from runtime deps.

    Reads [project] dependencies from pyproject.toml, then walks
    the transitive dependency tree using importlib.metadata.
    Returns normalized distribution names.
    """
    with open(PROJECT_ROOT / "pyproject.toml", "rb") as f:
        config = tomllib.load(f)

    # Extract direct runtime dep names (strip version specifiers)
    direct = set()
    for dep in config["project"]["dependencies"]:
        name = re.split(r"[<>=!~;\[\s]", dep)[0].strip()
        direct.add(_normalize(name))

    # Walk transitive deps
    resolved: set[str] = set()
    queue = list(direct)
    while queue:
        dist = queue.pop()
        if dist in resolved:
            continue
        resolved.add(dist)
        reqs = requires(dist)
        if reqs:
            for req in reqs:
                # Skip extras/optional deps (lines containing "; extra ==")
                if "extra ==" in req:
                    continue
                dep_name = re.split(r"[<>=!~;\[\s]", req)[0].strip()
                normalized = _normalize(dep_name)
                if normalized not in resolved:
                    queue.append(normalized)

    return resolved


def _normalize(name: str) -> str:
    """Normalize a distribution name for comparison."""
    return re.sub(r"[-_.]+", "-", name).lower()


def test_lib_imports_covered_by_runtime_deps() -> None:
    """All third-party imports in lib/ are provided by runtime deps."""
    imports = _collect_imports(LIB_DIR)

    # Filter out stdlib and internal imports
    stdlib = sys.stdlib_module_names | {"_thread", "_io"}
    third_party = set()
    for name in imports:
        if name in stdlib:
            continue
        if name == "airut":
            continue
        third_party.add(name)

    # Build mapping from import name -> distribution name
    import_to_dist = packages_distributions()

    # Resolve which distributions are in the runtime closure
    runtime_dists = _resolve_runtime_distributions()

    # Check each third-party import
    missing = []
    for imp in sorted(third_party):
        dists = import_to_dist.get(imp, [])
        if not dists:
            missing.append(f"{imp} (no distribution found)")
            continue
        # Check if any providing distribution is in the runtime set
        if not any(_normalize(d) in runtime_dists for d in dists):
            missing.append(f"{imp} (from {', '.join(dists)})")

    assert not missing, (
        "airut/ imports third-party packages not declared as runtime "
        "dependencies:\n"
        + "\n".join(f"  - {m}" for m in missing)
        + "\n\nAdd them to [project] dependencies in pyproject.toml."
    )
