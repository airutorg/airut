#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Rename the ``lib/`` package directory to ``airut/``.

This script performs a complete rename of the Python package from ``lib``
to ``airut``, updating all imports, string references, configuration
files, and documentation.

Usage:
    uv run scripts/rename_lib_to_airut.py              # Dry run (default)
    uv run scripts/rename_lib_to_airut.py --apply      # Apply changes
    uv run scripts/rename_lib_to_airut.py --apply --format  # Apply + ruff

The script operates in four phases:

1. **Directory renames** — ``git mv lib airut``,
   ``git mv tests/test_airut.py tests/test_cli.py`` (resolve collision),
   and ``git mv tests/test_lib tests/test_airut`` to preserve blame.
2. **Content replacements** — targeted regex substitutions per file type.
3. **Formatting** — runs ``ruff format`` and ``ruff check --fix`` (with
   ``--format`` flag).
4. **Validation** — greps for any remaining ``lib`` references that look
   like they should have been updated.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path


# Project root (parent of scripts/)
ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Replacement:
    """A regex replacement to apply to files matching a glob pattern."""

    # Glob pattern relative to ROOT (e.g. "**/*.py")
    glob: str
    # Regex pattern to search for
    pattern: str
    # Replacement string (can use backreferences)
    replacement: str
    # Human-readable description
    description: str
    # Files to exclude from this rule (relative to ROOT)
    exclude_files: set[str] = field(default_factory=set)


# ── False-positive exclusions ────────────────────────────────────────
#
# These files contain "lib" in contexts that should NOT be renamed:
#
# - tests/conftest.py: master_repo fixture creates a mock external
#   repository with a lib/ directory (not airut's own lib/).
# - tests/gateway/test_conversation.py: asserts the mock repo has lib/.
# - tests/test_install_services.py: references /var/lib/systemd/linger.

_MOCK_REPO_FILES = {
    "tests/conftest.py",
    "tests/gateway/test_conversation.py",
}

_SYSTEM_PATH_FILES = {
    "tests/test_install_services.py",
}

# ── Replacement rules ────────────────────────────────────────────────
#
# Each rule targets a specific pattern of "lib" usage.  Rules are
# ordered from most specific to most general to make review easier.
#
# IMPORTANT: Patterns use word boundaries (\b) and context where
# possible to avoid false positives like /var/lib/ or "library".

REPLACEMENTS: list[Replacement] = [
    # ── Python files (.py) ───────────────────────────────────────
    #
    # Import statements: from lib.X / from lib import X
    Replacement(
        glob="**/*.py",
        pattern=r"\bfrom lib\b",
        replacement="from airut",
        description="Python: from lib → from airut",
    ),
    # Import statements: import lib.X / import lib
    Replacement(
        glob="**/*.py",
        pattern=r"\bimport lib\b",
        replacement="import airut",
        description="Python: import lib → import airut",
    ),
    # String literals with lib. prefix (patch() targets,
    # importlib.resources, sys.modules keys, etc.) — double-quoted
    Replacement(
        glob="**/*.py",
        pattern=r'"lib\.',
        replacement='"airut.',
        description='Python: "lib. → "airut.',
    ),
    # Same, single-quoted
    Replacement(
        glob="**/*.py",
        pattern=r"'lib\.",
        replacement="'airut.",
        description="Python: 'lib. → 'airut.",
    ),
    # Exact string "lib" (sys.modules["lib"], name == "lib", etc.)
    # Exclude mock repo files and /var/lib/ system paths.
    Replacement(
        glob="**/*.py",
        pattern=r'"lib"',
        replacement='"airut"',
        description='Python: "lib" → "airut"',
        exclude_files=_MOCK_REPO_FILES | _SYSTEM_PATH_FILES,
    ),
    # Path construction: / "lib" / (hatch_build.py, test_hatch_build)
    Replacement(
        glob="**/*.py",
        pattern=r'/ "lib" /',
        replacement='/ "airut" /',
        description='Python: / "lib" / → / "airut" /',
    ),
    # Path construction at end of expression: / "lib"\n or / "lib")
    # e.g. tmp_path / "lib"\n, PROJECT_ROOT / "lib"\n
    # Exclude mock repo files where lib/ is an arbitrary directory in
    # a simulated external repo, and /var/lib/ system paths.
    Replacement(
        glob="**/*.py",
        pattern=r'/ "lib"(?=[)\n])',
        replacement='/ "airut"',
        description='Python: / "lib") → / "airut")',
        exclude_files=_MOCK_REPO_FILES | _SYSTEM_PATH_FILES,
    ),
    # String paths: "lib/_version.py" in force_include values
    Replacement(
        glob="**/*.py",
        pattern=r'"lib/',
        replacement='"airut/',
        description='Python: "lib/ → "airut/',
    ),
    # Coverage flag in command strings: --cov=lib (ci.py)
    Replacement(
        glob="**/*.py",
        pattern=r"--cov=lib\b",
        replacement="--cov=airut",
        description="Python: --cov=lib → --cov=airut",
    ),
    # Comment references to lib/ paths (e.g. ``lib/_version.py``)
    Replacement(
        glob="**/*.py",
        pattern=r"``lib/",
        replacement="``airut/",
        description="Python: ``lib/ → ``airut/ (docstrings)",
    ),
    Replacement(
        glob="**/*.py",
        pattern=r"``lib\.",
        replacement="``airut.",
        description="Python: ``lib. → ``airut. (docstrings)",
    ),
    # ── TOML files ───────────────────────────────────────────────
    #
    # Entry point: "lib.airut:cli"
    Replacement(
        glob="**/*.toml",
        pattern=r'"lib\.',
        replacement='"airut.',
        description='TOML: "lib. → "airut.',
    ),
    # Package list: ["lib"]
    Replacement(
        glob="**/*.toml",
        pattern=r'"lib"',
        replacement='"airut"',
        description='TOML: "lib" → "airut"',
    ),
    # Path references: "lib/ (exclude patterns, etc.)
    Replacement(
        glob="**/*.toml",
        pattern=r'"lib/',
        replacement='"airut/',
        description='TOML: "lib/ → "airut/',
    ),
    # ── YAML files (.yml, .yaml) ─────────────────────────────────
    #
    # Coverage flag: --cov=lib
    Replacement(
        glob="**/*.yml",
        pattern=r"--cov=lib\b",
        replacement="--cov=airut",
        description="YAML: --cov=lib → --cov=airut",
    ),
    # ── Markdown files (.md) ─────────────────────────────────────
    #
    # Inline code: `lib/
    Replacement(
        glob="**/*.md",
        pattern=r"`lib/",
        replacement="`airut/",
        description="Markdown: `lib/ → `airut/",
    ),
    # Inline code: `lib.
    Replacement(
        glob="**/*.md",
        pattern=r"`lib\.",
        replacement="`airut.",
        description="Markdown: `lib. → `airut.",
    ),
    # Directory trees: ── lib/ or ├── lib/
    Replacement(
        glob="**/*.md",
        pattern=r"── lib/",
        replacement="── airut/",
        description="Markdown: ── lib/ → ── airut/",
    ),
    # Bare path references in prose: lib/sandbox/, lib/gateway/, etc.
    # Negative lookbehind avoids matching /var/lib/ or similar.
    # Lookahead requires a word char to avoid matching standalone "lib/".
    Replacement(
        glob="**/*.md",
        pattern=r"(?<![/\w])lib/(?=\w)",
        replacement="airut/",
        description="Markdown: lib/X → airut/X (prose paths)",
    ),
    # Import examples in code blocks
    Replacement(
        glob="**/*.md",
        pattern=r"\bfrom lib\b",
        replacement="from airut",
        description="Markdown: from lib → from airut (code blocks)",
    ),
    Replacement(
        glob="**/*.md",
        pattern=r"\bimport lib\b",
        replacement="import airut",
        description="Markdown: import lib → import airut (code blocks)",
    ),
    # Quoted strings: "lib. (entry points in code blocks)
    Replacement(
        glob="**/*.md",
        pattern=r'"lib\.',
        replacement='"airut.',
        description='Markdown: "lib. → "airut. (code blocks)',
    ),
    # Quoted paths: "lib/
    Replacement(
        glob="**/*.md",
        pattern=r'"lib/',
        replacement='"airut/',
        description='Markdown: "lib/ → "airut/',
    ),
    # Start-of-line lib/ in code blocks (directory trees)
    Replacement(
        glob="**/*.md",
        pattern=r"(?m)^lib/",
        replacement="airut/",
        description="Markdown: ^lib/ → ^airut/ (code block trees)",
    ),
    # Coverage flag in command examples: --cov=lib
    Replacement(
        glob="**/*.md",
        pattern=r"--cov=lib\b",
        replacement="--cov=airut",
        description="Markdown: --cov=lib → --cov=airut",
    ),
]

# Directories to exclude from all replacements (relative to ROOT).
EXCLUDE_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    ".ruff_cache",
    "node_modules",
    ".uv",
}

# This script itself should not be modified by the replacements.
EXCLUDE_FILES = {
    "scripts/rename_lib_to_airut.py",
}


def find_files(
    glob_pattern: str,
    extra_excludes: set[str] | None = None,
) -> list[Path]:
    """Find files matching a glob, excluding irrelevant dirs and files."""
    matches = []
    for path in ROOT.glob(glob_pattern):
        if not path.is_file():
            continue
        rel = path.relative_to(ROOT)
        if any(part in EXCLUDE_DIRS for part in rel.parts):
            continue
        rel_str = str(rel)
        if rel_str in EXCLUDE_FILES:
            continue
        if extra_excludes and rel_str in extra_excludes:
            continue
        matches.append(path)
    return sorted(matches)


def apply_replacements(
    dry_run: bool,
) -> list[tuple[Path, str, int]]:
    """Apply all replacement rules to matching files.

    Returns:
        List of (file_path, description, count) for each rule that
        made changes in each file.
    """
    changes: list[tuple[Path, str, int]] = []

    for rule in REPLACEMENTS:
        files = find_files(rule.glob, rule.exclude_files or None)
        regex = re.compile(rule.pattern)

        for fpath in files:
            try:
                content = fpath.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue

            new_content, count = regex.subn(rule.replacement, content)
            if count > 0:
                changes.append((fpath, rule.description, count))
                if not dry_run:
                    fpath.write_text(new_content, encoding="utf-8")

    return changes


def _remove_stale_directory(target: Path, dry_run: bool) -> None:
    """Remove a target directory if it only contains artifacts.

    ``uv run`` and pytest can leave behind ``__pycache__/`` and
    ``_version.py`` from builds or previous runs.  If the target
    directory exists but contains nothing except these artifacts,
    remove it so that ``git mv`` can create it fresh.
    """
    if not target.is_dir():
        return

    # Walk the tree: every file must be a known artifact
    for item in target.rglob("*"):
        if item.is_dir():
            continue  # Directories are OK if their contents are OK
        if item.name.endswith((".pyc", ".pyo")):
            continue
        if item.name == "_version.py":
            continue
        # Found a real file — don't touch this directory
        return

    if not dry_run:
        import shutil

        shutil.rmtree(target)


def rename_directories(dry_run: bool) -> list[str]:
    """Rename lib/ → airut/ and tests/test_lib/ → tests/test_airut/.

    Uses ``git mv`` to preserve blame history.  If ``airut/`` already
    exists with only build artifacts (``_version.py``, ``__pycache__``),
    it is removed first so ``git mv`` can proceed.

    Before renaming the test directory, ``tests/test_airut.py`` is moved
    to ``tests/test_cli.py`` to avoid a file/directory name collision
    (``tests/test_airut.py`` vs ``tests/test_airut/``).

    Returns:
        List of rename descriptions.
    """
    renames: list[tuple[Path, Path]] = []

    lib_dir = ROOT / "lib"
    airut_dir = ROOT / "airut"
    if lib_dir.is_dir():
        _remove_stale_directory(airut_dir, dry_run)
        if not airut_dir.exists():
            renames.append((lib_dir, airut_dir))

    # Rename tests/test_airut.py → tests/test_cli.py BEFORE renaming
    # the test_lib/ directory, to avoid a name collision between the
    # file (test_airut.py) and the directory (test_airut/).
    test_airut_file = ROOT / "tests" / "test_airut.py"
    test_cli_file = ROOT / "tests" / "test_cli.py"
    if test_airut_file.is_file() and not test_cli_file.exists():
        renames.append((test_airut_file, test_cli_file))

    test_lib = ROOT / "tests" / "test_lib"
    test_airut = ROOT / "tests" / "test_airut"
    if test_lib.is_dir():
        _remove_stale_directory(test_airut, dry_run)
        if not test_airut.exists():
            renames.append((test_lib, test_airut))

    descriptions = []
    for src, dst in renames:
        desc = f"git mv {src.relative_to(ROOT)} {dst.relative_to(ROOT)}"
        descriptions.append(desc)
        if not dry_run:
            subprocess.run(
                ["git", "mv", str(src), str(dst)],
                cwd=ROOT,
                check=True,
                capture_output=True,
            )

    return descriptions


def validate_no_remaining_refs() -> list[str]:
    """Check for remaining lib references that look like they need updating.

    Returns:
        List of warning messages for suspicious remaining references.
    """
    warnings = []

    # Patterns that should not exist after a successful rename.
    # Each entry: (needle, glob, context_label)
    checks = [
        ("from lib.", "**/*.py", "import statement"),
        ("from lib ", "**/*.py", "import statement"),
        ("import lib.", "**/*.py", "import statement"),
        ("import lib ", "**/*.py", "import statement"),
        ('"lib.', "**/*.py", "string literal"),
        ("'lib.", "**/*.py", "string literal"),
        ("--cov=lib", "**/*.py", "coverage flag"),
        ("--cov=lib", "**/*.yml", "coverage flag"),
        ("--cov=lib", "**/*.md", "coverage flag"),
    ]

    for needle, glob_pattern, context in checks:
        for fpath in find_files(glob_pattern):
            try:
                content = fpath.read_text(encoding="utf-8")
            except (UnicodeDecodeError, PermissionError):
                continue
            for i, line in enumerate(content.splitlines(), 1):
                if needle in line:
                    rel = fpath.relative_to(ROOT)
                    warnings.append(f"  {rel}:{i}: {context}: {line.strip()}")

    return warnings


def fix_overlength_lines() -> int:
    """Fix lines that became >80 chars due to the lib→airut rename.

    The rename adds 2 characters per ``lib`` → ``airut`` occurrence.
    Lines at 79-80 chars before may now exceed the limit.  ``ruff
    format`` handles code but not docstrings/comments, so this function
    re-wraps those.

    For one-line docstrings, the closing quotes are moved to a new
    line (saves 3 chars).  For comments, the line is split at the
    last space before the limit.

    Returns:
        Number of lines fixed.
    """
    max_len = 80
    fixed = 0

    for fpath in find_files("**/*.py"):
        try:
            content = fpath.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue

        lines = content.splitlines(keepends=True)
        changed = False

        for i, line in enumerate(lines):
            stripped = line.rstrip("\n\r")
            if len(stripped) <= max_len:
                continue
            if "airut" not in stripped:
                continue

            # Only fix lines broken by the rename (reverting would fit)
            hypothetical = stripped.replace("airut", "lib")
            if len(hypothetical) > max_len:
                continue

            indent_n = len(stripped) - len(stripped.lstrip())
            indent_str = stripped[:indent_n]
            body = stripped[indent_n:]

            result = None
            if body.startswith("#"):
                result = _fix_comment(stripped, indent_str, max_len)
            elif body.startswith(('"""', "'''")):
                result = _fix_docstring(body, indent_str, max_len, lines, i)

            if result is not None:
                lines[i] = result + "\n"
                changed = True
                fixed += 1

        if changed:
            fpath.write_text("".join(lines), encoding="utf-8")

    return fixed


def _fix_comment(line: str, indent: str, max_len: int) -> str | None:
    """Wrap a comment at the last space before the limit."""
    wrap_at = line.rfind(" ", 0, max_len)
    if wrap_at <= len(indent) + 1:
        return None
    first = line[:wrap_at]
    rest = indent + "# " + line[wrap_at + 1 :].lstrip()
    return first + "\n" + rest


def _fix_docstring(
    body: str,
    indent: str,
    max_len: int,
    lines: list[str],
    line_idx: int,
) -> str | None:
    """Fix an overlength docstring summary line.

    For one-line docstrings, moves the closing quotes to a new line
    (saves 3 chars).  For multi-line docstrings, shortens the summary
    by splitting at a preposition and moving the tail into the
    description body with a blank separator (D205-safe).
    """
    quote = body[:3]
    inner = body[3:]
    is_one_liner = inner.rstrip().endswith(quote)

    if is_one_liner:
        text = inner.rstrip()[: -len(quote)].rstrip()
        summary_line = indent + quote + text
        if len(summary_line) <= max_len:
            return summary_line + "\n" + indent + quote
        return None

    # Multi-line docstring — shorten summary by splitting at a
    # preposition that keeps the first line under the limit.
    text = inner.rstrip()
    full = indent + quote + text

    # Find the rightmost preposition that produces a valid summary
    best_pos = -1
    for prep in [" for ", " with ", " to ", " in ", " via "]:
        pos = 0
        while True:
            idx = full.find(prep, pos)
            if idx == -1:
                break
            # Summary = text before prep + "."
            candidate = full[:idx] + "."
            if len(candidate) <= max_len:
                best_pos = idx
            pos = idx + 1

    if best_pos == -1:
        return None

    short_summary = full[:best_pos] + "."
    remainder = full[best_pos + 1 :].strip()

    # Build result: short summary + blank line + remainder
    result = short_summary + "\n"
    result += "\n"
    result += indent + remainder

    # If next line was a blank line (between summary and description),
    # blank it out to avoid a double blank line (we added one above).
    next_idx = line_idx + 1
    if next_idx < len(lines) and lines[next_idx].strip() == "":
        lines[next_idx] = ""

    return result


def reinstall_package() -> None:
    """Reinstall the package so imports resolve to ``airut/``."""
    print("  Running uv sync to reinstall package...")
    subprocess.run(
        ["uv", "sync"],
        cwd=ROOT,
        capture_output=True,
    )


def run_formatting() -> None:
    """Run ruff format and ruff check --fix."""
    print("\n── Running ruff format ──")
    subprocess.run(
        ["uv", "run", "ruff", "format", "."],
        cwd=ROOT,
    )
    print("\n── Running ruff check --fix ──")
    subprocess.run(
        ["uv", "run", "ruff", "check", "--fix", "."],
        cwd=ROOT,
    )


def main() -> int:
    """Run the rename script."""
    parser = argparse.ArgumentParser(
        description="Rename lib/ package to airut/",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes (default is dry-run)",
    )
    parser.add_argument(
        "--format",
        action="store_true",
        dest="run_format",
        help="Run ruff format and ruff check --fix after applying",
    )
    args = parser.parse_args()
    dry_run = not args.apply

    if dry_run:
        print("DRY RUN — no changes will be made. Use --apply to apply.\n")

    # Phase 1: Directory renames
    print("Phase 1: Directory renames")
    print("─" * 60)
    dir_renames = rename_directories(dry_run)
    if dir_renames:
        for desc in dir_renames:
            print(f"  {desc}")
    else:
        print("  (no directories to rename)")

    # Phase 2: Content replacements
    print("\nPhase 2: Content replacements")
    print("─" * 60)
    changes = apply_replacements(dry_run)

    # Summarize by rule
    rule_counts: Counter[str] = Counter()
    file_counts: Counter[str] = Counter()
    for _fpath, desc, count in changes:
        rule_counts[desc] += count
        file_counts[desc] += 1

    total_replacements = 0
    for desc in dict.fromkeys(r.description for r in REPLACEMENTS):
        if desc in rule_counts:
            total = rule_counts[desc]
            files = file_counts[desc]
            total_replacements += total
            print(f"  {desc}: {total} replacements in {files} files")

    print(f"\n  Total: {total_replacements} replacements")

    # Phase 2b: Fix overlength lines caused by the rename
    if not dry_run:
        print("\nPhase 2b: Fix overlength lines")
        print("─" * 60)
        n_fixed = fix_overlength_lines()
        if n_fixed:
            print(f"  Re-wrapped {n_fixed} lines that exceeded 80 chars")
        else:
            print("  No overlength lines to fix")

    # Phase 2c: Reinstall package so imports resolve correctly
    if not dry_run:
        print("\nPhase 2c: Reinstall package")
        print("─" * 60)
        reinstall_package()

    # Phase 3: Formatting (only with --apply --format)
    if not dry_run and args.run_format:
        print("\nPhase 3: Formatting")
        print("─" * 60)
        run_formatting()

    # Phase 4: Validation
    print("\nPhase 4: Validation")
    print("─" * 60)
    if dry_run:
        print("  (skipped in dry-run mode)")
    else:
        warnings = validate_no_remaining_refs()
        if warnings:
            print(
                f"  WARNING: {len(warnings)} suspicious remaining "
                "references found:"
            )
            for w in warnings:
                print(w)
            print(
                "\n  Review these manually — they may be false positives "
                "(e.g. /var/lib/) or genuine misses."
            )
        else:
            print("  No suspicious remaining references found.")

    # Summary
    print()
    if dry_run:
        print(
            "Dry run complete. Run with --apply to make changes, "
            "or --apply --format to also run ruff."
        )
    else:
        print("Rename complete.")
        if not args.run_format:
            print(
                "Run with --format to also run ruff, or manually run:\n"
                "  uv run ruff format . && uv run ruff check --fix ."
            )

    return 0


if __name__ == "__main__":
    sys.exit(main())
