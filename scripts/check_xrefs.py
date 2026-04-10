#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Validate cross-references in Markdown files.

Scans all Markdown files under the repository root and checks that every
``[text](target)`` link pointing to a local file or heading anchor is valid.

Checked link types:
  - Relative file paths: ``[text](other.md)``, ``[text](../doc/foo.md)``
  - File paths with anchors: ``[text](other.md#section)``
  - Same-file anchors: ``[text](#section)``

Skipped:
  - Absolute URLs (``http://``, ``https://``, ``mailto:``)

Usage:
    uv run python scripts/check_xrefs.py              # Check all .md files
    uv run python scripts/check_xrefs.py --verbose     # Show valid links too
    uv run python scripts/check_xrefs.py doc/ spec/    # Check specific dirs
"""

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import unquote


# Matches Markdown inline links: [text](target)
# Excludes image links ![alt](src) via negative lookbehind.
# Does not handle parentheses inside link targets.
_LINK_RE = re.compile(r"(?<!!)\[([^\]]*)\]\(([^)]+)\)")

# Patterns to skip (not local file references).
_SKIP_PREFIXES = ("http://", "https://", "mailto:")


def _heading_to_anchor(heading: str) -> str:
    """Convert a Markdown heading to its GitHub-style anchor ID.

    GitHub anchor generation rules:
      1. Strip leading/trailing whitespace
      2. Convert to lowercase
      3. Remove punctuation except hyphens, spaces, and underscores
      4. Replace spaces with hyphens

    Examples:
        "Getting Started" -> "getting-started"
        "Step 1: Choose a Provider" -> "step-1-choose-a-provider"
        "What's New?" -> "whats-new"
    """
    anchor = heading.strip().lower()
    # Remove characters that are not alphanumeric, space, hyphen, or underscore
    anchor = re.sub(r"[^\w\s-]", "", anchor)
    # Replace each space with a hyphen (preserving runs for double-hyphens)
    anchor = anchor.replace(" ", "-")
    return anchor


def _extract_headings(content: str) -> set[str]:
    """Extract all heading anchors from Markdown content.

    Parses ATX-style headings (lines starting with one or more ``#``).
    Returns a set of GitHub-style anchor IDs.  When duplicate headings
    exist, GitHub appends ``-1``, ``-2``, etc.  We generate those too.
    """
    anchors: dict[str, int] = {}
    result: set[str] = set()

    for line in content.splitlines():
        match = re.match(r"^#{1,6}\s+(.+?)(?:\s+#{1,6})?\s*$", line)
        if not match:
            continue
        heading_text = match.group(1).strip()
        base_anchor = _heading_to_anchor(heading_text)

        count = anchors.get(base_anchor, 0)
        if count == 0:
            result.add(base_anchor)
        else:
            result.add(f"{base_anchor}-{count}")
        anchors[base_anchor] = count + 1

    return result


def _strip_inline_code(line: str) -> str:
    """Remove inline code spans from a line.

    Handles both single and double backtick spans (`` `code` `` and
    ```` ``code`` ````).  Returns the line with code spans replaced by
    spaces to preserve character positions for error reporting.
    """
    # Double backtick spans first, then single
    line = re.sub(r"``[^`]*``", lambda m: " " * len(m.group()), line)
    line = re.sub(r"`[^`]*`", lambda m: " " * len(m.group()), line)
    return line


def _extract_links(content: str) -> list[tuple[int, str]]:
    """Extract local Markdown links from content.

    Returns a list of (line_number, target) tuples. Skips absolute URLs
    and links inside fenced code blocks or inline code spans.
    """
    links: list[tuple[int, str]] = []
    in_code_block = False

    for lineno, line in enumerate(content.splitlines(), start=1):
        # Track fenced code blocks (``` or ~~~)
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_code_block = not in_code_block
            continue
        if in_code_block:
            continue

        # Strip inline code spans before scanning for links
        clean_line = _strip_inline_code(line)

        for match in _LINK_RE.finditer(clean_line):
            target = match.group(2)
            if target.startswith(_SKIP_PREFIXES):
                continue
            links.append((lineno, target))

    return links


def _collect_md_files(base: Path, paths: list[Path] | None) -> list[Path]:
    """Collect Markdown files to check.

    Args:
        base: Repository root directory.
        paths: Specific files or directories, or None for all.

    Returns:
        Sorted list of Markdown file paths, excluding hidden directories
        (except ``.airut``).
    """
    if paths:
        md_files: list[Path] = []
        for p in paths:
            resolved = base / p if not p.is_absolute() else p
            if resolved.is_file():
                md_files.append(resolved)
            elif resolved.is_dir():
                md_files.extend(sorted(resolved.rglob("*.md")))
    else:
        md_files = sorted(base.rglob("*.md"))

    # Filter out hidden directories (except .airut)
    return [
        f
        for f in md_files
        if not any(
            part.startswith(".") and part != "." and part != ".airut"
            for part in f.parts
        )
    ]


def _validate_link(
    target: str,
    file_dir: Path,
    md_file: Path,
    heading_cache: dict[Path, set[str]],
) -> str | None:
    """Validate a single link target.

    Args:
        target: The raw link target string from the Markdown source.
        file_dir: Parent directory of the source Markdown file.
        md_file: Resolved path of the source Markdown file.
        heading_cache: Cache mapping resolved file paths to their heading
            anchor sets. Populated on first access for each file.

    Returns:
        An error message string if the link is broken, or None if valid.
    """
    # Split target into file path and optional anchor
    if "#" in target:
        file_part, anchor = target.split("#", 1)
        # URL-decode the anchor (e.g. %E2%80%94 -> —)
        anchor = unquote(anchor)
    else:
        file_part = target
        anchor = None

    # Determine the target file
    if file_part:
        target_path = (file_dir / file_part).resolve()
    else:
        # Same-file anchor: #section
        target_path = md_file.resolve()

    # Check file exists
    if not target_path.exists():
        return f"{target} — file not found"

    # Directory links are always valid (no anchor to check)
    if target_path.is_dir():
        return None

    # Check anchor if present
    if anchor:
        if target_path not in heading_cache:
            target_content = target_path.read_text()
            heading_cache[target_path] = _extract_headings(target_content)
        headings = heading_cache[target_path]
        # Normalize the anchor the same way headings are normalized,
        # so URL-encoded Unicode (e.g. %E2%80%94 for em dash) matches
        # the stripped form produced by _heading_to_anchor.
        normalized = _heading_to_anchor(anchor)
        if normalized not in headings:
            return f"{target} — anchor #{anchor} not found"

    return None


def check_xrefs(
    paths: list[Path] | None = None,
    *,
    verbose: bool = False,
    root: Path | None = None,
) -> int:
    """Validate cross-references in Markdown files.

    Args:
        paths: Specific files or directories to scan. Defaults to repo root.
        verbose: Print valid links too.
        root: Repository root directory. Defaults to current directory.

    Returns:
        0 if all links are valid, 1 if any are broken.
    """
    base = root or Path(".")
    md_files = _collect_md_files(base, paths)

    heading_cache: dict[Path, set[str]] = {}
    errors: list[str] = []
    valid_count = 0

    for md_file in md_files:
        content = md_file.read_text()
        links = _extract_links(content)
        rel = md_file.relative_to(base)

        for lineno, target in links:
            error = _validate_link(
                target, md_file.parent, md_file, heading_cache
            )
            if error:
                errors.append(f"  {rel}:{lineno}: {error}")
            else:
                valid_count += 1
                if verbose:
                    errors_for_target = f"{target} — OK"
                    # Check if it's a directory for verbose output
                    if "#" not in target:
                        file_part = target
                    else:
                        file_part = target.split("#", 1)[0]
                    if file_part:
                        resolved = (md_file.parent / file_part).resolve()
                        if resolved.is_dir():
                            errors_for_target = f"{target} — OK (directory)"
                    print(f"  {rel}:{lineno}: {errors_for_target}")

    if errors:
        print("Broken cross-references:")
        for msg in errors:
            print(msg)
        print()
        print(f"{len(errors)} broken, {valid_count} valid")
        return 1

    print(f"All {valid_count} cross-reference(s) valid.")
    return 0


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Validate cross-references in Markdown files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show valid links too",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="Repository root to scan (default: current directory)",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        type=Path,
        help="Files or directories to check (default: entire repo)",
    )

    args = parser.parse_args()
    return check_xrefs(
        paths=args.paths or None,
        verbose=args.verbose,
        root=args.root,
    )


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
