#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Check that the bundled Dockerfiles' base image digests are current.

Each base image in a bundled Dockerfile is pinned as
``<registry>/<repository>:<tag>@sha256:<digest>`` (see
``scripts/image_pins.py``).  This script looks up each tag's current
digest in its registry and reports pins that are out of date.  With
``--fix`` it rewrites them, and pins a fully qualified, tagged reference
that has no digest yet.  Short names, references without a tag and
references assembled from build arguments need fixing by hand.

The digest pinned is that of the tag's multi-platform index, so the pin
works on every server platform; a tag that resolves to a single-platform
manifest is reported as an error.

Usage:
    uv run python -m scripts.check_image_pins          # Check (report only)
    uv run python -m scripts.check_image_pins --fix    # Update digests
    uv run python -m scripts.check_image_pins --verbose  # Show up to date too
"""

import argparse
import http.client
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import Request

from scripts.image_pins import (
    DIGEST_RE,
    DockerfileError,
    ImageReference,
    base_images,
    find_dockerfiles,
    parse_reference,
    pin_problems,
)

from airut.http import urlopen_with_retry


_INDEX_TYPES = (
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
)

#: Manifest media types accepted when resolving a tag.  Listing the index
#: types first makes the registry return a multi-platform image's index
#: rather than one platform's manifest.
_MANIFEST_ACCEPT = ", ".join(
    [
        *_INDEX_TYPES,
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)


class RegistryError(Exception):
    """A registry response cannot be used to resolve a digest."""


def _registry_api(registry: str, repository: str) -> tuple[str, str]:
    """Return the registry API host and repository path for an image.

    Docker Hub serves its API from ``registry-1.docker.io``, and official
    images live under ``library/``.
    """
    if registry == "docker.io":
        if "/" not in repository:
            repository = f"library/{repository}"
        return "registry-1.docker.io", repository
    return registry, repository


def _bearer_token(challenge: str) -> str:
    """Fetch an anonymous token for a ``WWW-Authenticate`` challenge.

    Raises:
        RegistryError: If the challenge or token response is unusable.
        OSError: If the token request fails.
    """
    scheme, _, params = challenge.partition(" ")
    if scheme.lower() != "bearer":
        raise RegistryError(f"Unsupported authentication: {challenge!r}")
    fields = dict(re.findall(r'(\w+)="([^"]*)"', params))
    realm = fields.pop("realm", "")
    if not realm.startswith("https://"):
        raise RegistryError(f"Unsupported token realm: {realm!r}")
    url = f"{realm}?{urlencode(fields)}" if fields else realm
    with urlopen_with_retry(Request(url)) as response:
        body = response.read()
    try:
        data = json.loads(body)
    except ValueError as e:
        raise RegistryError("Token response is not JSON") from e
    if not isinstance(data, dict):
        raise RegistryError("Token response is not a JSON object")
    token = data.get("token") or data.get("access_token")
    if not isinstance(token, str) or not token:
        raise RegistryError("Token response has no token")
    return token


def _head_digest(url: str, headers: dict[str, str]) -> str:
    """Return the index digest from a manifest HEAD request.

    Raises:
        RegistryError: If the response is not a multi-platform index or
            carries no sha256 digest.
        OSError: If the request fails.
    """
    request = Request(url, method="HEAD", headers=headers)
    with urlopen_with_retry(request) as response:
        digest = response.headers.get("Docker-Content-Digest")
        content_type = response.headers.get("Content-Type", "")
    media_type = content_type.split(";", 1)[0].strip()
    if media_type not in _INDEX_TYPES:
        raise RegistryError(
            f"Not a multi-platform index: {media_type or 'no Content-Type'}"
        )
    if not isinstance(digest, str) or not DIGEST_RE.fullmatch(digest):
        raise RegistryError(f"No sha256 digest in response: {digest!r}")
    return digest


def resolve_digest(ref: ImageReference) -> str:
    """Look up the digest of the multi-platform index a tag points at.

    Uses HEAD requests, which do not download the manifest (nor count
    against Docker Hub's pull rate limit), and an anonymous token if the
    registry asks for one.

    Raises:
        RegistryError: If the reference has no registry or tag, or the
            registry's responses are unusable.
        OSError: If a request fails.
        http.client.HTTPException: If a response is malformed.
    """
    if ref.registry is None or ref.tag is None:
        raise RegistryError("Reference needs a registry and a tag")
    host, repository = _registry_api(ref.registry, ref.repository)
    url = f"https://{host}/v2/{repository}/manifests/{ref.tag}"
    headers = {"Accept": _MANIFEST_ACCEPT}
    try:
        return _head_digest(url, headers)
    except HTTPError as e:
        if e.code != 401:
            raise
        challenge = e.headers.get("WWW-Authenticate", "")
    headers["Authorization"] = f"Bearer {_bearer_token(challenge)}"
    return _head_digest(url, headers)


def _short_digest(digest: str | None) -> str:
    """Abbreviate a digest for display (``sha256:`` + 12 hex digits)."""
    return (digest or "")[:19]


def _replace_reference(
    content: str, reference: str, new: str
) -> tuple[str, int]:
    """Replace whole occurrences of an image reference in *content*.

    An occurrence preceded or followed by more reference characters (a
    registry path, a longer tag, a digest) is a different reference and
    is left alone.

    Returns:
        The new content and the number of occurrences replaced.
    """
    boundary = r"[\w.:/@-]"
    pattern = f"(?<!{boundary}){re.escape(reference)}(?!{boundary})"
    return re.subn(pattern, lambda _: new, content)


@dataclass
class _Results:
    """Report lines of a check, by outcome."""

    errors: list[str] = field(default_factory=list)
    invalid: list[str] = field(default_factory=list)
    unpinned: list[str] = field(default_factory=list)
    outdated: list[str] = field(default_factory=list)
    up_to_date: list[str] = field(default_factory=list)


def _check_reference(
    path: Path, reference: str, content: str, results: _Results, *, fix: bool
) -> str:
    """Check one base image reference of a Dockerfile.

    Returns:
        *content*, with the reference rewritten if *fix* and it needs it.
    """
    ref = parse_reference(reference)
    missing_digest = (
        ref.registry is not None and ref.tag is not None and not ref.digest
    )
    problems = pin_problems(reference)
    if problems and not missing_digest:
        results.invalid.append(f"  {path}: {reference} — {'; '.join(problems)}")
        return content

    try:
        current = resolve_digest(ref)
    except (OSError, http.client.HTTPException, RegistryError) as e:
        results.errors.append(f"  {path}: {reference} — cannot resolve: {e}")
        return content

    name = reference.partition("@")[0]
    if current == ref.digest:
        results.up_to_date.append(f"  {path}: {name}")
        return content
    if fix:
        content, count = _replace_reference(
            content, reference, f"{name}@{current}"
        )
        if not count:
            results.errors.append(
                f"  {path}: {reference} — cannot rewrite: not written"
                " literally in the file (assembled from build arguments?)"
            )
            return content
    if missing_digest:
        results.unpinned.append(f"  {path}: {name} → {_short_digest(current)}")
    else:
        results.outdated.append(
            f"  {path}: {name}"
            f" ({_short_digest(ref.digest)} → {_short_digest(current)})"
        )
    return content


def _check_file(path: Path, results: _Results, *, fix: bool) -> None:
    """Check one Dockerfile's pins, rewriting it if *fix* and needed."""
    content = path.read_text()
    try:
        images = base_images(content)
    except DockerfileError as e:
        results.errors.append(f"  {path}: {e}")
        return
    if not images:
        results.errors.append(f"  {path}: no base image found")
        return

    new_content = content
    for reference in dict.fromkeys(images):
        new_content = _check_reference(
            path, reference, new_content, results, fix=fix
        )
    if new_content != content:
        path.write_text(new_content)


def _print_section(title: str, lines: list[str]) -> None:
    """Print a titled list of report lines, if there are any."""
    if lines:
        print(f"{title}:")
        for line in lines:
            print(line)
        print()


def _report(results: _Results, *, fix: bool, verbose: bool) -> int:
    """Print the results and return the exit code."""
    _print_section("Errors", results.errors)
    _print_section(
        "Cannot be pinned automatically (fix by hand)", results.invalid
    )
    _print_section("Fixed (pinned)" if fix else "Unpinned", results.unpinned)
    _print_section("Fixed (updated)" if fix else "Outdated", results.outdated)
    if verbose:
        _print_section("Up to date", results.up_to_date)

    fixable = len(results.unpinned) + len(results.outdated)
    if not (fixable or results.invalid or results.errors):
        if not verbose:
            count = len(results.up_to_date)
            print(f"All {count} pinned image(s) up to date.")
        return 0

    if fix and fixable:
        print(f"Fixed {fixable} pin(s).")
    return 0 if fix and not (results.invalid or results.errors) else 1


def check_image_pins(
    *,
    fix: bool = False,
    verbose: bool = False,
    root: Path | None = None,
) -> int:
    """Check and optionally update the bundled Dockerfiles' pins.

    Args:
        fix: Update outdated digests and add missing ones in place.
        verbose: Show up-to-date pins.
        root: Repository root. Defaults to the current directory.

    Returns:
        0 if all pins are current (or were fixed), 1 otherwise.
    """
    files = find_dockerfiles(root)
    if not files:
        print("No bundled Dockerfiles found.")
        return 0
    results = _Results()
    for path in files:
        _check_file(path, results, fix=fix)
    return _report(results, fix=fix, verbose=verbose)


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Check digest pinning of bundled Dockerfiles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Update outdated digests in place (review diff before committing)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show up-to-date pins too",
    )
    args = parser.parse_args()
    return check_image_pins(fix=args.fix, verbose=args.verbose)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
