# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Base image references of the bundled Dockerfiles, and how they are pinned.

Every image a bundled Dockerfile (under ``airut/_bundled/``) builds from
must be named fully qualified, with a tag, and pinned by digest, e.g.
``docker.io/library/python:3.13-slim@sha256:<digest>``.  Rootless podman
resolves short names differently from host to host, and a tag alone
trusts whatever it points at on the day of the build.  The tag records
what the digest stands for, so ``scripts/check_image_pins.py`` can keep
the digest current.

A ``FROM`` may take its image from a build argument; the argument's
default is then the pinned reference (``ARG BASE_IMAGE=<reference>``
followed by ``FROM ${BASE_IMAGE}``).

This module only parses; it needs no network access.
"""

import re
from dataclasses import dataclass
from pathlib import Path


#: Directory whose Dockerfiles are checked, relative to the repo root.
BUNDLED_DIR = Path("airut/_bundled")

DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")
_VARIABLE_RE = re.compile(r"\$(?:\{(\w+)\}|(\w+))")


class DockerfileError(Exception):
    """A Dockerfile's base images cannot be determined."""


@dataclass(frozen=True)
class ImageReference:
    """An image reference split into its parts.

    Attributes:
        registry: Registry host, or None if the name has none (a short
            name).
        repository: Repository path within the registry.
        tag: Tag, or None.
        digest: Digest (``algorithm:hex``), or None.
    """

    registry: str | None
    repository: str
    tag: str | None
    digest: str | None


def is_dockerfile(name: str) -> bool:
    """Whether a file name is a Dockerfile by the usual conventions."""
    return (
        name in ("Dockerfile", "Containerfile")
        or name.startswith(("Dockerfile.", "Containerfile."))
        or name.endswith(
            (".dockerfile", ".Dockerfile", ".containerfile", ".Containerfile")
        )
    )


def find_dockerfiles(root: Path | None = None) -> list[Path]:
    """Find the bundled Dockerfiles.

    Args:
        root: Repository root. Defaults to the current directory.
    """
    base = (root or Path(".")) / BUNDLED_DIR
    return sorted(
        path
        for path in base.rglob("*")
        if path.is_file() and is_dockerfile(path.name)
    )


def _split_instruction(line: str) -> tuple[str, str]:
    """Split an instruction into its upper-cased keyword and arguments."""
    keyword, *args = line.split(None, 1)
    return keyword.upper(), args[0].strip() if args else ""


def _instructions(dockerfile: str) -> list[tuple[str, str]]:
    """Split a Dockerfile into (keyword, arguments) pairs.

    Joins continuation lines and drops comments and blank lines, also
    within continuations.  Parser directives (``# escape=``) and heredocs
    are not interpreted: a heredoc line starting with ``FROM`` is taken
    for an instruction, which can only add images to check.
    """
    instructions: list[tuple[str, str]] = []
    pending = ""
    for line in dockerfile.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1] + " "
            continue
        instructions.append(_split_instruction(pending + stripped))
        pending = ""
    if pending.strip():
        instructions.append(_split_instruction(pending))
    return instructions


def _substitute(value: str, build_args: dict[str, str | None]) -> str:
    """Substitute ``$NAME`` and ``${NAME}`` by build argument values.

    Raises:
        DockerfileError: If an argument is undeclared or has no value,
            or the value uses another form of substitution.
    """

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(2)
        value = build_args.get(name)
        if value is None:
            raise DockerfileError(
                f"FROM uses build argument {name} without a default"
            )
        return value

    result = _VARIABLE_RE.sub(replace, value)
    if "$" in result:
        raise DockerfileError(f"Unsupported substitution in FROM {value}")
    return result


def base_images(
    dockerfile: str, build_args: dict[str, str] | None = None
) -> list[str]:
    """Return the images a Dockerfile's FROM instructions build from.

    Build arguments in FROM are replaced by their value: the one given
    in *build_args* (as ``--build-arg`` would), else the default of the
    ``ARG`` declaring them before the first FROM.  ``scratch`` and FROMs
    naming an earlier stage are skipped.

    Args:
        dockerfile: Dockerfile content.
        build_args: Build argument values overriding ``ARG`` defaults.

    Raises:
        DockerfileError: If a FROM cannot be resolved.
    """
    overrides = build_args or {}
    values: dict[str, str | None] = {}
    stages: set[str] = set()
    images: list[str] = []
    seen_from = False
    for keyword, args in _instructions(dockerfile):
        if keyword == "ARG" and not seen_from:
            for declaration in args.split():
                name, sep, default = declaration.partition("=")
                if name in overrides:
                    values[name] = overrides[name]
                else:
                    values[name] = default.strip("\"'") if sep else None
        elif keyword == "FROM":
            seen_from = True
            words = [w for w in args.split() if not w.startswith("--")]
            if not words:
                raise DockerfileError("FROM without an image")
            image = _substitute(words[0], values)
            # Only earlier stages can be referenced: check before adding
            # this stage's own name.
            if image != "scratch" and image.lower() not in stages:
                images.append(image)
            if len(words) >= 3 and words[1].upper() == "AS":
                stages.add(words[2].lower())
    return images


def parse_reference(reference: str) -> ImageReference:
    """Split an image reference into registry, repository, tag, digest.

    The first path component is the registry if it looks like a host
    (contains ``.`` or ``:``, or is ``localhost``), as in Docker's and
    podman's reference parsing.
    """
    name, _, digest = reference.partition("@")
    tag: str | None = None
    colon = name.rfind(":")
    if colon > name.rfind("/"):
        name, tag = name[:colon], name[colon + 1 :]
    first, sep, rest = name.partition("/")
    if sep and ("." in first or ":" in first or first == "localhost"):
        return ImageReference(first, rest, tag, digest or None)
    return ImageReference(None, name, tag, digest or None)


def pin_problems(reference: str) -> list[str]:
    """List why an image reference is not a fully qualified pin.

    Returns:
        Problems found; empty if the reference names a registry, a tag
        and a sha256 digest.
    """
    ref = parse_reference(reference)
    problems: list[str] = []
    if ref.registry is None:
        problems.append("not fully qualified (no registry)")
    if ref.tag is None:
        problems.append("no tag (the tag records what the digest stands for)")
    if ref.digest is None or not DIGEST_RE.fullmatch(ref.digest):
        problems.append("not pinned by a sha256 digest")
    return problems
