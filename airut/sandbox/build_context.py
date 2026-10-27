# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Repo image build context collection.

A repo's container directory (``.airut/container/`` by default) is the
build context of its image.  Besides plain files it may contain
subdirectories and symlinks to files or directories elsewhere in the
repository -- e.g. ``flake.nix -> ../../flake.nix`` -- so an image can
be built from files that live outside the directory.  Symlinks are
resolved within the repository; absolute targets, targets outside the
repository, dangling links, cycles and other entry types (submodules,
sockets, ...) are errors.  ``.git`` is never part of a context.  The
number of entries and bytes collected is limited, so directory symlinks
fanning out (two links to a directory that links twice to the next...)
fail instead of exhausting time and memory.

The gateway reads the repository from a git commit and the CLI from
disk (see ``context_trees``).  Both go through the :class:`ContextTree`
protocol and the same resolution rules, so they produce identical build
contexts and image hashes.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Protocol

from airut.sandbox._image_cache import ImageBuildSpec


#: Maximum symlinks followed while resolving one path (as on Linux).
MAX_SYMLINKS = 40

#: Maximum files and directories visited while collecting a context.
MAX_CONTEXT_ENTRIES = 10_000

#: Maximum total size of the files in a context.
MAX_CONTEXT_BYTES = 256 * 1024 * 1024


class BuildContextError(Exception):
    """Raised when a build context cannot be collected."""


class EntryKind(enum.Enum):
    """Kind of a repository tree entry."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    OTHER = "other"


@dataclass(frozen=True)
class TreeEntry:
    """A repository tree entry.

    Attributes:
        kind: Entry kind.
        executable: Whether a file is executable.
        size: Size of a file in bytes.
    """

    kind: EntryKind
    executable: bool = False
    size: int = 0


class ContextTree(Protocol):
    """Read-only view of a repository.

    Paths are relative POSIX paths from the repository root, with no
    ``.`` or ``..`` components; ``""`` is the root.  Callers resolve
    symlinks before descending, so implementations never follow them;
    a path may still name a missing entry or lead through a file, in
    which case :meth:`stat` returns None.
    """

    def stat(self, path: str) -> TreeEntry | None:
        """Return the entry at *path* without following it, or None."""
        ...

    def list_dir(self, path: str) -> list[str]:
        """Return the names in directory *path*, sorted."""
        ...

    def read(self, path: str) -> bytes:
        """Return the content of file *path*."""
        ...

    def readlink(self, path: str) -> str:
        """Return the target of symlink *path*."""
        ...


@dataclass(frozen=True)
class ContextFiles:
    """Files collected from a build context directory.

    Attributes:
        files: Relative POSIX path in the context to file content.
        executable: Paths in ``files`` that are executable.
    """

    files: dict[str, bytes]
    executable: frozenset[str]


def _join(directory: str, name: str) -> str:
    return f"{directory}/{name}" if directory else name


def resolve(tree: ContextTree, path: str) -> str:
    """Resolve all symlinks in *path* within the repository.

    Args:
        tree: Repository tree.
        path: Relative POSIX path, possibly containing symlinks.

    Returns:
        The equivalent path without symlinks.  Its last component may
        not exist; every other component is a real directory.

    Raises:
        BuildContextError: If resolution leaves the repository, passes
            through something that is not a directory (a file, a
            submodule, a missing entry), meets an absolute symlink
            target, or follows too many symlinks.
    """
    pending = list(reversed(path.split("/")))
    resolved: list[str] = []
    followed = 0
    while pending:
        part = pending.pop()
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise BuildContextError(
                    f"{path!r} resolves to outside the repository"
                )
            resolved.pop()
            continue
        candidate = _join("/".join(resolved), part)
        entry = tree.stat(candidate)
        if entry is None or entry.kind is not EntryKind.SYMLINK:
            # Descending (or "..") needs a directory, as in the OS.
            if any(p not in ("", ".") for p in pending):
                if entry is None:
                    raise BuildContextError(
                        f"{candidate!r} (in {path!r}) does not exist"
                    )
                if entry.kind is not EntryKind.DIRECTORY:
                    raise BuildContextError(
                        f"{candidate!r} (in {path!r}) is not a directory"
                    )
            resolved.append(part)
            continue
        followed += 1
        if followed > MAX_SYMLINKS:
            raise BuildContextError(f"too many levels of symlinks in {path!r}")
        target = tree.readlink(candidate)
        if target.startswith("/"):
            raise BuildContextError(
                f"symlink {candidate!r} has an absolute target {target!r}; "
                "use a relative path within the repository"
            )
        pending.extend(reversed(target.split("/")))
    return "/".join(resolved)


def collect_context_files(tree: ContextTree, directory: str) -> ContextFiles:
    """Collect every file under a build context directory.

    Subdirectories are included recursively and symlinks are replaced
    by what they point to, keyed by their path inside the context.

    Args:
        tree: Repository tree.
        directory: Context directory, relative to the repository root.

    Returns:
        The collected files.

    Raises:
        BuildContextError: If *directory* is not a directory, the
            context contains an unsupported entry (see module
            docstring), or it exceeds MAX_CONTEXT_ENTRIES or
            MAX_CONTEXT_BYTES.
    """
    root = resolve(tree, directory)
    entry = tree.stat(root)
    if entry is None or entry.kind is not EntryKind.DIRECTORY:
        raise BuildContextError(f"{directory!r} is not a directory")

    files: dict[str, bytes] = {}
    executable: set[str] = set()
    entries = 0
    size = 0
    # (directory, its path in the context, directories enclosing it)
    pending: list[tuple[str, str, tuple[str, ...]]] = [(root, "", (root,))]
    while pending:
        real_dir, prefix, ancestors = pending.pop()
        for name in tree.list_dir(real_dir):
            entries += 1
            if entries > MAX_CONTEXT_ENTRIES:
                raise BuildContextError(
                    f"{directory!r} has more than {MAX_CONTEXT_ENTRIES} "
                    "files and directories (counting each path through "
                    "a symlink)"
                )
            source = _join(real_dir, name)
            dest = prefix + name
            real, entry = _follow(tree, source)
            if entry.kind is EntryKind.FILE:
                size += entry.size
                if size > MAX_CONTEXT_BYTES:
                    raise BuildContextError(
                        f"{directory!r} is larger than {MAX_CONTEXT_BYTES} "
                        "bytes"
                    )
                files[dest] = tree.read(real)
                if entry.executable:
                    executable.add(dest)
                continue
            # A directory symlink that leads back to an enclosing
            # directory (or the repository root) would include itself
            # forever.
            if not real or any(
                a == real or a.startswith(real + "/") for a in ancestors
            ):
                raise BuildContextError(
                    f"symlink {source!r} points to {real or '.'!r}, which "
                    "contains it (cycle)"
                )
            pending.append((real, dest + "/", (*ancestors, real)))
    return ContextFiles(files=files, executable=frozenset(executable))


def _follow(tree: ContextTree, source: str) -> tuple[str, TreeEntry]:
    """Return the real path and entry *source* stands for in a context.

    Raises:
        BuildContextError: If *source* is a dangling symlink or not a
            file, directory or symlink.
    """
    entry = tree.stat(source)
    real = source
    if entry is not None and entry.kind is EntryKind.SYMLINK:
        real = resolve(tree, source)
        entry = tree.stat(real)
        if entry is None:
            raise BuildContextError(
                f"symlink {source!r} points to {real!r}, which does not exist"
            )
    if entry is None or entry.kind is EntryKind.OTHER:
        raise BuildContextError(
            f"{source!r} is not a regular file, directory or symlink "
            "(e.g. a submodule)"
        )
    return real, entry


def repo_image_spec(dockerfile: bytes, context: ContextFiles) -> ImageBuildSpec:
    """Return the repo image spec for a Dockerfile and its context.

    A top-level ``Dockerfile`` in the context is the Dockerfile itself,
    not a context file.  Gateway and CLI both build their spec here, so
    equal inputs give equal image hashes.

    Args:
        dockerfile: Dockerfile content.
        context: Collected build context.

    Returns:
        Spec of kind ``"repo"``.
    """
    files = {k: v for k, v in context.files.items() if k != "Dockerfile"}
    return ImageBuildSpec(
        kind="repo",
        dockerfile=dockerfile,
        context_files=files,
        executable_files=context.executable - {"Dockerfile"},
    )
