# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Repository trees for build context collection.

:class:`FilesystemTree` reads a checkout on disk (CLI) and
:class:`GitTree` one commit of a git repository (gateway).  Both hide
``.git`` and report nested repositories as :attr:`EntryKind.OTHER`, so
the same repository state yields the same build context either way.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

from airut.sandbox.build_context import BuildContextError, EntryKind, TreeEntry


def _is_git_dir(name: str) -> bool:
    """Whether *name* is ``.git``, which git refuses in any case."""
    return name.lower() == ".git"


class FilesystemTree:
    """:class:`ContextTree` over a directory on disk.

    Matches what a git tree of the same checkout contains: ``.git`` is
    hidden, and nested repositories (submodule checkouts) are
    :attr:`EntryKind.OTHER`, like gitlinks.

    Args:
        root: Repository root.  Symlinks are resolved within it.  The
            root itself may be a symlink.
    """

    def __init__(self, root: Path) -> None:
        self._root = root

    def _path(self, path: str) -> Path:
        return self._root / path if path else self._root

    def stat(self, path: str) -> TreeEntry | None:
        """Return the entry at *path* without following it, or None."""
        if not path:
            return TreeEntry(EntryKind.DIRECTORY)
        if any(_is_git_dir(part) for part in path.split("/")):
            return None
        try:
            info = os.lstat(self._path(path))
        except (FileNotFoundError, NotADirectoryError):
            return None
        mode = info.st_mode
        if stat.S_ISLNK(mode):
            return TreeEntry(EntryKind.SYMLINK)
        if stat.S_ISDIR(mode):
            if os.path.lexists(self._path(path) / ".git"):
                return TreeEntry(EntryKind.OTHER)
            return TreeEntry(EntryKind.DIRECTORY)
        if stat.S_ISREG(mode):
            executable = bool(mode & stat.S_IXUSR)
            return TreeEntry(EntryKind.FILE, executable, info.st_size)
        return TreeEntry(EntryKind.OTHER)

    def list_dir(self, path: str) -> list[str]:
        """Return the names in directory *path*, sorted."""
        names = os.listdir(self._path(path))
        return sorted(n for n in names if not _is_git_dir(n))

    def read(self, path: str) -> bytes:
        """Return the content of file *path*."""
        return self._path(path).read_bytes()

    def readlink(self, path: str) -> str:
        """Return the target of symlink *path*."""
        return os.readlink(self._path(path))


_GIT_KINDS = {
    b"100644": (EntryKind.FILE, False),
    b"100755": (EntryKind.FILE, True),
    b"120000": (EntryKind.SYMLINK, False),
    b"040000": (EntryKind.DIRECTORY, False),
}


class GitTree:
    """:class:`ContextTree` over one commit of a git repository.

    Directory listings also answer :meth:`stat` for their entries, so
    collecting a directory costs one ``git ls-tree`` per directory plus
    one ``git cat-file`` per file.

    Args:
        repo: Repository (bare or not) containing the commit.
        commit: Commit to read.
    """

    def __init__(self, repo: Path, commit: str) -> None:
        self._repo = repo
        self._commit = commit
        # The commit is immutable, so everything read can be cached.
        self._entries: dict[str, TreeEntry | None] = {
            "": TreeEntry(EntryKind.DIRECTORY)
        }
        self._listings: dict[str, list[str]] = {}
        self._contents: dict[str, bytes] = {}

    def _git(self, *args: str) -> bytes:
        cmd = ["git", "--literal-pathspecs", "-C", str(self._repo), *args]
        try:
            return subprocess.run(cmd, check=True, capture_output=True).stdout
        except subprocess.CalledProcessError as e:
            detail = e.stderr.decode(errors="replace").strip()
            raise BuildContextError(f"git {args[0]} failed: {detail}") from e

    def _ls_tree(self, path: str) -> list[tuple[str, TreeEntry]]:
        """Return (path, entry) for *path*, or its contents if it ends in /."""
        output = self._git("ls-tree", "-l", "-z", self._commit, "--", path)
        records = []
        for record in output.split(b"\0"):
            if record:
                # <mode> <type> <object> <size, padded or "-">\t<path>
                meta, _, name = record.partition(b"\t")
                fields = meta.split()
                kind, executable = _GIT_KINDS.get(
                    fields[0], (EntryKind.OTHER, False)
                )
                size = int(fields[3]) if fields[3].isdigit() else 0
                entry = TreeEntry(kind, executable, size)
                records.append((os.fsdecode(name), entry))
        return records

    def stat(self, path: str) -> TreeEntry | None:
        """Return the entry at *path* without following it, or None."""
        if path not in self._entries:
            records = self._ls_tree(path)
            self._entries[path] = records[0][1] if records else None
        return self._entries[path]

    def list_dir(self, path: str) -> list[str]:
        """Return the names in directory *path*, sorted."""
        if path not in self._listings:
            prefix = f"{path}/" if path else ""
            names = []
            for full, entry in self._ls_tree(prefix or "."):
                self._entries[full] = entry
                names.append(full.removeprefix(prefix))
            self._listings[path] = sorted(names)
        return self._listings[path]

    def read(self, path: str) -> bytes:
        """Return the content of file *path*."""
        if path not in self._contents:
            self._contents[path] = self._git(
                "cat-file", "blob", f"{self._commit}:{path}"
            )
        return self._contents[path]

    def readlink(self, path: str) -> str:
        """Return the target of symlink *path*."""
        return os.fsdecode(self.read(path))
