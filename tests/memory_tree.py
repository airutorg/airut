# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""In-memory repository tree for tests that mock the git mirror."""

from unittest.mock import MagicMock

from airut.sandbox.build_context import EntryKind, TreeEntry


class MemoryTree:
    """``ContextTree`` over a dict of file path to content (no symlinks).

    Directories are implied by the file paths.
    """

    def __init__(self, files: dict[str, bytes]) -> None:
        self._files = files
        self._dirs = {""}
        for path in files:
            parts = path.split("/")
            for i in range(1, len(parts)):
                self._dirs.add("/".join(parts[:i]))

    def stat(self, path: str) -> TreeEntry | None:
        """Return the entry at *path*, or None."""
        if path in self._files:
            return TreeEntry(EntryKind.FILE, size=len(self._files[path]))
        if path in self._dirs:
            return TreeEntry(EntryKind.DIRECTORY)
        return None

    def list_dir(self, path: str) -> list[str]:
        """Return the names directly in *path*."""
        prefix = f"{path}/" if path else ""
        names = {
            p.removeprefix(prefix).split("/")[0]
            for p in (*self._files, *self._dirs)
            if p.startswith(prefix) and p != path
        }
        return sorted(names)

    def read(self, path: str) -> bytes:
        """Return the content of *path*."""
        return self._files[path]

    def readlink(self, path: str) -> str:
        """MemoryTree has no symlinks."""
        raise AssertionError(f"unexpected readlink({path!r})")


def use_repo_files(mirror: MagicMock, files: dict[str, bytes]) -> MemoryTree:
    """Make ``mirror.default_branch_tree()`` yield a tree of *files*.

    Args:
        mirror: Mock ``GitMirrorCache``.
        files: Repository path to content.

    Returns:
        The tree the mirror yields.
    """
    tree = MemoryTree(files)
    mirror.default_branch_tree.return_value.__enter__.return_value = tree
    return tree
