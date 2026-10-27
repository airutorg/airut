# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/sandbox/build_context.py -- build context collection."""

import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from airut.sandbox import build_context
from airut.sandbox.build_context import (
    MAX_SYMLINKS,
    BuildContextError,
    EntryKind,
    TreeEntry,
    collect_context_files,
    resolve,
)
from airut.sandbox.context_trees import FilesystemTree, GitTree


CONTAINER = ".airut/container"


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """Repository with a Dockerfile in .airut/container."""
    container = tmp_path / CONTAINER
    container.mkdir(parents=True)
    (container / "Dockerfile").write_text("FROM nixos/nix\n")
    return tmp_path


def _collect(repo: Path, directory: str = CONTAINER) -> dict[str, bytes]:
    return collect_context_files(FilesystemTree(repo), directory).files


def _link(repo: Path, path: str, target: str) -> None:
    link = repo / path
    link.parent.mkdir(parents=True, exist_ok=True)
    link.symlink_to(target)


class TestCollectContextFiles:
    """Tests for collect_context_files over a FilesystemTree."""

    def test_plain_files(self, repo: Path) -> None:
        """Files directly in the directory are collected."""
        (repo / CONTAINER / "gitconfig").write_text("[user]\n")

        assert _collect(repo) == {
            "Dockerfile": b"FROM nixos/nix\n",
            "gitconfig": b"[user]\n",
        }

    def test_subdirectories(self, repo: Path) -> None:
        """Subdirectories are collected recursively, keyed by path."""
        (repo / CONTAINER / "nix" / "pkgs").mkdir(parents=True)
        (repo / CONTAINER / "nix" / "pkgs" / "tool.nix").write_text("{ }")

        files = _collect(repo)

        assert files["nix/pkgs/tool.nix"] == b"{ }"

    def test_executable_bit(self, repo: Path) -> None:
        """Executable files are reported as such."""
        script = repo / CONTAINER / "setup.sh"
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)

        context = collect_context_files(FilesystemTree(repo), CONTAINER)

        assert context.executable == frozenset({"setup.sh"})

    def test_file_symlink_outside_directory(self, repo: Path) -> None:
        """A symlink to a file elsewhere in the repo is followed."""
        (repo / "flake.nix").write_text("{ outputs = _: { }; }")
        (repo / "flake.lock").write_text("{}")
        _link(repo, f"{CONTAINER}/flake.nix", "../../flake.nix")
        _link(repo, f"{CONTAINER}/flake.lock", "../../flake.lock")

        files = _collect(repo)

        assert files["flake.nix"] == b"{ outputs = _: { }; }"
        assert files["flake.lock"] == b"{}"

    def test_directory_symlink(self, repo: Path) -> None:
        """A symlink to a directory includes the directory's contents."""
        (repo / "nix").mkdir()
        (repo / "nix" / "shell.nix").write_text("{ }")
        _link(repo, f"{CONTAINER}/nix", "../../nix")

        assert _collect(repo)["nix/shell.nix"] == b"{ }"

    def test_executable_through_symlink(self, repo: Path) -> None:
        """The executable bit comes from the symlink's target."""
        (repo / "scripts").mkdir()
        target = repo / "scripts" / "setup.sh"
        target.write_text("#!/bin/sh\n")
        target.chmod(0o755)
        _link(repo, f"{CONTAINER}/setup.sh", "../../scripts/setup.sh")

        context = collect_context_files(FilesystemTree(repo), CONTAINER)

        assert context.executable == frozenset({"setup.sh"})

    def test_symlink_chain_and_intermediate_directory_link(
        self, repo: Path
    ) -> None:
        """Chains and symlinked directories inside targets resolve."""
        (repo / "real").mkdir()
        (repo / "real" / "file").write_text("data")
        _link(repo, "alias", "real")
        _link(repo, "hop", "alias/file")
        _link(repo, f"{CONTAINER}/file", "../../hop")

        assert _collect(repo)["file"] == b"data"

    def test_directory_itself_a_symlink(self, repo: Path) -> None:
        """The context directory may itself be a symlink."""
        _link(repo, ".devcontainer", CONTAINER)

        assert _collect(repo, ".devcontainer") == {
            "Dockerfile": b"FROM nixos/nix\n"
        }

    def test_same_directory_twice_is_not_a_cycle(self, repo: Path) -> None:
        """Two links to one directory are both collected."""
        (repo / "nix").mkdir()
        (repo / "nix" / "a.nix").write_text("a")
        _link(repo, f"{CONTAINER}/one", "../../nix")
        _link(repo, f"{CONTAINER}/two", "../../nix")

        files = _collect(repo)

        assert files["one/a.nix"] == files["two/a.nix"] == b"a"

    @pytest.mark.parametrize(
        ("target", "message"),
        [
            ("/etc/passwd", "absolute target"),
            ("../../../outside", "outside the repository"),
            ("../../missing", "does not exist"),
            (".", "cycle"),
            ("..", "cycle"),
            ("../..", "cycle"),
        ],
        ids=["absolute", "escape", "dangling", "self", "parent", "root"],
    )
    def test_rejected_symlinks(
        self, repo: Path, target: str, message: str
    ) -> None:
        """Symlinks that cannot be part of the context are errors."""
        _link(repo, f"{CONTAINER}/link", target)

        with pytest.raises(BuildContextError, match=message):
            _collect(repo)

    def test_cycle_through_nested_link(self, repo: Path) -> None:
        """A link in a subdirectory back to the context is a cycle."""
        _link(repo, f"{CONTAINER}/sub/back", "..")

        with pytest.raises(BuildContextError, match="cycle"):
            _collect(repo)

    def test_symlink_loop(self, repo: Path) -> None:
        """Symlinks pointing at each other stop at the link limit."""
        _link(repo, "a", "b")
        _link(repo, "b", "a")
        _link(repo, f"{CONTAINER}/link", "../../a")

        with pytest.raises(BuildContextError, match="too many levels"):
            _collect(repo)

    def test_other_entry_types_rejected(self, repo: Path) -> None:
        """Entries that are not files, directories or links are errors."""
        os.mkfifo(repo / CONTAINER / "pipe")

        with pytest.raises(BuildContextError, match="not a regular file"):
            _collect(repo)

    def test_git_directory_never_included(self, repo: Path) -> None:
        """.git is hidden, even when the context is the repo root."""
        (repo / ".git").mkdir()
        (repo / ".git" / "config").write_text("[http] extraheader = token")
        _link(repo, f"{CONTAINER}/config", "../../.git/config")

        with pytest.raises(BuildContextError, match="does not exist"):
            _collect(repo)
        (repo / CONTAINER / "config").unlink()
        assert ".git/config" not in _collect(repo, ".")

    def test_nested_repository_rejected(self, repo: Path) -> None:
        """A nested checkout (e.g. a submodule) is rejected, as in git."""
        (repo / CONTAINER / "vendor" / ".git").mkdir(parents=True)

        with pytest.raises(BuildContextError, match="submodule"):
            _collect(repo)

    @pytest.mark.parametrize(
        ("target", "message"),
        [
            ("../../missing/../flake.nix", "'missing' .* does not exist"),
            ("../../flake.nix/../flake.nix", "'flake.nix' .* not a directory"),
        ],
        ids=["through-missing", "through-file"],
    )
    def test_link_must_descend_through_directories(
        self, repo: Path, target: str, message: str
    ) -> None:
        """Like the OS, a link cannot pass through a non-directory."""
        (repo / "flake.nix").write_text("{ }")
        _link(repo, f"{CONTAINER}/flake.nix", target)

        with pytest.raises(BuildContextError, match=message):
            _collect(repo)

    def test_git_directory_hidden_in_any_case(self, repo: Path) -> None:
        """.git is hidden whatever its case, as git refuses it in trees."""
        (repo / ".GIT").mkdir()
        (repo / ".GIT" / "config").write_text("token")
        _link(repo, f"{CONTAINER}/config", "../../.GIT/config")

        with pytest.raises(BuildContextError, match="does not exist"):
            _collect(repo)

    def test_root_may_be_a_symlink(self, tmp_path: Path) -> None:
        """The tree root itself may be a symlink to the repository."""
        real = tmp_path / "real"
        (real / "ctx").mkdir(parents=True)
        (real / "ctx" / "Dockerfile").write_text("FROM x\n")
        (tmp_path / "link").symlink_to("real")

        files = collect_context_files(FilesystemTree(tmp_path / "link"), "ctx")

        assert files.files == {"Dockerfile": b"FROM x\n"}

    def test_fan_out_limited(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Directory links that double at every level hit the entry limit."""
        monkeypatch.setattr(build_context, "MAX_CONTEXT_ENTRIES", 100)
        depth = 8  # 2**8 paths to the innermost directory
        for level in range(depth):
            (repo / f"d{level}").mkdir()
            for name in ("a", "b"):
                _link(repo, f"d{level}/{name}", f"../d{level + 1}")
        (repo / f"d{depth}").mkdir()
        (repo / f"d{depth}" / "leaf").write_text("x")
        _link(repo, f"{CONTAINER}/fan", "../../d0")

        with pytest.raises(BuildContextError, match="more than 100 files"):
            _collect(repo)

    def test_size_limited_before_reading(
        self, repo: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Oversized contexts are rejected before the file is read."""
        monkeypatch.setattr(build_context, "MAX_CONTEXT_BYTES", 20)
        (repo / CONTAINER / "big").write_bytes(b"x" * 20)
        read = FilesystemTree.read

        def guarded_read(self: FilesystemTree, path: str) -> bytes:
            assert not path.endswith("big"), "oversized file was read"
            return read(self, path)

        monkeypatch.setattr(FilesystemTree, "read", guarded_read)

        with pytest.raises(BuildContextError, match="larger than 20 bytes"):
            _collect(repo)

    def test_missing_directory(self, repo: Path) -> None:
        """A missing context directory is an error."""
        with pytest.raises(BuildContextError, match="not a directory"):
            _collect(repo, "missing")

    def test_directory_is_a_file(self, repo: Path) -> None:
        """A context 'directory' that is a file is an error."""
        with pytest.raises(BuildContextError, match="not a directory"):
            _collect(repo, f"{CONTAINER}/Dockerfile")


class _FakeTree:
    """In-memory ContextTree for resolution edge cases."""

    def __init__(self, entries: dict[str, TreeEntry | str]) -> None:
        # A str value is a symlink target.
        self._entries = entries

    def stat(self, path: str) -> TreeEntry | None:
        if path == "":
            return TreeEntry(EntryKind.DIRECTORY)
        value = self._entries.get(path)
        if isinstance(value, str):
            return TreeEntry(EntryKind.SYMLINK)
        return value

    def list_dir(self, path: str) -> list[str]:
        raise NotImplementedError

    def read(self, path: str) -> bytes:
        raise NotImplementedError

    def readlink(self, path: str) -> str:
        value = self._entries[path]
        assert isinstance(value, str)
        return value


class TestResolve:
    """Tests for resolve()."""

    def test_dot_and_dotdot_components(self) -> None:
        """Plain . and .. components are normalized."""
        tree = _FakeTree({"a": TreeEntry(EntryKind.DIRECTORY)})

        assert resolve(tree, "./a/../a/./b") == "a/b"

    def test_dotdot_after_symlink_is_physical(self) -> None:
        """'..' after a symlink applies to the link's target, as in the OS."""
        tree = _FakeTree(
            {
                "x": TreeEntry(EntryKind.DIRECTORY),
                "x/y": TreeEntry(EntryKind.DIRECTORY),
                "link": "x/y",
            }
        )

        assert resolve(tree, "link/../z") == "x/z"

    def test_link_limit(self) -> None:
        """MAX_SYMLINKS links in a chain resolve; one more fails."""
        chain: dict[str, TreeEntry | str] = {
            f"l{i}": f"l{i + 1}" for i in range(MAX_SYMLINKS)
        }
        chain[f"l{MAX_SYMLINKS}"] = TreeEntry(EntryKind.FILE)

        assert resolve(_FakeTree(chain), "l0") == f"l{MAX_SYMLINKS}"
        chain["start"] = "l0"
        with pytest.raises(BuildContextError, match="too many levels"):
            resolve(_FakeTree(chain), "start")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _commit_all(repo: Path) -> str:
    """Commit everything in *repo* (initialising it) and return the SHA."""
    if not (repo / ".git").exists():
        _git(repo, "init", "-q")
    _git(repo, "add", "-A")
    _git(
        repo,
        "-c",
        "user.name=Test",
        "-c",
        "user.email=test@example.com",
        "commit",
        "-q",
        "-m",
        "snapshot",
    )
    return _git(repo, "rev-parse", "HEAD")


class TestGitTree:
    """Tests for GitTree, against a real git repository."""

    def test_matches_filesystem_tree(self, repo: Path) -> None:
        """A commit and its checkout produce identical contexts."""
        (repo / "flake.nix").write_text("{ }")
        (repo / "nix").mkdir()
        (repo / "nix" / "shell.nix").write_text("shell")
        script = repo / CONTAINER / "bin" / "setup.sh"
        script.parent.mkdir()
        script.write_text("#!/bin/sh\n")
        script.chmod(0o755)
        _link(repo, f"{CONTAINER}/flake.nix", "../../flake.nix")
        _link(repo, f"{CONTAINER}/nix", "../../nix")
        commit = _commit_all(repo)

        from_git = collect_context_files(GitTree(repo, commit), CONTAINER)
        from_disk = collect_context_files(FilesystemTree(repo), CONTAINER)

        assert from_git == from_disk
        assert from_git.files == {
            "Dockerfile": b"FROM nixos/nix\n",
            "bin/setup.sh": b"#!/bin/sh\n",
            "flake.nix": b"{ }",
            "nix/shell.nix": b"shell",
        }
        assert from_git.executable == frozenset({"bin/setup.sh"})

    def test_reads_the_given_commit(self, repo: Path) -> None:
        """Later commits and uncommitted changes are not seen."""
        commit = _commit_all(repo)
        (repo / CONTAINER / "Dockerfile").write_text("FROM changed\n")
        _commit_all(repo)
        (repo / CONTAINER / "new").write_text("uncommitted")

        files = collect_context_files(GitTree(repo, commit), CONTAINER).files

        assert files == {"Dockerfile": b"FROM nixos/nix\n"}

    def test_root_listing(self, repo: Path) -> None:
        """The repository root can be listed."""
        commit = _commit_all(repo)

        assert GitTree(repo, commit).list_dir("") == [".airut"]

    def test_symlink_rules_apply(self, repo: Path) -> None:
        """Escaping symlinks are rejected for git trees too."""
        _link(repo, f"{CONTAINER}/link", "../../../outside")
        commit = _commit_all(repo)

        with pytest.raises(BuildContextError, match="outside the repository"):
            collect_context_files(GitTree(repo, commit), CONTAINER)

    def test_submodule_rejected(self, repo: Path) -> None:
        """A submodule (gitlink) in the context is an error."""
        commit = _commit_all(repo)
        _git(
            repo,
            "update-index",
            "--add",
            "--cacheinfo",
            f"160000,{commit},{CONTAINER}/sub",
        )
        _git(
            repo,
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-q",
            "-m",
            "add submodule",
        )
        commit = _git(repo, "rev-parse", "HEAD")

        with pytest.raises(BuildContextError, match="not a regular file"):
            collect_context_files(GitTree(repo, commit), CONTAINER)

    def test_unusual_names_match_filesystem_tree(self, repo: Path) -> None:
        """Names with tabs, newlines and non-UTF-8 bytes parse correctly."""
        container = repo / CONTAINER
        for name in ("tab\tname", "new\nline", os.fsdecode(b"caf\xe9")):
            (container / name).write_bytes(os.fsencode(name))
        commit = _commit_all(repo)

        from_git = collect_context_files(GitTree(repo, commit), CONTAINER)

        assert from_git == collect_context_files(
            FilesystemTree(repo), CONTAINER
        )
        assert len(from_git.files) == 4

    def test_listings_and_contents_cached(self, repo: Path) -> None:
        """Paths reached twice through symlinks are read from git once."""
        (repo / "nix").mkdir()
        (repo / "nix" / "a.nix").write_text("a")
        _link(repo, f"{CONTAINER}/one", "../../nix")
        _link(repo, f"{CONTAINER}/two", "../../nix")
        tree = GitTree(repo, _commit_all(repo))

        with patch.object(tree, "_git", wraps=tree._git) as git:
            files = collect_context_files(tree, CONTAINER).files

        assert files["one/a.nix"] == files["two/a.nix"] == b"a"
        calls = [c.args for c in git.call_args_list]
        assert sum(c[0] == "ls-tree" and c[-1] == "nix/" for c in calls) == 1
        assert sum(c[-1].endswith(":nix/a.nix") for c in calls) == 1

    def test_link_through_submodule_rejected(self, repo: Path) -> None:
        """Both trees reject a link into a submodule the same way."""
        (repo / "vendor" / "sub").mkdir(parents=True)
        (repo / "vendor" / "sub" / "file").write_text("inside")
        _commit_all(repo / "vendor" / "sub")
        _link(repo, f"{CONTAINER}/x", "../../vendor/sub/file")
        commit = _commit_all(repo)
        message = "'vendor/sub' .* not a directory"

        with pytest.raises(BuildContextError, match=message):
            collect_context_files(GitTree(repo, commit), CONTAINER)
        with pytest.raises(BuildContextError, match=message):
            collect_context_files(FilesystemTree(repo), CONTAINER)

    def test_sizes_from_ls_tree(self, repo: Path) -> None:
        """GitTree reports file sizes (used for the size budget)."""
        commit = _commit_all(repo)
        tree = GitTree(repo, commit)

        entry = tree.stat(f"{CONTAINER}/Dockerfile")
        listed = tree.list_dir(CONTAINER)

        assert entry == TreeEntry(EntryKind.FILE, size=len("FROM nixos/nix\n"))
        assert listed == ["Dockerfile"]
        assert tree.stat(CONTAINER) == TreeEntry(EntryKind.DIRECTORY)

    def test_git_failure(self, repo: Path) -> None:
        """Git errors surface as BuildContextError."""
        _commit_all(repo)
        tree = GitTree(repo, "0" * 40)

        with pytest.raises(BuildContextError, match="git ls-tree failed"):
            collect_context_files(tree, CONTAINER)
