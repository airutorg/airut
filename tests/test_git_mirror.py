# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for GitMirrorCache."""

import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest

from airut.git_mirror import GitMirrorCache, MirrorError


@pytest.fixture
def temp_paths(tmp_path: Path):
    """Provide temporary paths for testing."""
    mirror_path = tmp_path / "mirror.git"
    lock_file = tmp_path / ".mirror.git.lock"
    dest_path = tmp_path / "dest"
    return {
        "mirror": mirror_path,
        "lock": lock_file,
        "dest": dest_path,
        "tmp": tmp_path,
    }


@pytest.fixture
def mirror_cache(temp_paths):
    """Create a GitMirrorCache instance."""
    return GitMirrorCache(
        mirror_path=temp_paths["mirror"],
        origin_url="git@github.com:user/repo.git",
    )


def test_init_success(temp_paths):
    """Test successful initialization."""
    cache = GitMirrorCache(
        mirror_path=temp_paths["mirror"],
        origin_url="git@github.com:user/repo.git",
    )

    assert cache.mirror_path == temp_paths["mirror"]
    assert cache.origin_url == "git@github.com:user/repo.git"
    assert cache.lock_file == temp_paths["lock"]


def test_init_empty_origin_url(temp_paths):
    """Test initialization with empty origin URL."""
    with pytest.raises(ValueError, match="Origin URL cannot be empty"):
        GitMirrorCache(mirror_path=temp_paths["mirror"], origin_url="")


def test_ensure_mirror_exists_creates_mirror(mirror_cache, temp_paths):
    """Test ensure_mirror_exists creates mirror if it doesn't exist."""
    with patch("subprocess.run") as mock_run:
        mirror_cache.ensure_mirror_exists()

        # Should run git clone --mirror
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [
            "git",
            "clone",
            "--mirror",
            "git@github.com:user/repo.git",
            str(temp_paths["mirror"]),
        ]


def test_ensure_mirror_exists_skips_if_exists(mirror_cache, temp_paths):
    """Test ensure_mirror_exists skips if mirror already exists."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mirror_cache.ensure_mirror_exists()

        # Should not run git clone
        mock_run.assert_not_called()


def test_ensure_mirror_exists_git_failure(mirror_cache, temp_paths):
    """Test ensure_mirror_exists handles git clone failure."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            128, "git", stderr="fatal: could not clone"
        )

        with pytest.raises(MirrorError, match="Failed to create git mirror"):
            mirror_cache.ensure_mirror_exists()


def test_update_mirror_success(mirror_cache, temp_paths):
    """Test update_mirror successfully updates from origin."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock") as mock_flock,
    ):
        mirror_cache.update_mirror()

        # Should acquire exclusive lock
        mock_flock.assert_called_once()
        args = mock_flock.call_args[0]
        assert args[1] == 2  # fcntl.LOCK_EX

        # Should run git remote update --prune
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["mirror"]),
            "remote",
            "update",
            "--prune",
        ]


def test_update_mirror_no_mirror(mirror_cache, temp_paths):
    """Test update_mirror fails if mirror doesn't exist."""
    with pytest.raises(MirrorError, match="Mirror does not exist"):
        mirror_cache.update_mirror()


def test_update_mirror_git_failure(mirror_cache, temp_paths):
    """Test update_mirror handles git failure."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run, patch("fcntl.flock"):
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="fatal: could not fetch"
        )

        with pytest.raises(MirrorError, match="Failed to update git mirror"):
            mirror_cache.update_mirror()


def test_clone_from_mirror_success(mirror_cache, temp_paths):
    """Test clone from mirror, sets origin, fetches, and resets."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock") as mock_flock,
    ):
        # Mock git symbolic-ref to return default branch
        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                # Mock return for git symbolic-ref
                mock_result = subprocess.CompletedProcess(
                    cmd, 0, stdout="origin/main\n", stderr=""
                )
                return mock_result
            # Default success for other commands
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        mirror_cache.clone_from_mirror(temp_paths["dest"])

        # Should acquire shared lock
        mock_flock.assert_called_once()
        args = mock_flock.call_args[0]
        assert args[1] == 1  # fcntl.LOCK_SH

        # Should run 5 git commands:
        # 1. clone from mirror
        # 2. set-url origin to GitHub
        # 3. fetch from GitHub
        # 4. symbolic-ref to detect default branch
        # 5. reset --hard to origin/main
        assert mock_run.call_count == 5

        # First call: git clone from local mirror
        # Note: No --reference flag to prevent alternates file
        args = mock_run.call_args_list[0][0][0]
        assert args == [
            "git",
            "clone",
            "--quiet",
            str(temp_paths["mirror"]),
            str(temp_paths["dest"]),
        ]

        # Second call: git remote set-url origin
        args = mock_run.call_args_list[1][0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["dest"]),
            "remote",
            "set-url",
            "origin",
            "git@github.com:user/repo.git",
        ]

        # Third call: git fetch origin --prune
        args = mock_run.call_args_list[2][0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["dest"]),
            "fetch",
            "origin",
            "--prune",
        ]

        # Fourth call: git symbolic-ref to detect default branch
        args = mock_run.call_args_list[3][0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["dest"]),
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "--short",
        ]

        # Fifth call: git reset --hard origin/main
        args = mock_run.call_args_list[4][0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["dest"]),
            "reset",
            "--hard",
            "origin/main",
        ]


def test_clone_from_mirror_no_mirror(mirror_cache, temp_paths):
    """Test clone_from_mirror fails if mirror doesn't exist."""
    with pytest.raises(MirrorError, match="Mirror does not exist"):
        mirror_cache.clone_from_mirror(temp_paths["dest"])


def test_clone_from_mirror_dest_exists(mirror_cache, temp_paths):
    """Test clone_from_mirror fails if destination exists."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)
    # Create destination
    temp_paths["dest"].mkdir(parents=True)

    with pytest.raises(ValueError, match="Destination already exists"):
        mirror_cache.clone_from_mirror(temp_paths["dest"])


def test_clone_from_mirror_git_failure(mirror_cache, temp_paths):
    """Test clone_from_mirror handles git failure."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run, patch("fcntl.flock"):
        mock_run.side_effect = subprocess.CalledProcessError(
            128, "git", stderr="fatal: could not clone"
        )

        with pytest.raises(MirrorError, match="Failed to clone from mirror"):
            mirror_cache.clone_from_mirror(temp_paths["dest"])


def test_concurrent_clones_use_shared_lock(mirror_cache, temp_paths):
    """Test that multiple clones can acquire shared lock concurrently."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    # Create multiple destination paths
    dest1 = temp_paths["tmp"] / "dest1"
    dest2 = temp_paths["tmp"] / "dest2"

    with (
        patch("subprocess.run"),
        patch("fcntl.flock") as mock_flock,
    ):
        # Simulate two concurrent clones
        mirror_cache.clone_from_mirror(dest1)
        mirror_cache.clone_from_mirror(dest2)

        # Both should acquire shared lock (LOCK_SH)
        assert mock_flock.call_count == 2
        for call_args in mock_flock.call_args_list:
            assert call_args[0][1] == 1  # fcntl.LOCK_SH


def test_update_blocks_clone(mirror_cache, temp_paths):
    """Test that update acquires exclusive lock (blocks clones)."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run"), patch("fcntl.flock") as mock_flock:
        # Update should acquire exclusive lock
        mirror_cache.update_mirror()

        # Verify exclusive lock was acquired
        mock_flock.assert_called_once()
        assert mock_flock.call_args[0][1] == 2  # fcntl.LOCK_EX


def test_lock_file_location(temp_paths):
    """Test that lock file is placed in correct location."""
    cache = GitMirrorCache(
        mirror_path=temp_paths["tmp"] / "subdir" / "mirror.git",
        origin_url="git@github.com:user/repo.git",
    )

    # Lock file should be sibling to mirror directory
    expected_lock = temp_paths["tmp"] / "subdir" / ".mirror.git.lock"
    assert cache.lock_file == expected_lock


def test_ensure_mirror_creates_parent_dirs(temp_paths):
    """Test that ensure_mirror_exists creates parent directories."""
    # Use nested path that doesn't exist
    nested_mirror = temp_paths["tmp"] / "nested" / "dirs" / "mirror.git"
    cache = GitMirrorCache(
        mirror_path=nested_mirror, origin_url="git@github.com:user/repo.git"
    )

    with patch("subprocess.run"):
        cache.ensure_mirror_exists()

    # Parent directories should be created
    assert nested_mirror.parent.exists()


def test_clone_creates_lock_file_parent(mirror_cache, temp_paths):
    """Test that clone_from_mirror creates lock file parent directory."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run"), patch("fcntl.flock"):
        mirror_cache.clone_from_mirror(temp_paths["dest"])

    # Lock file parent should exist
    assert mirror_cache.lock_file.parent.exists()


def test_update_creates_lock_file_parent(mirror_cache, temp_paths):
    """Test that update_mirror creates lock file parent directory."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run"), patch("fcntl.flock"):
        mirror_cache.update_mirror()

    # Lock file parent should exist
    assert mirror_cache.lock_file.parent.exists()


def test_get_default_branch_main(mirror_cache, temp_paths):
    """Test detecting default branch when it's 'main'."""
    # Create a temp repo directory
    repo_path = temp_paths["tmp"] / "repo"
    repo_path.mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="origin/main\n", stderr=""
        )

        result = mirror_cache._get_default_branch(repo_path)

        assert result == "main"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [
            "git",
            "-C",
            str(repo_path),
            "symbolic-ref",
            "refs/remotes/origin/HEAD",
            "--short",
        ]


def test_get_default_branch_master(mirror_cache, temp_paths):
    """Test detecting default branch when it's 'master'."""
    repo_path = temp_paths["tmp"] / "repo"
    repo_path.mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="origin/master\n", stderr=""
        )

        result = mirror_cache._get_default_branch(repo_path)

        assert result == "master"


def test_get_default_branch_failure(mirror_cache, temp_paths):
    """Test _get_default_branch handles git failure."""
    repo_path = temp_paths["tmp"] / "repo"
    repo_path.mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="fatal: ref does not exist"
        )

        with pytest.raises(
            MirrorError, match="Failed to detect default branch"
        ):
            mirror_cache._get_default_branch(repo_path)


def test_clone_from_mirror_with_master_branch(mirror_cache, temp_paths):
    """Test clone_from_mirror correctly resets when default branch is master."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):
        # Mock git symbolic-ref to return master branch
        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="origin/master\n", stderr=""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        mirror_cache.clone_from_mirror(temp_paths["dest"])

        # Verify reset uses origin/master
        reset_call = mock_run.call_args_list[4][0][0]
        assert reset_call == [
            "git",
            "-C",
            str(temp_paths["dest"]),
            "reset",
            "--hard",
            "origin/master",
        ]


def test_clone_from_mirror_default_branch_detection_failure(
    mirror_cache, temp_paths
):
    """Test clone_from_mirror handles default branch detection failure."""
    # Create mirror directory
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):
        # Mock successful operations until symbolic-ref
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] <= 3:
                # First 3 calls succeed (clone, set-url, fetch)
                return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")
            else:
                # symbolic-ref fails
                raise subprocess.CalledProcessError(
                    1, cmd, stderr="fatal: ref does not exist"
                )

        mock_run.side_effect = run_side_effect

        with pytest.raises(
            MirrorError, match="Failed to detect default branch"
        ):
            mirror_cache.clone_from_mirror(temp_paths["dest"])


# -- Tests for _get_default_branch_from_mirror --


def test_get_default_branch_from_mirror_main(mirror_cache, temp_paths):
    """Test detecting default branch from bare mirror when it's 'main'."""
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="refs/heads/main\n", stderr=""
        )

        result = mirror_cache._get_default_branch_from_mirror()

        assert result == "main"
        mock_run.assert_called_once()
        args = mock_run.call_args[0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["mirror"]),
            "symbolic-ref",
            "HEAD",
        ]


def test_get_default_branch_from_mirror_master(mirror_cache, temp_paths):
    """Test detecting default branch from bare mirror when it's 'master'."""
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="refs/heads/master\n", stderr=""
        )

        result = mirror_cache._get_default_branch_from_mirror()

        assert result == "master"


def test_get_default_branch_from_mirror_failure(mirror_cache, temp_paths):
    """Test _get_default_branch_from_mirror handles git failure."""
    temp_paths["mirror"].mkdir(parents=True)

    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, "git", stderr="fatal: ref does not exist"
        )

        with pytest.raises(
            MirrorError, match="Failed to detect mirror default branch"
        ):
            mirror_cache._get_default_branch_from_mirror()


# -- Tests for read_file --


def test_read_file_success(mirror_cache, temp_paths):
    """Test reading a file from the mirror."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):
        # First call: symbolic-ref to get default branch
        # Second call: git show to read file
        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            if "show" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=b"domains: []\n", stderr=b""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        result = mirror_cache.read_file(".airut/network-allowlist.yaml")

        assert result == b"domains: []\n"

        # Verify git show command
        show_call = mock_run.call_args_list[1]
        args = show_call[0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["mirror"]),
            "show",
            "refs/heads/main:.airut/network-allowlist.yaml",
        ]


def test_read_file_no_mirror(mirror_cache, temp_paths):
    """Test read_file fails if mirror doesn't exist."""
    with pytest.raises(MirrorError, match="Mirror does not exist"):
        mirror_cache.read_file(".airut/network-allowlist.yaml")


def test_read_file_not_found(mirror_cache, temp_paths):
    """Test read_file fails if file doesn't exist in mirror."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # symbolic-ref succeeds
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            # git show fails
            raise subprocess.CalledProcessError(
                128, cmd, stderr=b"fatal: path not found"
            )

        mock_run.side_effect = run_side_effect

        with pytest.raises(MirrorError, match="Failed to read"):
            mirror_cache.read_file("nonexistent.yaml")


def test_read_file_uses_shared_lock(mirror_cache, temp_paths):
    """Test that read_file acquires a shared lock."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock") as mock_flock,
    ):
        mock_run.return_value = subprocess.CompletedProcess(
            [], 0, stdout="refs/heads/main\n", stderr=""
        )

        # Make the show call also succeed
        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            return subprocess.CompletedProcess(
                cmd, 0, stdout=b"content", stderr=b""
            )

        mock_run.side_effect = run_side_effect

        mirror_cache.read_file("some/file.yaml")

        # Should acquire shared lock
        mock_flock.assert_called_once()
        assert mock_flock.call_args[0][1] == 1  # fcntl.LOCK_SH


# -- Tests for list_directory --


def test_list_directory_success(mirror_cache, temp_paths):
    """Test listing files in a directory from the mirror."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):

        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            if "ls-tree" in cmd:
                # ls-tree returns full paths
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=(
                        ".airut/container/Dockerfile\n"
                        ".airut/container/gitconfig\n"
                    ),
                    stderr="",
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        result = mirror_cache.list_directory(".airut/container")

        assert result == ["Dockerfile", "gitconfig"]

        # Verify ls-tree command - should include trailing slash
        ls_tree_call = mock_run.call_args_list[1]
        args = ls_tree_call[0][0]
        assert args == [
            "git",
            "-C",
            str(temp_paths["mirror"]),
            "ls-tree",
            "--name-only",
            "refs/heads/main",
            ".airut/container/",
        ]


def test_list_directory_no_mirror(mirror_cache, temp_paths):
    """Test list_directory fails if mirror doesn't exist."""
    with pytest.raises(MirrorError, match="Mirror does not exist"):
        mirror_cache.list_directory(".airut/container")


def test_list_directory_not_found(mirror_cache, temp_paths):
    """Test list_directory fails if directory doesn't exist in mirror."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                # symbolic-ref succeeds
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            # ls-tree fails
            raise subprocess.CalledProcessError(
                128, cmd, stderr="fatal: path not found"
            )

        mock_run.side_effect = run_side_effect

        with pytest.raises(MirrorError, match="Failed to list"):
            mirror_cache.list_directory("nonexistent")


def test_list_directory_uses_shared_lock(mirror_cache, temp_paths):
    """Test that list_directory acquires a shared lock."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock") as mock_flock,
    ):

        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        mirror_cache.list_directory(".airut/container")

        # Should acquire shared lock
        mock_flock.assert_called_once()
        assert mock_flock.call_args[0][1] == 1  # fcntl.LOCK_SH


def test_list_directory_empty(mirror_cache, temp_paths):
    """Test list_directory returns empty list for empty directory."""
    temp_paths["mirror"].mkdir(parents=True)

    with (
        patch("subprocess.run") as mock_run,
        patch("fcntl.flock"),
    ):

        def run_side_effect(cmd, **kwargs):
            if "symbolic-ref" in cmd:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout="refs/heads/main\n", stderr=""
                )
            # Empty output
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        result = mirror_cache.list_directory(".airut/container")

        assert result == []
