# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for ConversationManager class."""

import re
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.conversation import (
    ConversationError,
    ConversationManager,
    GitCloneError,
)


@pytest.fixture(autouse=True)
def mock_mirror(master_repo):
    """Mock GitMirrorCache to use real git clone for testing."""
    with patch("airut.gateway.conversation.GitMirrorCache") as mock_cls:
        mock_instance = MagicMock()
        # Mock ensure_mirror_exists to do nothing
        mock_instance.ensure_mirror_exists.return_value = None

        # Mock clone_from_mirror to use real git clone
        def clone_from_mirror(dest):
            subprocess.run(
                ["git", "clone", "--quiet", str(master_repo), str(dest)],
                check=True,
                capture_output=True,
            )

        mock_instance.clone_from_mirror.side_effect = clone_from_mirror
        mock_cls.return_value = mock_instance
        yield mock_instance


class TestConversationManager:
    """Tests for ConversationManager class."""

    def test_init_valid_repo(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """Initialize with valid git repository URL."""
        manager = ConversationManager(str(master_repo), storage_dir)
        assert manager.repo_url == str(master_repo)
        assert manager.storage_dir == storage_dir
        assert storage_dir.exists()

    def test_init_empty_url(self, storage_dir: Path) -> None:
        """Raise ValueError if repo_url is empty."""
        with pytest.raises(ValueError, match="Repository URL cannot be empty"):
            ConversationManager("", storage_dir)

    def test_generate_id_format(self) -> None:
        """Generated IDs are 8-character lowercase hex."""
        conversation_id = ConversationManager.generate_id()
        assert len(conversation_id) == 8
        assert re.match(r"^[0-9a-f]{8}$", conversation_id)

    def test_generate_id_unique(self) -> None:
        """Multiple calls generate different IDs."""
        ids = {ConversationManager.generate_id() for _ in range(100)}
        assert len(ids) == 100  # All unique

    def test_initialize_new_creates_clone(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """initialize_new() creates git clone."""
        manager = ConversationManager(str(master_repo), storage_dir)
        conversation_id, repo_path = manager.initialize_new()

        # Verify conversation ID format
        assert len(conversation_id) == 8
        assert re.match(r"^[0-9a-f]{8}$", conversation_id)

        # Verify git clone exists
        assert repo_path.exists()
        assert (repo_path / ".git").exists()
        assert (repo_path / "books").exists()
        assert (repo_path / "lib").exists()

    def test_initialize_new_returns_id_and_path(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """Returns tuple of (conversation_id, workspace_path)."""
        manager = ConversationManager(str(master_repo), storage_dir)
        conversation_id, workspace_path = manager.initialize_new()

        assert isinstance(conversation_id, str)
        assert isinstance(workspace_path, Path)
        assert (
            workspace_path
            == storage_dir / "conversations" / conversation_id / "workspace"
        )

    @patch("subprocess.run")
    def test_initialize_new_git_clone_fails(
        self, mock_run, master_repo: Path, storage_dir: Path
    ) -> None:
        """Raise GitCloneError and cleanup on clone failure."""
        # Make git clone fail
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["git", "clone"], stderr="fatal: clone failed"
        )

        manager = ConversationManager(str(master_repo), storage_dir)

        with pytest.raises(GitCloneError, match="Failed to clone repository"):
            manager.initialize_new()

        # Verify no partial directories left behind
        conversations_dir = storage_dir / "conversations"
        if conversations_dir.exists():
            for item in conversations_dir.iterdir():
                # If any session dirs exist, their workspaces shouldn't have git
                if item.is_dir():
                    workspace = item / "workspace"
                    if workspace.exists():
                        assert not (workspace / ".git").exists()

    def test_initialize_new_git_clone_fails_with_partial_dir(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """Cleanup partial directory when git clone fails."""
        manager = ConversationManager(str(master_repo), storage_dir)

        # Patch subprocess to fail after creating a directory
        with patch("subprocess.run") as mock_run:

            def create_partial_and_fail(*args, **kwargs):
                # Create a partial directory to test cleanup
                cmd = args[0]
                if "clone" in cmd:
                    # Extract the target path from git clone command
                    target_path = Path(cmd[-1])
                    target_path.mkdir(parents=True, exist_ok=True)
                    (target_path / "partial.txt").write_text("partial")
                    raise subprocess.CalledProcessError(
                        1, cmd, stderr="fatal: clone failed"
                    )

            mock_run.side_effect = create_partial_and_fail

            with pytest.raises(GitCloneError):
                manager.initialize_new()

        # Verify partial directory was cleaned up
        conversations_dir = storage_dir / "conversations"
        if conversations_dir.exists():
            for item in conversations_dir.iterdir():
                if item.is_dir():
                    workspace = item / "workspace"
                    if workspace.exists():
                        assert not (workspace / "partial.txt").exists()

    def test_resume_existing_success(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """resume_existing() returns path for existing conversation."""
        manager = ConversationManager(str(master_repo), storage_dir)
        conversation_id, expected_path = manager.initialize_new()

        # Resume the conversation
        resumed_path = manager.resume_existing(conversation_id)

        assert resumed_path == expected_path
        assert resumed_path.exists()

    def test_resume_nonexistent_raises(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """resume_existing() raises ConversationError if not found."""
        manager = ConversationManager(str(master_repo), storage_dir)

        with pytest.raises(
            ConversationError, match="Conversation .* not found"
        ):
            manager.resume_existing("abcdef01")

    def test_resume_invalid_id_format(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """resume_existing() raises ValueError for invalid ID format."""
        manager = ConversationManager(str(master_repo), storage_dir)

        invalid_ids = [
            "abc",  # Too short
            "abcdef0123",  # Too long
            "ABCDEF01",  # Uppercase
            "abcdefg1",  # Invalid character
            "12345678-",  # Invalid character
        ]

        for invalid_id in invalid_ids:
            with pytest.raises(
                ValueError, match="Invalid conversation ID format"
            ):
                manager.resume_existing(invalid_id)

    def test_exists_true_for_existing(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """exists() returns True for existing conversation."""
        manager = ConversationManager(str(master_repo), storage_dir)
        conversation_id, _ = manager.initialize_new()

        assert manager.exists(conversation_id) is True

    def test_exists_false_for_missing(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """exists() returns False for non-existent conversation."""
        manager = ConversationManager(str(master_repo), storage_dir)

        assert manager.exists("abcdef01") is False

    def test_delete_removes_directory(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """delete() removes conversation directory."""
        manager = ConversationManager(str(master_repo), storage_dir)
        conversation_id, repo_path = manager.initialize_new()

        assert repo_path.exists()

        result = manager.delete(conversation_id)

        assert result is True
        assert not repo_path.exists()

    def test_delete_returns_false_if_not_exists(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """delete() returns False if conversation doesn't exist."""
        manager = ConversationManager(str(master_repo), storage_dir)

        result = manager.delete("abcdef01")

        assert result is False

    def test_list_all_empty(self, master_repo: Path, storage_dir: Path) -> None:
        """list_all() returns empty list when no conversations."""
        manager = ConversationManager(str(master_repo), storage_dir)

        conversations = manager.list_all()

        assert conversations == []

    def test_list_all_storage_dir_not_exists(
        self, master_repo: Path, tmp_path: Path
    ) -> None:
        """list_all() returns empty list when storage_dir doesn't exist yet."""
        storage_dir = tmp_path / "nonexistent_storage_dir"
        manager = ConversationManager(str(master_repo), storage_dir)

        # Don't create storage_dir - test the case where it doesn't exist
        import shutil

        if storage_dir.exists():
            shutil.rmtree(storage_dir)

        conversations = manager.list_all()

        assert conversations == []

    def test_list_all_multiple_conversations(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """list_all() returns all conversation IDs."""
        manager = ConversationManager(str(master_repo), storage_dir)

        id1, _ = manager.initialize_new()
        id2, _ = manager.initialize_new()
        id3, _ = manager.initialize_new()

        conversations = manager.list_all()

        assert len(conversations) == 3
        assert sorted(conversations) == sorted([id1, id2, id3])

    def test_list_all_ignores_non_hex_directories(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """list_all() ignores directories that aren't 8-char hex."""
        manager = ConversationManager(str(master_repo), storage_dir)

        # Create valid conversation
        id1, _ = manager.initialize_new()

        # Create invalid directories in conversations/
        conversations_dir = storage_dir / "conversations"
        (conversations_dir / "invalid").mkdir()
        (conversations_dir / "toolong123").mkdir()
        (conversations_dir / "ABCDEF01").mkdir()  # Uppercase
        (conversations_dir / ".hidden").mkdir()

        conversations = manager.list_all()

        assert len(conversations) == 1
        assert conversations[0] == id1

    def test_get_workspace_path(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """get_workspace_path() returns correct path."""
        manager = ConversationManager(str(master_repo), storage_dir)

        path = manager.get_workspace_path("abcdef01")

        assert path == storage_dir / "conversations" / "abcdef01" / "workspace"

    def test_get_conversation_dir(
        self, master_repo: Path, storage_dir: Path
    ) -> None:
        """get_conversation_dir() returns correct path."""
        manager = ConversationManager(str(master_repo), storage_dir)

        path = manager.get_conversation_dir("abcdef01")

        assert path == storage_dir / "conversations" / "abcdef01"
