# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for conversation layout module."""

from pathlib import Path

from airut.conversation import (
    ConversationLayout,
    create_conversation_layout,
    get_container_mounts,
    prepare_conversation,
    unique_inbox_path,
)


class TestCreateConversationLayout:
    """Tests for create_conversation_layout() path derivation."""

    def test_derives_all_paths(self, tmp_path: Path) -> None:
        """All paths are derived from conversation_dir."""
        layout = create_conversation_layout(tmp_path / "conv")

        assert layout.conversation_dir == tmp_path / "conv"
        assert layout.workspace == tmp_path / "conv" / "workspace"
        assert layout.claude == tmp_path / "conv" / "claude"
        assert layout.inbox == tmp_path / "conv" / "inbox"
        assert layout.outbox == tmp_path / "conv" / "outbox"
        assert layout.storage == tmp_path / "conv" / "storage"

    def test_returns_frozen_dataclass(self, tmp_path: Path) -> None:
        """ConversationLayout is immutable."""
        layout = create_conversation_layout(tmp_path)

        import dataclasses

        assert dataclasses.is_dataclass(layout)
        assert isinstance(layout, ConversationLayout)


class TestPrepareConversation:
    """Tests for prepare_conversation() directory creation."""

    def test_creates_directories(self, tmp_path: Path) -> None:
        """Creates claude, inbox, outbox, and storage directories."""
        layout = create_conversation_layout(tmp_path / "conv")
        layout.conversation_dir.mkdir(parents=True)

        prepare_conversation(layout)

        assert layout.claude.is_dir()
        assert layout.inbox.is_dir()
        assert layout.outbox.is_dir()
        assert layout.storage.is_dir()

    def test_does_not_create_workspace(self, tmp_path: Path) -> None:
        """Does not create workspace directory (git clone's job)."""
        layout = create_conversation_layout(tmp_path / "conv")
        layout.conversation_dir.mkdir(parents=True)

        prepare_conversation(layout)

        assert not layout.workspace.exists()

    def test_idempotent(self, tmp_path: Path) -> None:
        """Can be called multiple times without error."""
        layout = create_conversation_layout(tmp_path / "conv")
        layout.conversation_dir.mkdir(parents=True)

        prepare_conversation(layout)
        prepare_conversation(layout)

        assert layout.claude.is_dir()


class TestUniqueInboxPath:
    """Tests for unique_inbox_path() collision avoidance."""

    def test_no_collision_returns_name(self, tmp_path: Path) -> None:
        """An unused name is returned unchanged."""
        assert unique_inbox_path(tmp_path, "data.csv") == tmp_path / "data.csv"

    def test_single_collision_appends_counter(self, tmp_path: Path) -> None:
        """A collision inserts ``-1`` before the extension."""
        (tmp_path / "data.csv").write_bytes(b"existing")
        assert (
            unique_inbox_path(tmp_path, "data.csv") == tmp_path / "data-1.csv"
        )

    def test_multiple_collisions_increment_counter(
        self, tmp_path: Path
    ) -> None:
        """Successive collisions increment the counter until free."""
        (tmp_path / "data.csv").write_bytes(b"a")
        (tmp_path / "data-1.csv").write_bytes(b"b")
        (tmp_path / "data-2.csv").write_bytes(b"c")
        assert (
            unique_inbox_path(tmp_path, "data.csv") == tmp_path / "data-3.csv"
        )

    def test_collision_without_extension(self, tmp_path: Path) -> None:
        """A name with no extension still gets a ``-N`` counter."""
        (tmp_path / "README").write_bytes(b"x")
        assert unique_inbox_path(tmp_path, "README") == tmp_path / "README-1"

    def test_collision_multi_dot_extension(self, tmp_path: Path) -> None:
        """The counter is inserted before the final extension only."""
        (tmp_path / "archive.tar.gz").write_bytes(b"x")
        assert (
            unique_inbox_path(tmp_path, "archive.tar.gz")
            == tmp_path / "archive.tar-1.gz"
        )


class TestGetContainerMounts:
    """Tests for get_container_mounts() mount string generation."""

    def test_returns_all_mounts(self, tmp_path: Path) -> None:
        """Returns mount strings for all conversation directories."""
        layout = create_conversation_layout(tmp_path / "conv")
        mounts = get_container_mounts(layout)

        assert len(mounts) == 5
        assert f"{tmp_path / 'conv' / 'workspace'}:/workspace:rw" in mounts
        assert f"{tmp_path / 'conv' / 'claude'}:/root/.claude:rw" in mounts
        assert f"{tmp_path / 'conv' / 'inbox'}:/inbox:rw" in mounts
        assert f"{tmp_path / 'conv' / 'outbox'}:/outbox:rw" in mounts
        assert f"{tmp_path / 'conv' / 'storage'}:/storage:rw" in mounts

    def test_workspace_is_readwrite(self, tmp_path: Path) -> None:
        """Workspace mount is read-write."""
        layout = create_conversation_layout(tmp_path)
        mounts = get_container_mounts(layout)

        workspace_mount = [m for m in mounts if "/workspace:" in m][0]
        assert workspace_mount.endswith(":rw")
