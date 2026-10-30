# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for conversation layout module."""

from pathlib import Path
from unittest.mock import patch

from airut.conversation import (
    ConversationLayout,
    clear_outbox,
    create_conversation_layout,
    get_container_mounts,
    list_outbox_files,
    prepare_conversation,
    write_inbox_file,
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


class TestWriteInboxFile:
    """Tests for write_inbox_file() collision avoidance."""

    def test_no_collision_keeps_name(self, tmp_path: Path) -> None:
        """An unused name is used unchanged."""
        path = write_inbox_file(tmp_path, "data.csv", b"new")
        assert path == tmp_path / "data.csv"
        assert path.read_bytes() == b"new"

    def test_single_collision_appends_counter(self, tmp_path: Path) -> None:
        """A collision inserts ``-1`` before the extension."""
        (tmp_path / "data.csv").write_bytes(b"existing")
        path = write_inbox_file(tmp_path, "data.csv", b"new")
        assert path == tmp_path / "data-1.csv"
        assert path.read_bytes() == b"new"
        assert (tmp_path / "data.csv").read_bytes() == b"existing"

    def test_multiple_collisions_increment_counter(
        self, tmp_path: Path
    ) -> None:
        """Successive collisions increment the counter until free."""
        (tmp_path / "data.csv").write_bytes(b"a")
        (tmp_path / "data-1.csv").write_bytes(b"b")
        (tmp_path / "data-2.csv").write_bytes(b"c")
        path = write_inbox_file(tmp_path, "data.csv", b"new")
        assert path == tmp_path / "data-3.csv"

    def test_collision_without_extension(self, tmp_path: Path) -> None:
        """A name with no extension still gets a ``-N`` counter."""
        (tmp_path / "README").write_bytes(b"x")
        path = write_inbox_file(tmp_path, "README", b"new")
        assert path == tmp_path / "README-1"

    def test_collision_multi_dot_extension(self, tmp_path: Path) -> None:
        """The counter is inserted before the final extension only."""
        (tmp_path / "archive.tar.gz").write_bytes(b"x")
        path = write_inbox_file(tmp_path, "archive.tar.gz", b"new")
        assert path == tmp_path / "archive.tar-1.gz"


class TestWriteInboxFileSymlinks:
    """write_inbox_file() never writes through what is already there.

    The inbox is writable from the container, so a task can leave links
    in it.  Writing through one would create or overwrite a file
    wherever it points on the host.
    """

    def test_dangling_symlink_not_followed(self, tmp_path: Path) -> None:
        target = tmp_path / "host" / "planted.txt"
        target.parent.mkdir()
        (tmp_path / "data.csv").symlink_to(target)

        path = write_inbox_file(tmp_path, "data.csv", b"new")

        assert path == tmp_path / "data-1.csv"
        assert path.read_bytes() == b"new"
        assert not target.exists()

    def test_symlink_to_existing_file_not_followed(
        self, tmp_path: Path
    ) -> None:
        target = tmp_path / "host.txt"
        target.write_bytes(b"host data")
        (tmp_path / "data.csv").symlink_to(target)

        write_inbox_file(tmp_path, "data.csv", b"new")

        assert target.read_bytes() == b"host data"

    def test_dangling_symlink_with_counter_skipped(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "data.csv").write_bytes(b"existing")
        (tmp_path / "data-1.csv").symlink_to(tmp_path / "missing")

        path = write_inbox_file(tmp_path, "data.csv", b"new")

        assert path == tmp_path / "data-2.csv"
        assert not (tmp_path / "missing").exists()

    def test_directory_in_the_way(self, tmp_path: Path) -> None:
        (tmp_path / "data.csv").mkdir()
        path = write_inbox_file(tmp_path, "data.csv", b"new")
        assert path == tmp_path / "data-1.csv"


class TestListOutboxFiles:
    """Tests for list_outbox_files() delivery selection."""

    def test_returns_files_sorted_by_name(self, tmp_path: Path) -> None:
        """Attachment order is stable, not directory order."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "b.txt").write_text("b")
        (outbox / "a.txt").write_text("a")

        assert list_outbox_files(outbox) == [
            outbox / "a.txt",
            outbox / "b.txt",
        ]

    def test_skips_subdirectories(self, tmp_path: Path) -> None:
        """Only the outbox root is delivered; channels send flat files."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "nested").mkdir()
        (outbox / "file.txt").write_text("a")

        assert list_outbox_files(outbox) == [outbox / "file.txt"]

    def test_missing_outbox_is_empty(self, tmp_path: Path) -> None:
        """A missing outbox directory yields nothing to deliver."""
        assert list_outbox_files(tmp_path / "nonexistent") == []

    def test_skips_symlinks(self, tmp_path: Path) -> None:
        """Symlinks are never delivered.

        The gateway reads the outbox on the host, where a link written
        inside the container resolves against a different filesystem —
        delivering it would ship whatever host file it happens to name.
        """
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        secret = tmp_path / "server-config.yaml"
        secret.write_text("token: hunter2")
        (outbox / "report.txt").symlink_to(secret)
        (outbox / "real.txt").write_text("fine")

        assert list_outbox_files(outbox) == [outbox / "real.txt"]


class TestClearOutbox:
    """Tests for clear_outbox() post-delivery cleanup."""

    def test_removes_files(self, tmp_path: Path) -> None:
        """Every file in the outbox is deleted."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file1.txt").write_text("a")
        (outbox / "file2.txt").write_text("b")

        clear_outbox(outbox)

        assert list(outbox.iterdir()) == []

    def test_keeps_subdirectories(self, tmp_path: Path) -> None:
        """Sub-directories are left alone; only root files are sent."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "nested").mkdir()
        (outbox / "file.txt").write_text("a")

        clear_outbox(outbox)

        assert list(outbox.iterdir()) == [outbox / "nested"]

    def test_removes_symlinks_without_touching_targets(
        self, tmp_path: Path
    ) -> None:
        """Undelivered symlinks go too, so they aren't re-reported."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        target = tmp_path / "target.txt"
        target.write_text("keep me")
        (outbox / "link.txt").symlink_to(target)
        (outbox / "dirlink").symlink_to(tmp_path)

        clear_outbox(outbox)

        assert list(outbox.iterdir()) == []
        assert target.read_text() == "keep me"

    def test_noop_for_missing_outbox(self, tmp_path: Path) -> None:
        """A missing outbox directory is not an error."""
        clear_outbox(tmp_path / "nonexistent")

        assert not (tmp_path / "nonexistent").exists()

    def test_handles_unlink_error(self, tmp_path: Path) -> None:
        """An undeletable file is logged, not raised."""
        outbox = tmp_path / "outbox"
        outbox.mkdir()
        (outbox / "file.txt").write_text("data")

        with patch.object(Path, "unlink", side_effect=OSError("perm denied")):
            clear_outbox(outbox)

        assert (outbox / "file.txt").exists()


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
