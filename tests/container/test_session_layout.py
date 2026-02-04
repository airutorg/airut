# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for session layout module."""

from pathlib import Path

from lib.container.session_layout import (
    SessionLayout,
    create_session_layout,
    get_container_mounts,
    prepare_session,
)


class TestCreateSessionLayout:
    """Tests for create_session_layout() path derivation."""

    def test_derives_all_paths(self, tmp_path: Path) -> None:
        """All paths are derived from session_dir."""
        layout = create_session_layout(tmp_path / "session")

        assert layout.session_dir == tmp_path / "session"
        assert layout.workspace == tmp_path / "session" / "workspace"
        assert layout.claude == tmp_path / "session" / "claude"
        assert layout.inbox == tmp_path / "session" / "inbox"
        assert layout.outbox == tmp_path / "session" / "outbox"

    def test_returns_frozen_dataclass(self, tmp_path: Path) -> None:
        """SessionLayout is immutable."""
        layout = create_session_layout(tmp_path)

        import dataclasses

        assert dataclasses.is_dataclass(layout)
        assert isinstance(layout, SessionLayout)


class TestPrepareSession:
    """Tests for prepare_session() directory creation."""

    def test_creates_directories(self, tmp_path: Path) -> None:
        """Creates claude, inbox, and outbox directories."""
        layout = create_session_layout(tmp_path / "session")
        layout.session_dir.mkdir(parents=True)

        prepare_session(layout)

        assert layout.claude.is_dir()
        assert layout.inbox.is_dir()
        assert layout.outbox.is_dir()

    def test_does_not_create_workspace(self, tmp_path: Path) -> None:
        """Does not create workspace directory (git clone's job)."""
        layout = create_session_layout(tmp_path / "session")
        layout.session_dir.mkdir(parents=True)

        prepare_session(layout)

        assert not layout.workspace.exists()

    def test_idempotent(self, tmp_path: Path) -> None:
        """Can be called multiple times without error."""
        layout = create_session_layout(tmp_path / "session")
        layout.session_dir.mkdir(parents=True)

        prepare_session(layout)
        prepare_session(layout)

        assert layout.claude.is_dir()


class TestGetContainerMounts:
    """Tests for get_container_mounts() mount string generation."""

    def test_returns_all_mounts(self, tmp_path: Path) -> None:
        """Returns mount strings for all session directories."""
        layout = create_session_layout(tmp_path / "session")
        mounts = get_container_mounts(layout)

        assert len(mounts) == 4
        assert f"{tmp_path / 'session' / 'workspace'}:/workspace:rw" in mounts
        assert f"{tmp_path / 'session' / 'claude'}:/root/.claude:rw" in mounts
        assert f"{tmp_path / 'session' / 'inbox'}:/inbox:rw" in mounts
        assert f"{tmp_path / 'session' / 'outbox'}:/outbox:rw" in mounts

    def test_workspace_is_readwrite(self, tmp_path: Path) -> None:
        """Workspace mount is read-write."""
        layout = create_session_layout(tmp_path)
        mounts = get_container_mounts(layout)

        workspace_mount = [m for m in mounts if "/workspace:" in m][0]
        assert workspace_mount.endswith(":rw")
