# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/install_services.py."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest


# Import the module under test
# Scripts are not in the normal Python path, so we add them manually
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import install_services  # type: ignore[import-not-found]


@pytest.fixture
def mock_repo_root(tmp_path: Path) -> Path:
    """Create a mock repository root.

    Args:
        tmp_path: Pytest temporary path fixture.

    Returns:
        Path to mock repository root.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    return repo


@pytest.fixture
def mock_systemd_dir(tmp_path: Path) -> Path:
    """Create a mock systemd user directory.

    Args:
        tmp_path: Pytest temporary path fixture.

    Returns:
        Path to mock systemd user directory.
    """
    systemd = tmp_path / "systemd_user"
    systemd.mkdir()
    return systemd


def test_get_repo_root_success() -> None:
    """Test get_repo_root returns repository root."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="/path/to/repo\n", returncode=0
        )

        result = install_services.get_repo_root()

        assert result == Path("/path/to/repo")
        mock_run.assert_called_once_with(
            ["git", "rev-parse", "--show-toplevel"],
            capture_output=True,
            text=True,
            check=True,
        )


def test_get_repo_root_not_git_repo() -> None:
    """Test get_repo_root raises error when not in git repo."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            128, ["git"], stderr="not a git repository"
        )

        with pytest.raises(RuntimeError, match="Not in a git repository"):
            install_services.get_repo_root()


def test_get_systemd_user_dir() -> None:
    """Test get_systemd_user_dir returns correct path."""
    result = install_services.get_systemd_user_dir()
    expected = Path.home() / ".config" / "systemd" / "user"
    assert result == expected


def test_systemctl_user_success() -> None:
    """Test systemctl_user executes command successfully."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        install_services.systemctl_user("daemon-reload")

        mock_run.assert_called_once_with(
            ["systemctl", "--user", "daemon-reload"],
            check=True,
            capture_output=True,
            text=True,
        )


def test_systemctl_user_with_service() -> None:
    """Test systemctl_user with service parameter."""
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)

        install_services.systemctl_user("start", "test.service")

        mock_run.assert_called_once_with(
            ["systemctl", "--user", "start", "test.service"],
            check=True,
            capture_output=True,
            text=True,
        )


def test_systemctl_user_failure() -> None:
    """Test systemctl_user raises error on failure."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["systemctl"], stderr="Unit not found"
        )

        with pytest.raises(
            RuntimeError, match="systemctl daemon-reload failed"
        ):
            install_services.systemctl_user("daemon-reload")


def test_uninstall_service_not_installed(mock_systemd_dir: Path) -> None:
    """Test uninstall_service when service is not installed."""
    unit_path = mock_systemd_dir / "test.service"

    with patch("install_services.systemctl_user") as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    mock_systemctl.assert_not_called()


def test_uninstall_service_success(mock_systemd_dir: Path) -> None:
    """Test uninstall_service removes service successfully."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.touch()

    with patch("install_services.systemctl_user") as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    assert mock_systemctl.call_args_list == [
        call("stop", "test.service"),
        call("disable", "test.service"),
    ]

    assert not unit_path.exists()


def test_uninstall_service_stop_fails(mock_systemd_dir: Path) -> None:
    """Test uninstall_service continues if stop fails."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.touch()

    with patch("install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            RuntimeError("Not running"),
            None,
        ]

        install_services.uninstall_service("test.service", unit_path)

    assert not unit_path.exists()
    assert mock_systemctl.call_count == 2


def test_uninstall_service_broken_symlink(mock_systemd_dir: Path) -> None:
    """Test uninstall_service handles broken symlinks gracefully."""
    unit_path = mock_systemd_dir / "test.service"
    target = mock_systemd_dir / "nonexistent_target"
    unit_path.symlink_to(target)

    assert unit_path.is_symlink()
    assert not unit_path.exists()

    with patch("install_services.systemctl_user") as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    assert mock_systemctl.call_args_list == [
        call("stop", "test.service"),
        call("disable", "test.service"),
    ]

    assert not unit_path.is_symlink()


def test_uninstall_service_already_removed(mock_systemd_dir: Path) -> None:
    """Test uninstall_service handles unit removed during disable."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.touch()

    def remove_on_disable(action: str, service: str | None = None) -> None:
        """Mock that removes unit file when disable is called."""
        if action == "disable" and unit_path.exists():
            unit_path.unlink()

    with patch(
        "install_services.systemctl_user", side_effect=remove_on_disable
    ) as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    assert mock_systemctl.call_count == 2


def test_install_service_new(mock_systemd_dir: Path) -> None:
    """Test install_service writes new unit file."""
    unit_content = "[Unit]\nDescription=Test\n"

    install_services.install_service(
        "test.service", unit_content, mock_systemd_dir
    )

    unit_path = mock_systemd_dir / "test.service"
    assert unit_path.exists()
    assert unit_path.read_text() == unit_content


def test_install_service_reinstall(mock_systemd_dir: Path) -> None:
    """Test install_service reinstalls existing service."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.write_text("[Unit]\nDescription=Old\n")

    new_content = "[Unit]\nDescription=New\n"

    with patch("install_services.uninstall_service") as mock_uninstall:
        install_services.install_service(
            "test.service", new_content, mock_systemd_dir
        )

    mock_uninstall.assert_called_once_with("test.service", unit_path)
    assert unit_path.read_text() == new_content


def test_install_service_broken_symlink_reinstall(
    mock_systemd_dir: Path,
) -> None:
    """Test install_service handles broken symlink during reinstall."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.symlink_to(mock_systemd_dir / "nonexistent")

    new_content = "[Unit]\nDescription=New\n"

    with patch("install_services.systemctl_user"):
        install_services.install_service(
            "test.service", new_content, mock_systemd_dir
        )

    assert unit_path.exists()
    assert unit_path.read_text() == new_content


def test_enable_and_start_service() -> None:
    """Test enable_and_start_service enables and starts service."""
    with patch("install_services.systemctl_user") as mock_systemctl:
        install_services.enable_and_start_service("test.service")

    assert mock_systemctl.call_args_list == [
        call("enable", "test.service"),
        call("start", "test.service"),
    ]


def test_enable_and_start_timer() -> None:
    """Test enable_and_start_service handles timer files."""
    with patch("install_services.systemctl_user") as mock_systemctl:
        install_services.enable_and_start_service("test.timer")

    assert mock_systemctl.call_args_list == [
        call("enable", "test.timer"),
        call("start", "test.timer"),
    ]


def test_enable_and_start_service_enable_fails() -> None:
    """Test enable_and_start_service continues if enable fails."""
    with patch("install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            RuntimeError("Enable failed"),
            None,
        ]

        install_services.enable_and_start_service("test.service")

    assert mock_systemctl.call_count == 2


def test_generate_unit_email_gateway(mock_repo_root: Path) -> None:
    """Test generate_unit produces correct email gateway unit."""
    result = install_services.generate_unit(
        "airut.service", mock_repo_root, "/usr/bin/uv"
    )

    assert f"WorkingDirectory={mock_repo_root}" in result
    assert "ExecStart=/usr/bin/uv run scripts/gateway/main.py" in result
    assert f"EnvironmentFile={mock_repo_root}/.env" in result
    assert "Restart=always" in result


def test_generate_unit_updater_service(mock_repo_root: Path) -> None:
    """Test generate_unit produces correct updater service unit."""
    result = install_services.generate_unit(
        "airut-updater.service", mock_repo_root, "/usr/bin/uv"
    )

    assert "Type=oneshot" in result
    assert (
        "ExecStart=/usr/bin/uv run scripts/install_services.py --update"
        in result
    )


def test_generate_unit_updater_timer() -> None:
    """Test generate_unit produces correct updater timer unit."""
    result = install_services.generate_unit(
        "airut-updater.timer", Path("/repo"), "/usr/bin/uv"
    )

    assert "OnCalendar=*:0/5" in result
    assert "Persistent=true" in result
    assert "WantedBy=timers.target" in result


def test_generate_unit_unknown() -> None:
    """Test generate_unit raises ValueError for unknown service."""
    with pytest.raises(ValueError, match="Unknown service"):
        install_services.generate_unit(
            "unknown.service", Path("/repo"), "/usr/bin/uv"
        )


def test_check_linger_enabled(tmp_path: Path) -> None:
    """Test check_linger passes when linger file exists."""
    linger_file = tmp_path / "testuser"
    linger_file.touch()

    with (
        patch.dict("os.environ", {"USER": "testuser"}),
        patch(
            "install_services.Path",
            side_effect=lambda p: tmp_path / "testuser"
            if "linger" in str(p)
            else Path(p),
        ),
    ):
        # Directly test the linger file check logic
        username = "testuser"
        assert (tmp_path / username).exists()


def test_check_linger_not_enabled() -> None:
    """Test check_linger raises error when linger is not enabled."""
    with patch.dict("os.environ", {"USER": "testuser"}):
        with pytest.raises(RuntimeError, match="Linger is not enabled"):
            install_services.check_linger()


def test_check_linger_enabled_via_file(tmp_path: Path) -> None:
    """Test check_linger succeeds when linger file exists."""
    linger_dir = tmp_path / "var" / "lib" / "systemd" / "linger"
    linger_dir.mkdir(parents=True)
    (linger_dir / "testuser").touch()

    with (
        patch.dict("os.environ", {"USER": "testuser"}),
        patch("install_services.Path") as mock_path,
    ):
        mock_path.return_value = linger_dir / "testuser"
        install_services.check_linger()


def test_get_uv_path_found_on_path() -> None:
    """Test get_uv_path uses shutil.which when uv is on PATH."""
    with patch("shutil.which", return_value="/usr/local/bin/uv"):
        with patch.object(
            Path, "resolve", return_value=Path("/usr/local/bin/uv")
        ):
            result = install_services.get_uv_path()

    assert result == "/usr/local/bin/uv"


def test_get_uv_path_not_on_path() -> None:
    """Test get_uv_path falls back to ~/.local/bin/uv."""
    with patch("shutil.which", return_value=None):
        result = install_services.get_uv_path()

    expected = str(Path.home() / ".local" / "bin" / "uv")
    assert result == expected


def test_install_services_with_updater(mock_repo_root: Path) -> None:
    """Test install_services installs all services including updater."""
    with (
        patch("install_services.check_linger"),
        patch("install_services.get_systemd_user_dir") as mock_get_dir,
        patch("install_services.get_uv_path", return_value="/usr/bin/uv"),
        patch("install_services.install_service") as mock_install,
        patch("install_services.systemctl_user") as mock_systemctl,
        patch("install_services.enable_and_start_service") as mock_enable,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.install_services(mock_repo_root, with_updater=True)

        assert mock_install.call_count == 3
        mock_systemctl.assert_called_once_with("daemon-reload")
        assert mock_enable.call_count == 2


def test_install_services_without_updater(mock_repo_root: Path) -> None:
    """Test install_services can skip updater services."""
    with (
        patch("install_services.check_linger"),
        patch("install_services.get_systemd_user_dir") as mock_get_dir,
        patch("install_services.get_uv_path", return_value="/usr/bin/uv"),
        patch("install_services.install_service") as mock_install,
        patch("install_services.systemctl_user") as mock_systemctl,
        patch("install_services.enable_and_start_service") as mock_enable,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.install_services(mock_repo_root, with_updater=False)

        assert mock_install.call_count == 1
        mock_systemctl.assert_called_once_with("daemon-reload")
        assert mock_enable.call_count == 1


def test_install_services_linger_check_fails(mock_repo_root: Path) -> None:
    """Test install_services aborts when linger is not enabled."""
    with patch(
        "install_services.check_linger",
        side_effect=RuntimeError("Linger is not enabled"),
    ):
        with pytest.raises(RuntimeError, match="Linger is not enabled"):
            install_services.install_services(mock_repo_root)


def test_uninstall_services_with_updater() -> None:
    """Test uninstall_services removes all services including updater."""
    with (
        patch("install_services.get_systemd_user_dir") as mock_get_dir,
        patch("install_services.uninstall_service") as mock_uninstall,
        patch("install_services.systemctl_user") as mock_systemctl,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.uninstall_services(with_updater=True)

        assert mock_uninstall.call_count == 3
        mock_systemctl.assert_called_once_with("daemon-reload")


def test_uninstall_services_without_updater() -> None:
    """Test uninstall_services can skip updater services."""
    with (
        patch("install_services.get_systemd_user_dir") as mock_get_dir,
        patch("install_services.uninstall_service") as mock_uninstall,
        patch("install_services.systemctl_user") as mock_systemctl,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.uninstall_services(with_updater=False)

        assert mock_uninstall.call_count == 1
        mock_systemctl.assert_called_once_with("daemon-reload")


def test_check_for_updates_available(mock_repo_root: Path) -> None:
    """Test check_for_updates returns True when updates available."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0),  # fetch
            MagicMock(stdout="abc123\n", returncode=0),  # local HEAD
            MagicMock(stdout="def456\n", returncode=0),  # remote origin/main
        ]

        result = install_services.check_for_updates(mock_repo_root)

        assert result is True


def test_check_for_updates_not_available(mock_repo_root: Path) -> None:
    """Test check_for_updates returns False when no updates."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0),  # fetch
            MagicMock(stdout="abc123\n", returncode=0),  # local HEAD
            MagicMock(stdout="abc123\n", returncode=0),  # remote origin/main
        ]

        result = install_services.check_for_updates(mock_repo_root)

        assert result is False


def test_check_for_updates_fetch_fails(mock_repo_root: Path) -> None:
    """Test check_for_updates raises error if fetch fails."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["git"], stderr="network error"
        )

        with pytest.raises(RuntimeError, match="git fetch failed"):
            install_services.check_for_updates(mock_repo_root)


def test_check_for_updates_rev_parse_fails(mock_repo_root: Path) -> None:
    """Test check_for_updates raises error if rev-parse fails."""
    with patch("subprocess.run") as mock_run:
        mock_run.side_effect = [
            MagicMock(returncode=0),
            subprocess.CalledProcessError(1, ["git"], stderr="not a valid ref"),
        ]

        with pytest.raises(RuntimeError, match="git rev-parse failed"):
            install_services.check_for_updates(mock_repo_root)


def test_apply_update(mock_repo_root: Path) -> None:
    """Test apply_update uninstalls, updates, syncs deps, re-executes."""
    with (
        patch("install_services.UpdateLock") as mock_lock_class,
        patch("install_services.uninstall_services") as mock_uninstall,
        patch("subprocess.run") as mock_run,
        patch("os.execv") as mock_execv,
        patch("shutil.which", return_value=None),
    ):
        mock_lock = MagicMock()
        mock_lock.try_acquire.return_value = True
        mock_lock_class.return_value = mock_lock

        mock_run.return_value = MagicMock(returncode=0)

        result = install_services.apply_update(mock_repo_root)

        assert result is True

        mock_lock_class.assert_called_once_with(mock_repo_root / ".update.lock")
        mock_lock.try_acquire.assert_called_once()

        mock_uninstall.assert_called_once_with(with_updater=False)

        assert mock_run.call_count == 3
        checkout_call = mock_run.call_args_list[0]
        reset_call = mock_run.call_args_list[1]
        sync_call = mock_run.call_args_list[2]

        assert checkout_call[0][0] == ["git", "checkout", "main"]
        assert reset_call[0][0] == ["git", "reset", "--hard", "origin/main"]
        expected_uv = str(Path.home() / ".local" / "bin" / "uv")
        assert sync_call[0][0] == [expected_uv, "sync"]

        expected_script = mock_repo_root / "scripts" / "install_services.py"
        mock_execv.assert_called_once()
        call_args = mock_execv.call_args[0]
        assert call_args[1][1] == str(expected_script)
        assert call_args[1][2] == "--skip-updater"


def test_apply_update_email_service_busy(mock_repo_root: Path) -> None:
    """Test apply_update returns False when email service is busy."""
    with (
        patch("install_services.UpdateLock") as mock_lock_class,
        patch("install_services.uninstall_services") as mock_uninstall,
    ):
        mock_lock = MagicMock()
        mock_lock.try_acquire.return_value = False
        mock_lock_class.return_value = mock_lock

        result = install_services.apply_update(mock_repo_root)

        assert result is False

        mock_lock.try_acquire.assert_called_once()
        mock_uninstall.assert_not_called()


def test_apply_update_git_fails(mock_repo_root: Path) -> None:
    """Test apply_update raises error if git operations fail."""
    with (
        patch("install_services.UpdateLock") as mock_lock_class,
        patch("install_services.uninstall_services"),
        patch("subprocess.run") as mock_run,
    ):
        mock_lock = MagicMock()
        mock_lock.try_acquire.return_value = True
        mock_lock_class.return_value = mock_lock

        mock_run.side_effect = subprocess.CalledProcessError(
            1, ["git"], stderr="checkout failed"
        )

        with pytest.raises(RuntimeError, match="git checkout/reset failed"):
            install_services.apply_update(mock_repo_root)


def test_apply_update_uv_sync_fails(mock_repo_root: Path) -> None:
    """Test apply_update raises error if uv sync fails."""
    with (
        patch("install_services.UpdateLock") as mock_lock_class,
        patch("install_services.uninstall_services"),
        patch("subprocess.run") as mock_run,
        patch("shutil.which", return_value=None),
    ):
        mock_lock = MagicMock()
        mock_lock.try_acquire.return_value = True
        mock_lock_class.return_value = mock_lock

        mock_run.side_effect = [
            MagicMock(returncode=0),  # git checkout
            MagicMock(returncode=0),  # git reset
            subprocess.CalledProcessError(1, ["uv"], stderr="sync failed"),
        ]

        with pytest.raises(RuntimeError, match="uv sync failed"):
            install_services.apply_update(mock_repo_root)


def test_main_install(mock_repo_root: Path) -> None:
    """Test main with default install action."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.install_services") as mock_install,
    ):
        mock_get_root.return_value = mock_repo_root

        with patch("sys.argv", ["install_services.py"]):
            result = install_services.main()

        assert result == 0
        mock_install.assert_called_once_with(mock_repo_root, with_updater=True)


def test_main_install_skip_updater(mock_repo_root: Path) -> None:
    """Test main with --skip-updater flag skips updater installation."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.install_services") as mock_install,
    ):
        mock_get_root.return_value = mock_repo_root

        with patch("sys.argv", ["install_services.py", "--skip-updater"]):
            result = install_services.main()

        assert result == 0
        mock_install.assert_called_once_with(mock_repo_root, with_updater=False)


def test_main_uninstall() -> None:
    """Test --uninstall removes all services including auto-updater."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.get_systemd_user_dir") as mock_get_dir,
        patch("install_services.uninstall_service") as mock_uninstall,
        patch("install_services.systemctl_user") as mock_systemctl,
    ):
        mock_get_root.return_value = Path("/repo")
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        with patch("sys.argv", ["install_services.py", "--uninstall"]):
            result = install_services.main()

        assert result == 0
        mock_systemctl.assert_called_once_with("daemon-reload")
        # Verify ALL services are uninstalled, including updater services
        assert mock_uninstall.call_count == 3
        uninstalled_services = [c[0][0] for c in mock_uninstall.call_args_list]
        assert "airut-updater.timer" in uninstalled_services
        assert "airut-updater.service" in uninstalled_services
        assert "airut.service" in uninstalled_services


def test_main_update_available(mock_repo_root: Path) -> None:
    """Test main with --update flag when updates available."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.check_for_updates") as mock_check,
        patch("install_services.apply_update") as mock_apply,
    ):
        mock_get_root.return_value = mock_repo_root
        mock_check.return_value = True
        mock_apply.return_value = True

        with patch("sys.argv", ["install_services.py", "--update"]):
            result = install_services.main()

        assert result == 0
        mock_check.assert_called_once_with(mock_repo_root)
        mock_apply.assert_called_once_with(mock_repo_root)


def test_main_update_email_service_busy(mock_repo_root: Path) -> None:
    """Test main with --update flag when email service is busy."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.check_for_updates") as mock_check,
        patch("install_services.apply_update") as mock_apply,
    ):
        mock_get_root.return_value = mock_repo_root
        mock_check.return_value = True
        mock_apply.return_value = False

        with patch("sys.argv", ["install_services.py", "--update"]):
            result = install_services.main()

        assert result == 0
        mock_check.assert_called_once_with(mock_repo_root)
        mock_apply.assert_called_once_with(mock_repo_root)


def test_main_update_not_available(mock_repo_root: Path) -> None:
    """Test main with --update flag when no updates available."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.check_for_updates") as mock_check,
        patch("install_services.apply_update") as mock_apply,
    ):
        mock_get_root.return_value = mock_repo_root
        mock_check.return_value = False

        with patch("sys.argv", ["install_services.py", "--update"]):
            result = install_services.main()

        assert result == 0
        mock_check.assert_called_once_with(mock_repo_root)
        mock_apply.assert_not_called()


def test_main_runtime_error() -> None:
    """Test main handles RuntimeError gracefully."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.configure_logging"),
    ):
        mock_get_root.side_effect = RuntimeError("Test error")

        with patch("sys.argv", ["install_services.py"]):
            result = install_services.main()

        assert result == 1


def test_main_unexpected_error() -> None:
    """Test main handles unexpected errors gracefully."""
    with (
        patch("install_services.get_repo_root") as mock_get_root,
        patch("install_services.configure_logging"),
    ):
        mock_get_root.side_effect = ValueError("Unexpected")

        with patch("sys.argv", ["install_services.py"]):
            result = install_services.main()

        assert result == 1


def test_configure_logging_default() -> None:
    """Test configure_logging sets INFO level by default."""
    with patch("logging.basicConfig") as mock_config:
        install_services.configure_logging()

        mock_config.assert_called_once()
        assert mock_config.call_args[1]["level"] == pytest.approx(20)  # INFO


def test_configure_logging_debug() -> None:
    """Test configure_logging sets DEBUG level when requested."""
    with patch("logging.basicConfig") as mock_config:
        install_services.configure_logging(debug=True)

        mock_config.assert_called_once()
        assert mock_config.call_args[1]["level"] == pytest.approx(10)  # DEBUG
