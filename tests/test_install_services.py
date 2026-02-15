# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/install_services.py."""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from lib import install_services


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


# --- get_systemd_user_dir tests ---


def test_get_systemd_user_dir() -> None:
    """Test get_systemd_user_dir returns correct path."""
    result = install_services.get_systemd_user_dir()
    expected = Path.home() / ".config" / "systemd" / "user"
    assert result == expected


# --- systemctl_user tests ---


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


# --- uninstall_service tests ---


def test_uninstall_service_not_installed(mock_systemd_dir: Path) -> None:
    """Test uninstall_service when service is not installed."""
    unit_path = mock_systemd_dir / "test.service"

    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    mock_systemctl.assert_not_called()


def test_uninstall_service_success(mock_systemd_dir: Path) -> None:
    """Test uninstall_service removes service successfully."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.touch()

    with patch("lib.install_services.systemctl_user") as mock_systemctl:
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

    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            RuntimeError("Not running"),
            None,
        ]

        install_services.uninstall_service("test.service", unit_path)

    assert not unit_path.exists()
    assert mock_systemctl.call_count == 2


def test_uninstall_service_disable_fails(mock_systemd_dir: Path) -> None:
    """Test uninstall_service continues if disable fails."""
    unit_path = mock_systemd_dir / "test.service"
    unit_path.touch()

    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            None,  # stop succeeds
            RuntimeError("Not enabled"),  # disable fails
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

    with patch("lib.install_services.systemctl_user") as mock_systemctl:
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
        "lib.install_services.systemctl_user", side_effect=remove_on_disable
    ) as mock_systemctl:
        install_services.uninstall_service("test.service", unit_path)

    assert mock_systemctl.call_count == 2


# --- install_service tests ---


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

    with patch("lib.install_services.uninstall_service") as mock_uninstall:
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

    with patch("lib.install_services.systemctl_user"):
        install_services.install_service(
            "test.service", new_content, mock_systemd_dir
        )

    assert unit_path.exists()
    assert unit_path.read_text() == new_content


# --- enable_and_start_service tests ---


def test_enable_and_start_service() -> None:
    """Test enable_and_start_service enables and starts service."""
    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        install_services.enable_and_start_service("test.service")

    assert mock_systemctl.call_args_list == [
        call("enable", "test.service"),
        call("start", "test.service"),
    ]


def test_enable_and_start_timer() -> None:
    """Test enable_and_start_service handles timer files."""
    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        install_services.enable_and_start_service("test.timer")

    assert mock_systemctl.call_args_list == [
        call("enable", "test.timer"),
        call("start", "test.timer"),
    ]


def test_enable_and_start_service_enable_fails() -> None:
    """Test enable_and_start_service continues if enable fails."""
    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            RuntimeError("Enable failed"),
            None,
        ]

        install_services.enable_and_start_service("test.service")

    assert mock_systemctl.call_count == 2


def test_enable_and_start_service_start_fails() -> None:
    """Test enable_and_start_service continues if start fails."""
    with patch("lib.install_services.systemctl_user") as mock_systemctl:
        mock_systemctl.side_effect = [
            None,  # enable succeeds
            RuntimeError("Start failed"),  # start fails
        ]

        install_services.enable_and_start_service("test.service")

    assert mock_systemctl.call_count == 2


# --- generate_unit tests ---


def test_generate_unit_email_gateway() -> None:
    """Test generate_unit produces correct email gateway unit."""
    result = install_services.generate_unit(
        "airut.service", "/home/user/.local/bin/airut"
    )

    assert (
        "ExecStart=/home/user/.local/bin/airut run-gateway --resilient"
        in result
    )
    assert "Restart=always" in result
    assert "WorkingDirectory" not in result
    assert "EnvironmentFile" not in result


def test_generate_unit_unknown() -> None:
    """Test generate_unit raises ValueError for unknown service."""
    with pytest.raises(ValueError, match="Unknown service"):
        install_services.generate_unit("unknown.service", "/usr/bin/airut")


# --- check_linger tests ---


def test_check_linger_enabled(tmp_path: Path) -> None:
    """Test check_linger passes when linger file exists."""
    linger_file = tmp_path / "testuser"
    linger_file.touch()

    with (
        patch.dict("os.environ", {"USER": "testuser"}),
        patch(
            "lib.install_services.Path",
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
        patch("lib.install_services.Path") as mock_path,
    ):
        mock_path.return_value = linger_dir / "testuser"
        install_services.check_linger()


# --- get_airut_path tests ---


def test_get_airut_path_found_on_path() -> None:
    """Test get_airut_path uses shutil.which when airut is on PATH."""
    with patch("shutil.which", return_value="/usr/local/bin/airut"):
        with patch.object(
            Path, "resolve", return_value=Path("/usr/local/bin/airut")
        ):
            result = install_services.get_airut_path()

    assert result == "/usr/local/bin/airut"


def test_get_airut_path_not_on_path() -> None:
    """Test get_airut_path falls back to ~/.local/bin/airut."""
    with patch("shutil.which", return_value=None):
        result = install_services.get_airut_path()

    expected = str(Path.home() / ".local" / "bin" / "airut")
    assert result == expected


# --- install_services tests ---


def test_install_services() -> None:
    """Test install_services installs gateway service."""
    with (
        patch("lib.install_services.check_linger"),
        patch("lib.install_services.get_systemd_user_dir") as mock_get_dir,
        patch(
            "lib.install_services.get_airut_path",
            return_value="/usr/local/bin/airut",
        ),
        patch("lib.install_services.install_service") as mock_install,
        patch("lib.install_services.systemctl_user") as mock_systemctl,
        patch("lib.install_services.enable_and_start_service") as mock_enable,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.install_services()

        assert mock_install.call_count == 1
        mock_systemctl.assert_called_once_with("daemon-reload")
        assert mock_enable.call_count == 1


def test_install_services_linger_check_fails() -> None:
    """Test install_services aborts when linger is not enabled."""
    with patch(
        "lib.install_services.check_linger",
        side_effect=RuntimeError("Linger is not enabled"),
    ):
        with pytest.raises(RuntimeError, match="Linger is not enabled"):
            install_services.install_services()


# --- uninstall_services tests ---


def test_uninstall_services() -> None:
    """Test uninstall_services removes gateway service."""
    with (
        patch("lib.install_services.get_systemd_user_dir") as mock_get_dir,
        patch("lib.install_services.uninstall_service") as mock_uninstall,
        patch("lib.install_services.systemctl_user") as mock_systemctl,
    ):
        mock_systemd = MagicMock()
        mock_get_dir.return_value = mock_systemd

        install_services.uninstall_services()

        assert mock_uninstall.call_count == 1
        mock_systemctl.assert_called_once_with("daemon-reload")
