# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/airut.py — multi-command CLI."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lib.airut import (
    _STUB_CONFIG,
    _check_dependency,
    _fmt_version,
    _parse_version,
    cli,
    cmd_check,
    cmd_init,
    cmd_run_gateway,
)


# ── _parse_version ──────────────────────────────────────────────────


class TestParseVersion:
    def test_git_version(self) -> None:
        assert _parse_version("git version 2.43.0") == (2, 43, 0)

    def test_podman_version(self) -> None:
        assert _parse_version("podman version 5.3.1") == (5, 3, 1)

    def test_version_with_trailing_text(self) -> None:
        assert _parse_version("gh version 2.62.0 (2024-11-14)") == (
            2,
            62,
            0,
        )

    def test_version_with_rc_suffix(self) -> None:
        assert _parse_version("tool 1.2.3-rc1") == (1, 2, 3)

    def test_single_number(self) -> None:
        assert _parse_version("v 4") == (4,)

    def test_no_version_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse version"):
            _parse_version("no version here")

    def test_empty_string_raises(self) -> None:
        with pytest.raises(ValueError, match="Cannot parse version"):
            _parse_version("")


# ── _fmt_version ────────────────────────────────────────────────────


class TestFmtVersion:
    def test_three_part(self) -> None:
        assert _fmt_version((2, 43, 0)) == "2.43.0"

    def test_two_part(self) -> None:
        assert _fmt_version((4, 0)) == "4.0"

    def test_single_part(self) -> None:
        assert _fmt_version((5,)) == "5"


# ── _check_dependency ───────────────────────────────────────────────


class TestCheckDependency:
    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/git")
    def test_found_with_good_version(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="git version 2.43.0", stderr=""
        )
        assert _check_dependency("git", ["git", "--version"], (2, 25))

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/podman")
    def test_found_but_too_old(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="podman version 3.4.0", stderr=""
        )
        assert not _check_dependency("podman", ["podman", "--version"], (4, 0))

    @patch("lib.airut.shutil.which", return_value=None)
    def test_not_found(self, _which: MagicMock) -> None:
        assert not _check_dependency("missing", ["missing", "--version"])

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/gh")
    def test_no_min_version(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="gh version 2.62.0 (2024-11-14)", stderr=""
        )
        assert _check_dependency("gh", ["gh", "--version"])

    @patch("lib.airut.subprocess.run", side_effect=FileNotFoundError)
    @patch("lib.airut.shutil.which", return_value="/usr/bin/broken")
    def test_command_fails(self, _which: MagicMock, _run: MagicMock) -> None:
        assert not _check_dependency("broken", ["broken", "--version"])

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/weird")
    def test_unparseable_version(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(stdout="no version info", stderr="")
        assert not _check_dependency("weird", ["weird", "--version"])

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/git")
    def test_exact_min_version_passes(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="git version 2.25.0", stderr=""
        )
        assert _check_dependency("git", ["git", "--version"], (2, 25))

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/tool")
    def test_stderr_fallback(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="", stderr="tool version 1.0.0"
        )
        assert _check_dependency("tool", ["tool", "--version"])


# ── cmd_init ────────────────────────────────────────────────────────


class TestCmdInit:
    def test_creates_config(self, tmp_path: Path) -> None:
        """Creates stub config when file does not exist."""
        config_path = tmp_path / "airut" / "airut.yaml"
        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_init([])

        assert result == 0
        assert config_path.exists()
        assert config_path.read_text() == _STUB_CONFIG

    def test_creates_parent_dirs(self, tmp_path: Path) -> None:
        """Creates parent directories if they don't exist."""
        config_path = tmp_path / "deep" / "nested" / "airut.yaml"
        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_init([])

        assert result == 0
        assert config_path.exists()

    def test_existing_config_not_overwritten(self, tmp_path: Path) -> None:
        """Does not overwrite existing config file."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text("existing: config\n")

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_init([])

        assert result == 0
        assert config_path.read_text() == "existing: config\n"

    def test_prints_created_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Prints message when config is created."""
        config_path = tmp_path / "airut.yaml"
        with patch("lib.airut.get_config_path", return_value=config_path):
            cmd_init([])

        captured = capsys.readouterr()
        assert "Created stub config:" in captured.out
        assert str(config_path) in captured.out

    def test_prints_exists_message(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Prints message when config already exists."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text("existing: config\n")

        with patch("lib.airut.get_config_path", return_value=config_path):
            cmd_init([])

        captured = capsys.readouterr()
        assert "Config already exists:" in captured.out
        assert str(config_path) in captured.out


# ── cmd_check ───────────────────────────────────────────────────────


class TestCmdCheck:
    @patch("lib.airut._check_dependency", return_value=True)
    def test_valid_config_and_deps(
        self, _dep: MagicMock, tmp_path: Path
    ) -> None:
        """Returns 0 when config is valid and dependencies pass."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text(
            """\
repos:
  test:
    email:
      imap_server: imap.test.com
      smtp_server: smtp.test.com
      username: user@test.com
      password: secret
      from: "Test <test@example.com>"
    authorized_senders:
      - auth@test.com
    trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/repo.git
"""
        )

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 0
        assert _dep.call_count == 2

    @patch("lib.airut._check_dependency", return_value=True)
    def test_missing_config(self, _dep: MagicMock, tmp_path: Path) -> None:
        """Returns 1 when config file is missing."""
        config_path = tmp_path / "nonexistent.yaml"
        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 1

    @patch("lib.airut._check_dependency", return_value=True)
    def test_invalid_yaml(self, _dep: MagicMock, tmp_path: Path) -> None:
        """Returns 1 for invalid YAML."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text("not: [valid: yaml: {{")

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 1

    @patch("lib.airut._check_dependency", return_value=True)
    def test_missing_required_field(
        self, _dep: MagicMock, tmp_path: Path
    ) -> None:
        """Returns 1 when a required field is missing."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text(
            """\
repos:
  test:
    email:
      imap_server: imap.test.com
"""
        )

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 1

    @patch("lib.airut._check_dependency", return_value=True)
    def test_empty_config_file(self, _dep: MagicMock, tmp_path: Path) -> None:
        """Returns 1 for an empty config file."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text("")

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 1

    @patch("lib.airut._check_dependency", return_value=True)
    def test_multiple_repos(self, _dep: MagicMock, tmp_path: Path) -> None:
        """Succeeds with multiple repos configured."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text(
            """\
repos:
  alpha:
    email:
      imap_server: imap.test.com
      smtp_server: smtp.test.com
      username: alpha@test.com
      password: secret
      from: "Alpha <alpha@example.com>"
    authorized_senders:
      - auth@test.com
    trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/alpha.git
  beta:
    email:
      imap_server: imap2.test.com
      smtp_server: smtp2.test.com
      username: beta@test.com
      password: secret
      from: "Beta <beta@example.com>"
    authorized_senders:
      - auth@test.com
    trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/beta.git
"""
        )

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 0

    @patch("lib.airut._check_dependency", return_value=False)
    def test_dependency_failure(self, _dep: MagicMock, tmp_path: Path) -> None:
        """Returns 1 when dependencies fail even if config is valid."""
        config_path = tmp_path / "airut.yaml"
        config_path.write_text(
            """\
repos:
  test:
    email:
      imap_server: imap.test.com
      smtp_server: smtp.test.com
      username: user@test.com
      password: secret
      from: "Test <test@example.com>"
    authorized_senders:
      - auth@test.com
    trusted_authserv_id: mx.test.com
    git:
      repo_url: https://example.com/repo.git
"""
        )

        with patch("lib.airut.get_config_path", return_value=config_path):
            result = cmd_check([])

        assert result == 1


# ── cmd_run_gateway ─────────────────────────────────────────────────


class TestCmdRunGateway:
    @patch("lib.gateway.service.main", return_value=0)
    def test_forwards_args(self, mock_main: MagicMock) -> None:
        result = cmd_run_gateway(["--resilient", "--debug"])
        mock_main.assert_called_once_with(["--resilient", "--debug"])
        assert result == 0

    @patch("lib.gateway.service.main", return_value=0)
    def test_empty_args(self, mock_main: MagicMock) -> None:
        result = cmd_run_gateway([])
        mock_main.assert_called_once_with([])
        assert result == 0


# ── cli() dispatch ──────────────────────────────────────────────────


class TestCli:
    @patch("lib.airut.sys.exit")
    @patch("lib.gateway.service.main", return_value=0)
    def test_no_args_defaults_to_gateway(
        self, mock_main: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut"]):
            cli()
        mock_main.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.gateway.service.main", return_value=0)
    def test_bare_flags_forward_to_gateway(
        self, mock_main: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "--resilient"]):
            cli()
        mock_main.assert_called_once_with(["--resilient"])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.gateway.service.main", return_value=0)
    def test_explicit_run_gateway(
        self, mock_main: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch(
            "lib.airut.sys.argv",
            ["airut", "run-gateway", "--debug"],
        ):
            cli()
        mock_main.assert_called_once_with(["--debug"])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.airut.cmd_init", return_value=0)
    def test_init_subcommand(
        self, mock_init: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "init"]):
            cli()
        mock_init.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.airut.cmd_check", return_value=0)
    def test_check_subcommand(
        self, mock_check: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "check"]):
            cli()
        mock_check.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.gateway.service.main", return_value=1)
    def test_nonzero_exit_propagated(
        self, mock_main: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut"]):
            cli()
        mock_exit.assert_called_once_with(1)

    def test_help_flag(self) -> None:
        with (
            patch("lib.airut.sys.argv", ["airut", "--help"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            cli()
        assert exc_info.value.code == 0
