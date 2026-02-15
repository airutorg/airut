# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/airut.py — multi-command CLI."""

import subprocess
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lib.airut import (
    _STUB_CONFIG,
    _check_dependency,
    _dashboard_url,
    _fetch_running_version,
    _fmt_version,
    _is_service_installed,
    _is_service_running,
    _local_dashboard_url,
    _parse_version,
    _print_info,
    _Style,
    _use_color,
    cli,
    cmd_check,
    cmd_init,
    cmd_install_service,
    cmd_run_gateway,
    cmd_uninstall_service,
    cmd_update,
)
from lib.git_version import UpstreamVersion


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
        ok, detail = _check_dependency("git", ["git", "--version"], (2, 25))
        assert ok
        assert "2.43.0" in detail

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/podman")
    def test_found_but_too_old(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="podman version 3.4.0", stderr=""
        )
        ok, detail = _check_dependency(
            "podman", ["podman", "--version"], (4, 0)
        )
        assert not ok
        assert "need >=" in detail

    @patch("lib.airut.shutil.which", return_value=None)
    def test_not_found(self, _which: MagicMock) -> None:
        ok, detail = _check_dependency("missing", ["missing", "--version"])
        assert not ok
        assert "not found" in detail

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/gh")
    def test_no_min_version(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="gh version 2.62.0 (2024-11-14)", stderr=""
        )
        ok, detail = _check_dependency("gh", ["gh", "--version"])
        assert ok
        assert "2.62.0" in detail

    @patch("lib.airut.subprocess.run", side_effect=FileNotFoundError)
    @patch("lib.airut.shutil.which", return_value="/usr/bin/broken")
    def test_command_fails(self, _which: MagicMock, _run: MagicMock) -> None:
        ok, detail = _check_dependency("broken", ["broken", "--version"])
        assert not ok
        assert "failed to get version" in detail

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/weird")
    def test_unparseable_version(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(stdout="no version info", stderr="")
        ok, detail = _check_dependency("weird", ["weird", "--version"])
        assert not ok
        assert "cannot parse version" in detail

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/git")
    def test_exact_min_version_passes(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="git version 2.25.0", stderr=""
        )
        ok, _detail = _check_dependency("git", ["git", "--version"], (2, 25))
        assert ok

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut.shutil.which", return_value="/usr/bin/tool")
    def test_stderr_fallback(
        self, _which: MagicMock, mock_run: MagicMock
    ) -> None:
        mock_run.return_value = MagicMock(
            stdout="", stderr="tool version 1.0.0"
        )
        ok, _detail = _check_dependency("tool", ["tool", "--version"])
        assert ok


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


# ── _use_color ─────────────────────────────────────────────────────


class TestUseColor:
    def test_no_color_env(self) -> None:
        """NO_COLOR env var disables color."""
        with patch.dict("os.environ", {"NO_COLOR": "1"}, clear=False):
            assert not _use_color()

    def test_dumb_terminal(self) -> None:
        """TERM=dumb disables color."""
        env = {"TERM": "dumb"}
        with patch.dict("os.environ", env, clear=False):
            assert not _use_color()

    def test_non_tty(self) -> None:
        """Non-TTY stdout disables color."""
        with patch("lib.airut.sys.stdout") as mock_stdout:
            mock_stdout.isatty.return_value = False
            assert not _use_color()

    def test_tty_with_no_overrides(self) -> None:
        """TTY stdout with no env overrides enables color."""
        env: dict[str, str] = {}
        with (
            patch.dict("os.environ", env, clear=True),
            patch("lib.airut.sys.stdout") as mock_stdout,
        ):
            mock_stdout.isatty.return_value = True
            assert _use_color()


# ── _Style ─────────────────────────────────────────────────────────


class TestStyle:
    def test_color_on(self) -> None:
        """Wraps text with ANSI codes when color is enabled."""
        s = _Style(True)
        assert s.green("ok") == "\033[32mok\033[0m"
        assert s.red("fail") == "\033[31mfail\033[0m"
        assert s.bold("title") == "\033[1mtitle\033[0m"
        assert s.yellow("warn") == "\033[33mwarn\033[0m"
        assert s.dim("path") == "\033[2mpath\033[0m"
        assert s.cyan("cmd") == "\033[36mcmd\033[0m"

    def test_color_off(self) -> None:
        """Returns plain text when color is disabled."""
        s = _Style(False)
        assert s.green("ok") == "ok"
        assert s.red("fail") == "fail"
        assert s.bold("title") == "title"
        assert s.yellow("warn") == "warn"
        assert s.dim("path") == "path"
        assert s.cyan("cmd") == "cmd"


# ── _is_service_installed / _is_service_running ───────────────────


class TestServiceStatus:
    def test_installed_when_unit_exists(self, tmp_path: Path) -> None:
        """Returns True when unit file exists."""
        unit = tmp_path / "airut.service"
        unit.write_text("[Unit]\n")
        with patch(
            "lib.install_services.get_systemd_user_dir",
            return_value=tmp_path,
        ):
            assert _is_service_installed()

    def test_not_installed(self, tmp_path: Path) -> None:
        """Returns False when unit file is absent."""
        with patch(
            "lib.install_services.get_systemd_user_dir",
            return_value=tmp_path,
        ):
            assert not _is_service_installed()

    @patch("lib.airut.subprocess.run")
    def test_running(self, mock_run: MagicMock) -> None:
        """Returns True when systemctl reports active."""
        mock_run.return_value = MagicMock(stdout="active\n")
        assert _is_service_running()

    @patch("lib.airut.subprocess.run")
    def test_not_running(self, mock_run: MagicMock) -> None:
        """Returns False when systemctl reports inactive."""
        mock_run.return_value = MagicMock(stdout="inactive\n")
        assert not _is_service_running()

    @patch("lib.airut.subprocess.run", side_effect=FileNotFoundError)
    def test_running_no_systemctl(self, _run: MagicMock) -> None:
        """Returns False when systemctl is not available."""
        assert not _is_service_running()


# ── _dashboard_url ─────────────────────────────────────────────────


class TestDashboardUrl:
    def test_base_url_configured(self) -> None:
        """Uses dashboard_base_url when set."""

        @dataclass
        class FakeGlobal:
            dashboard_base_url: str | None = "https://dash.example.com"
            dashboard_host: str = "127.0.0.1"
            dashboard_port: int = 5200

        config = MagicMock()
        config.global_config = FakeGlobal()
        assert _dashboard_url(config) == "https://dash.example.com"

    def test_fallback_to_host_port(self) -> None:
        """Falls back to host:port when base_url is None."""

        @dataclass
        class FakeGlobal:
            dashboard_base_url: str | None = None
            dashboard_host: str = "0.0.0.0"
            dashboard_port: int = 8080

        config = MagicMock()
        config.global_config = FakeGlobal()
        assert _dashboard_url(config) == "http://0.0.0.0:8080"


# ── _local_dashboard_url ──────────────────────────────────────────


class TestLocalDashboardUrl:
    def test_ignores_base_url(self) -> None:
        """Always uses host:port, ignoring dashboard_base_url."""

        @dataclass
        class FakeGlobal:
            dashboard_base_url: str | None = "https://dash.example.com"
            dashboard_host: str = "127.0.0.1"
            dashboard_port: int = 5200

        config = MagicMock()
        config.global_config = FakeGlobal()
        assert _local_dashboard_url(config) == "http://127.0.0.1:5200"

    def test_custom_host_port(self) -> None:
        """Uses configured host and port."""

        @dataclass
        class FakeGlobal:
            dashboard_base_url: str | None = None
            dashboard_host: str = "0.0.0.0"
            dashboard_port: int = 8080

        config = MagicMock()
        config.global_config = FakeGlobal()
        assert _local_dashboard_url(config) == "http://0.0.0.0:8080"


# ── _fetch_running_version ─────────────────────────────────────────


class TestFetchRunningVersion:
    @patch("lib.airut.urllib.request.urlopen")
    def test_success(self, mock_urlopen: MagicMock) -> None:
        """Returns parsed JSON on success."""
        body = b'{"version":"v0.8.0","sha_short":"abc1234","sha_full":"abc"}'
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _fetch_running_version("http://127.0.0.1:5200")
        assert result is not None
        assert result["sha_short"] == "abc1234"

    @patch(
        "lib.airut.urllib.request.urlopen",
        side_effect=OSError("refused"),
    )
    def test_connection_refused(self, _m: MagicMock) -> None:
        """Returns None on connection error."""
        assert _fetch_running_version("http://127.0.0.1:5200") is None

    @patch("lib.airut.urllib.request.urlopen")
    def test_bad_json(self, mock_urlopen: MagicMock) -> None:
        """Returns None on malformed JSON."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        assert _fetch_running_version("http://127.0.0.1:5200") is None


# ── cmd_check ───────────────────────────────────────────────────────

# Shared valid config YAML used by multiple tests.
_VALID_CONFIG = """\
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


@dataclass
class _FakeVersionInfo:
    version: str = "v0.8.0"
    sha_short: str = "abc1234"
    sha_full: str = "abc1234" * 5
    worktree_clean: bool = True
    full_status: str = ""


def _check_patches(
    tmp_path: Path,
    *,
    config_text: str | None = _VALID_CONFIG,
    dep_ok: bool = True,
    service_installed: bool = False,
    service_running: bool = False,
    dotenv: bool = False,
    running_version: dict[str, str] | None = None,
    upstream_version: object | None = None,
):
    """Build a ``contextmanager`` that patches everything cmd_check needs.

    Returns (config_path, context_manager).
    """
    config_path = tmp_path / "airut.yaml"
    if config_text is not None:
        config_path.write_text(config_text)

    dotenv_path = tmp_path / ".env"
    if dotenv:
        dotenv_path.write_text("SOME_VAR=1\n")

    from contextlib import ExitStack

    stack = ExitStack()
    stack.enter_context(
        patch("lib.airut.get_config_path", return_value=config_path)
    )
    stack.enter_context(
        patch("lib.airut.get_dotenv_path", return_value=dotenv_path)
    )
    stack.enter_context(
        patch(
            "lib.airut._check_dependency",
            return_value=(dep_ok, "git: 2.43.0 (>= 2.25)"),
        )
    )
    stack.enter_context(
        patch(
            "lib.git_version.get_git_version_info",
            return_value=_FakeVersionInfo(),
        )
    )
    stack.enter_context(
        patch(
            "lib.airut._is_service_installed",
            return_value=service_installed,
        )
    )
    stack.enter_context(
        patch(
            "lib.airut._is_service_running",
            return_value=service_running,
        )
    )
    stack.enter_context(
        patch(
            "lib.airut._fetch_running_version",
            return_value=running_version,
        )
    )
    stack.enter_context(
        patch(
            "lib.git_version.check_upstream_version",
            return_value=upstream_version,
        )
    )
    stack.enter_context(patch("lib.airut._use_color", return_value=False))
    return config_path, stack


class TestCmdCheck:
    def test_valid_config_and_deps(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 0 when config is valid and dependencies pass."""
        _path, ctx = _check_patches(tmp_path)
        with ctx:
            result = cmd_check([])
        assert result == 0
        out = capsys.readouterr().out
        assert "All checks passed." in out
        assert "Airut v0.8.0" in out

    def test_missing_config(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when config file is missing."""
        _path, ctx = _check_patches(tmp_path, config_text=None)
        with ctx:
            result = cmd_check([])
        assert result == 1
        out = capsys.readouterr().out
        assert "not found" in out
        assert "airut init" in out

    def test_invalid_yaml(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 for invalid YAML."""
        _path, ctx = _check_patches(
            tmp_path, config_text="not: [valid: yaml: {{"
        )
        with ctx:
            result = cmd_check([])
        assert result == 1
        out = capsys.readouterr().out
        assert "error" in out

    def test_missing_required_field(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when a required field is missing."""
        _path, ctx = _check_patches(
            tmp_path,
            config_text="repos:\n  test:\n    email:\n      imap_server: x\n",
        )
        with ctx:
            result = cmd_check([])
        assert result == 1

    def test_empty_config_file(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 for an empty config file."""
        _path, ctx = _check_patches(tmp_path, config_text="")
        with ctx:
            result = cmd_check([])
        assert result == 1

    def test_multiple_repos(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Succeeds with multiple repos configured."""
        multi = """\
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
        _path, ctx = _check_patches(tmp_path, config_text=multi)
        with ctx:
            result = cmd_check([])
        assert result == 0
        out = capsys.readouterr().out
        assert "2 repo(s)" in out

    def test_dependency_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 1 when dependencies fail even if config is valid."""
        _path, ctx = _check_patches(tmp_path, dep_ok=False)
        with ctx:
            result = cmd_check([])
        assert result == 1
        out = capsys.readouterr().out
        assert "Some checks failed." in out

    def test_shows_config_path(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Always prints the config file path."""
        config_path, ctx = _check_patches(tmp_path)
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert str(config_path) in out

    def test_shows_dotenv_when_exists(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows .env path when the file exists."""
        _path, ctx = _check_patches(tmp_path, dotenv=True)
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert ".env" in out
        assert "Env file:" in out

    def test_hides_dotenv_when_absent(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Does not mention .env when the file is absent."""
        _path, ctx = _check_patches(tmp_path, dotenv=False)
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Env file:" not in out

    def test_service_not_installed(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows 'not installed' and suggests install-service."""
        _path, ctx = _check_patches(tmp_path, service_installed=False)
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "not installed" in out
        assert "airut install-service" in out

    def test_service_installed_stopped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows 'stopped' when installed but not running."""
        _path, ctx = _check_patches(
            tmp_path, service_installed=True, service_running=False
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "stopped" in out

    def test_service_running_shows_url(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows dashboard URL when service is running and config loaded."""
        _path, ctx = _check_patches(
            tmp_path,
            service_installed=True,
            service_running=True,
            running_version={
                "version": "v0.8.0",
                "sha_short": "abc1234",
                "sha_full": "abc",
            },
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "running" in out
        assert "http://" in out

    def test_service_does_not_affect_exit_code(self, tmp_path: Path) -> None:
        """Service not installed does not cause exit code 1."""
        _path, ctx = _check_patches(tmp_path, service_installed=False)
        with ctx:
            result = cmd_check([])
        assert result == 0

    def test_version_mismatch_warning(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Warns when running server version differs from installed."""
        _path, ctx = _check_patches(
            tmp_path,
            service_installed=True,
            service_running=True,
            running_version={
                "version": "v0.7.0",
                "sha_short": "old5678",
                "sha_full": "old5678" * 5,
            },
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Version mismatch" in out
        assert "v0.7.0" in out
        assert "airut update" in out

    def test_no_mismatch_when_versions_match(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No warning when running version matches installed."""
        _path, ctx = _check_patches(
            tmp_path,
            service_installed=True,
            service_running=True,
            running_version={
                "version": "v0.8.0",
                "sha_short": "abc1234",
                "sha_full": "abc",
            },
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Version mismatch" not in out

    def test_no_mismatch_when_fetch_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No warning when version fetch fails (returns None)."""
        _path, ctx = _check_patches(
            tmp_path,
            service_installed=True,
            service_running=True,
            running_version=None,
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Version mismatch" not in out

    def test_version_fetch_uses_local_url(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Version fetch bypasses dashboard_base_url and uses local addr."""
        config_with_base_url = _VALID_CONFIG + (
            "dashboard:\n"
            "  base_url: https://dash.example.com\n"
            "  host: 127.0.0.1\n"
            "  port: 5200\n"
        )
        config_path = tmp_path / "airut.yaml"
        config_path.write_text(config_with_base_url)
        dotenv_path = tmp_path / ".env"

        from contextlib import ExitStack

        stack = ExitStack()
        stack.enter_context(
            patch("lib.airut.get_config_path", return_value=config_path)
        )
        stack.enter_context(
            patch("lib.airut.get_dotenv_path", return_value=dotenv_path)
        )
        stack.enter_context(
            patch(
                "lib.airut._check_dependency",
                return_value=(True, "git: 2.43.0 (>= 2.25)"),
            )
        )
        stack.enter_context(
            patch(
                "lib.git_version.get_git_version_info",
                return_value=_FakeVersionInfo(),
            )
        )
        stack.enter_context(
            patch("lib.airut._is_service_installed", return_value=True)
        )
        stack.enter_context(
            patch("lib.airut._is_service_running", return_value=True)
        )
        mock_fetch = MagicMock(return_value=None)
        stack.enter_context(
            patch("lib.airut._fetch_running_version", mock_fetch)
        )
        stack.enter_context(
            patch(
                "lib.git_version.check_upstream_version",
                return_value=None,
            )
        )
        stack.enter_context(patch("lib.airut._use_color", return_value=False))
        with stack:
            cmd_check([])
        mock_fetch.assert_called_once_with("http://127.0.0.1:5200")
        # Public URL should still appear in service status display
        out = capsys.readouterr().out
        assert "https://dash.example.com" in out

    def test_shows_pypi_update(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows update available message for PyPI installs."""
        _path, ctx = _check_patches(
            tmp_path,
            upstream_version=UpstreamVersion(
                source="pypi",
                latest="0.9.0",
                current="0.8.0",
                update_available=True,
            ),
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Update available:" in out
        assert "0.8.0" in out
        assert "0.9.0" in out
        assert "airut update" in out

    def test_shows_github_update(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Shows update available message for VCS/GitHub installs."""
        _path, ctx = _check_patches(
            tmp_path,
            upstream_version=UpstreamVersion(
                source="github",
                latest="b" * 40,
                current="a" * 40,
                update_available=True,
            ),
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Update available:" in out
        assert "aaaaaaa" in out
        assert "bbbbbbb" in out
        assert "airut update" in out

    def test_no_update_message_when_up_to_date(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No update message when upstream matches installed."""
        _path, ctx = _check_patches(
            tmp_path,
            upstream_version=UpstreamVersion(
                source="pypi",
                latest="0.8.0",
                current="0.8.0",
                update_available=False,
            ),
        )
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Update available:" not in out

    def test_no_update_message_when_check_fails(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """No update message when upstream check returns None."""
        _path, ctx = _check_patches(tmp_path, upstream_version=None)
        with ctx:
            cmd_check([])
        out = capsys.readouterr().out
        assert "Update available:" not in out


# ── cmd_update ──────────────────────────────────────────────────────


class TestCmdUpdate:
    @patch("lib.airut.subprocess.run")
    @patch("lib.airut._is_service_installed", return_value=False)
    @patch("lib.airut._use_color", return_value=False)
    def test_no_service_upgrade_only(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Runs uv upgrade without service management."""
        mock_run.return_value = MagicMock(
            returncode=0, stdout="Updated airut v0.8.0 -> v0.9.0", stderr=""
        )
        result = cmd_update([])
        assert result == 0
        mock_run.assert_called_once_with(
            ["uv", "tool", "upgrade", "airut"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        out = capsys.readouterr().out
        assert "Update complete." in out
        assert "Stopping" not in out
        assert "Reinstalling" not in out

    @patch("lib.airut.subprocess.run")
    @patch("lib.install_services.get_airut_path", return_value="/usr/bin/airut")
    @patch("lib.install_services.uninstall_services")
    @patch("lib.airut._is_service_installed", return_value=True)
    @patch("lib.airut._use_color", return_value=False)
    def test_service_installed_full_cycle(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        mock_uninstall: MagicMock,
        _airut_path: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Full cycle: uninstall, upgrade, reinstall."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="Updated", stderr=""),  # uv upgrade
            MagicMock(returncode=0, stdout="", stderr=""),  # install-service
        ]
        result = cmd_update([])
        assert result == 0
        mock_uninstall.assert_called_once()
        out = capsys.readouterr().out
        assert "Stopping and uninstalling" in out
        assert "Reinstalling" in out
        assert "Update complete." in out

    @patch("lib.airut.subprocess.run", side_effect=FileNotFoundError)
    @patch("lib.airut._is_service_installed", return_value=False)
    @patch("lib.airut._use_color", return_value=False)
    def test_uv_not_found(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        _run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when uv is not on PATH."""
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "uv not found" in out

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut._is_service_installed", return_value=False)
    @patch("lib.airut._use_color", return_value=False)
    def test_uv_upgrade_fails(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when uv tool upgrade returns non-zero."""
        mock_run.return_value = MagicMock(
            returncode=1, stdout="", stderr="error: no such tool"
        )
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "uv tool upgrade failed" in out

    @patch(
        "lib.install_services.uninstall_services",
        side_effect=RuntimeError("fail"),
    )
    @patch("lib.airut._is_service_installed", return_value=True)
    @patch("lib.airut._use_color", return_value=False)
    def test_uninstall_error(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        _uninstall: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when uninstall_services raises RuntimeError."""
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "Error uninstalling service" in out

    @patch("lib.airut.subprocess.run")
    @patch("lib.install_services.get_airut_path", return_value="/usr/bin/airut")
    @patch("lib.install_services.uninstall_services")
    @patch("lib.airut._is_service_installed", return_value=True)
    @patch("lib.airut._use_color", return_value=False)
    def test_reinstall_fails(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        _uninstall: MagicMock,
        _airut_path: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when reinstalling service fails."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="Updated", stderr=""),  # uv upgrade
            MagicMock(
                returncode=1, stdout="", stderr="linger error"
            ),  # install
        ]
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "Error reinstalling service" in out

    @patch("lib.airut.subprocess.run")
    @patch(
        "lib.install_services.get_airut_path",
        return_value="/nonexistent/airut",
    )
    @patch("lib.install_services.uninstall_services")
    @patch("lib.airut._is_service_installed", return_value=True)
    @patch("lib.airut._use_color", return_value=False)
    def test_reinstall_binary_not_found(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        _uninstall: MagicMock,
        _airut_path: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when updated airut binary is not found."""
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="Updated", stderr=""),  # uv upgrade
            FileNotFoundError("not found"),  # install-service
        ]
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "Error reinstalling service" in out

    @patch(
        "lib.airut.subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd="uv", timeout=120),
    )
    @patch("lib.airut._is_service_installed", return_value=False)
    @patch("lib.airut._use_color", return_value=False)
    def test_uv_timeout(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        _run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when uv tool upgrade times out."""
        result = cmd_update([])
        assert result == 1
        out = capsys.readouterr().out
        assert "timed out" in out

    @patch("lib.airut.subprocess.run")
    @patch("lib.airut._is_service_installed", return_value=False)
    @patch("lib.airut._use_color", return_value=False)
    def test_no_output_from_upgrade(
        self,
        _color: MagicMock,
        _installed: MagicMock,
        mock_run: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Succeeds even when uv produces no output."""
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        result = cmd_update([])
        assert result == 0
        out = capsys.readouterr().out
        assert "Update complete." in out


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


# ── _print_info ─────────────────────────────────────────────────────


class TestPrintInfo:
    @patch("lib.airut._use_color", return_value=False)
    @patch(
        "lib.git_version.get_git_version_info",
        return_value=_FakeVersionInfo(),
    )
    def test_shows_version_and_usage(
        self,
        _vi: MagicMock,
        _color: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Prints version header and usage listing all commands."""
        _print_info()
        out = capsys.readouterr().out
        assert "Airut v0.8.0" in out
        assert "run-gateway" in out
        assert "init" in out
        assert "check" in out
        assert "update" in out
        assert "install-service" in out
        assert "uninstall-service" in out

    @patch("lib.airut._use_color", return_value=False)
    @patch(
        "lib.git_version.get_git_version_info",
        return_value=_FakeVersionInfo(version="", sha_short="def5678"),
    )
    def test_falls_back_to_sha(
        self,
        _vi: MagicMock,
        _color: MagicMock,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Falls back to SHA when version tag is empty."""
        _print_info()
        out = capsys.readouterr().out
        assert "Airut def5678" in out


# ── cli() dispatch ──────────────────────────────────────────────────


class TestCli:
    def test_no_args_prints_info(self) -> None:
        """Bare ``airut`` prints version and usage, exits 0."""
        with (
            patch("lib.airut.sys.argv", ["airut"]),
            patch("lib.airut._print_info") as mock_info,
            pytest.raises(SystemExit) as exc_info,
        ):
            cli()
        mock_info.assert_called_once()
        assert exc_info.value.code == 0

    def test_unknown_command_exits_with_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Unknown command prints error to stderr and exits 2."""
        with (
            patch("lib.airut.sys.argv", ["airut", "--resilient"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            cli()
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "unknown command '--resilient'" in err
        assert "run-gateway" in err

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
        with patch("lib.airut.sys.argv", ["airut", "run-gateway"]):
            cli()
        mock_exit.assert_called_once_with(1)

    @patch("lib.airut.sys.exit")
    @patch("lib.airut.cmd_update", return_value=0)
    def test_update_subcommand(
        self, mock_update: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "update"]):
            cli()
        mock_update.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.airut.cmd_install_service", return_value=0)
    def test_install_service_subcommand(
        self, mock_install: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "install-service"]):
            cli()
        mock_install.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    @patch("lib.airut.sys.exit")
    @patch("lib.airut.cmd_uninstall_service", return_value=0)
    def test_uninstall_service_subcommand(
        self, mock_uninstall: MagicMock, mock_exit: MagicMock
    ) -> None:
        with patch("lib.airut.sys.argv", ["airut", "uninstall-service"]):
            cli()
        mock_uninstall.assert_called_once_with([])
        mock_exit.assert_called_once_with(0)

    def test_help_flag(self) -> None:
        """``airut --help`` prints version and usage, exits 0."""
        with (
            patch("lib.airut.sys.argv", ["airut", "--help"]),
            patch("lib.airut._print_info") as mock_info,
            pytest.raises(SystemExit) as exc_info,
        ):
            cli()
        mock_info.assert_called_once()
        assert exc_info.value.code == 0


# ── cmd_install_service ────────────────────────────────────────────


class TestCmdInstallService:
    @patch("lib.install_services.install_services")
    def test_default(self, mock_install: MagicMock) -> None:
        """Calls install_services."""
        result = cmd_install_service([])
        assert result == 0
        mock_install.assert_called_once_with()

    @patch(
        "lib.install_services.install_services",
        side_effect=RuntimeError("Linger not enabled"),
    )
    def test_runtime_error(self, _mock: MagicMock) -> None:
        """Returns 1 on RuntimeError."""
        result = cmd_install_service([])
        assert result == 1


# ── cmd_uninstall_service ──────────────────────────────────────────


class TestCmdUninstallService:
    @patch("lib.install_services.uninstall_services")
    def test_default(self, mock_uninstall: MagicMock) -> None:
        """Calls uninstall_services."""
        result = cmd_uninstall_service([])
        assert result == 0
        mock_uninstall.assert_called_once()

    @patch(
        "lib.install_services.uninstall_services",
        side_effect=RuntimeError("systemctl failed"),
    )
    def test_runtime_error(self, _mock: MagicMock) -> None:
        """Returns 1 on RuntimeError."""
        result = cmd_uninstall_service([])
        assert result == 1
