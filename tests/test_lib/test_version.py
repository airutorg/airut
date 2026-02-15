# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/version.py."""

import json
import subprocess
import urllib.error
from importlib.metadata import PackageNotFoundError
from unittest.mock import MagicMock, patch

from lib.version import (
    GitVersionInfo,
    InstallSource,
    UpstreamVersion,
    _check_github,
    _check_pypi,
    _fetch_pypi_version,
    _get_git_version_info_live,
    _is_older,
    _try_embedded,
    check_upstream_version,
    get_git_version_info,
    get_install_source,
    github_commit_url,
    github_release_url,
    is_exact_version_tag,
)


class TestGitVersionInfo:
    """Tests for GitVersionInfo dataclass."""

    def test_dataclass_fields(self) -> None:
        """GitVersionInfo should have all expected fields."""
        info = GitVersionInfo(
            version="v0.7.0",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="status output",
        )
        assert info.version == "v0.7.0"
        assert info.sha_short == "abc1234"
        assert info.sha_full == "abc1234567890abcdef1234567890abcdef123456"
        assert info.full_status == "status output"

    def test_empty_version(self) -> None:
        """GitVersionInfo should accept empty version string."""
        info = GitVersionInfo(
            version="",
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            full_status="status output",
        )
        assert info.version == ""


class TestTryEmbedded:
    """Tests for _try_embedded function."""

    def test_returns_none_when_no_module(self) -> None:
        """Should return None when lib._version is not importable."""
        import sys

        # Temporarily remove lib._version from sys.modules so the
        # import inside _try_embedded raises ImportError.
        saved = sys.modules.pop("lib._version", None)
        with patch.dict(sys.modules, {"lib._version": None}):
            result = _try_embedded()
        if saved is not None:
            sys.modules["lib._version"] = saved
        assert result is None

    def test_returns_info_when_module_exists(self) -> None:
        """Should return GitVersionInfo when lib._version is importable."""
        mock_module = MagicMock()
        mock_module.VERSION = "v0.7.0"
        mock_module.GIT_SHA_SHORT = "abc1234"
        mock_module.GIT_SHA_FULL = "abc1234567890abcdef1234567890abcdef123456"

        import sys

        with patch.dict(sys.modules, {"lib._version": mock_module}):
            result = _try_embedded()

        assert result is not None
        assert result.version == "v0.7.0"
        assert result.sha_short == "abc1234"
        assert result.sha_full == ("abc1234567890abcdef1234567890abcdef123456")
        assert "=== VERSION ===" in result.full_status
        assert "v0.7.0" in result.full_status


class TestGetGitVersionInfo:
    """Tests for get_git_version_info function."""

    def test_returns_git_version_info(self) -> None:
        """get_git_version_info should return GitVersionInfo instance."""
        info = get_git_version_info()
        assert isinstance(info, GitVersionInfo)

    def test_prefers_embedded_when_no_repo_path(self) -> None:
        """Should use embedded info when available and no repo_path."""
        embedded = GitVersionInfo(
            version="v1.0.0",
            sha_short="aaa1111",
            sha_full="a" * 40,
            full_status="embedded",
        )
        with patch("lib.version._try_embedded", return_value=embedded):
            result = get_git_version_info()
        assert result is embedded

    def test_falls_back_to_git_when_no_embedded(self) -> None:
        """Should use git when embedded module is not available."""
        with patch("lib.version._try_embedded", return_value=None):
            info = get_git_version_info()
        assert isinstance(info, GitVersionInfo)
        assert "=== HEAD COMMIT ===" in info.full_status


class TestGetGitVersionInfoLive:
    """Tests for _get_git_version_info_live function."""

    def test_returns_git_version_info(self) -> None:
        """_get_git_version_info_live should return GitVersionInfo."""
        info = _get_git_version_info_live()
        assert isinstance(info, GitVersionInfo)

    def test_sha_short_is_hex(self) -> None:
        """sha_short should be a valid hex string."""
        info = _get_git_version_info_live()
        if info.sha_short != "unknown":
            assert all(c in "0123456789abcdef" for c in info.sha_short.lower())

    def test_sha_full_is_40_chars(self) -> None:
        """sha_full should be a 40-character hex string."""
        info = _get_git_version_info_live()
        if info.sha_full != "unknown":
            assert len(info.sha_full) == 40
            assert all(c in "0123456789abcdef" for c in info.sha_full.lower())

    def test_full_status_contains_sections(self) -> None:
        """full_status should contain HEAD and WORKING TREE sections."""
        info = _get_git_version_info_live()
        assert "=== HEAD COMMIT ===" in info.full_status
        assert "=== WORKING TREE STATUS ===" in info.full_status

    def test_version_is_string(self) -> None:
        """Version should be a string (possibly empty)."""
        info = _get_git_version_info_live()
        assert isinstance(info.version, str)

    def test_handles_git_command_failure_for_short_sha(self) -> None:
        """Should return 'unknown' for sha_short when git command fails."""
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(1, "git")
            info = _get_git_version_info_live()
        assert info.sha_short == "unknown"

    def test_handles_git_command_failure_for_full_sha(self) -> None:
        """Should return 'unknown' for sha_full when git command fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 3:  # Third call is for full SHA
                raise subprocess.CalledProcessError(1, "git")
            result = MagicMock()
            result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.sha_full == "unknown"

    def test_handles_git_show_failure(self) -> None:
        """Should include error message when git show fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 4:  # Fourth call is for git show
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: not a git repo"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 4 else ""
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert "Error:" in info.full_status

    def test_handles_git_status_failure(self) -> None:
        """Should include error message when git status fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 5:  # Fifth call is for git status
                err = subprocess.CalledProcessError(1, "git")
                err.stderr = "fatal: error"
                raise err
            result = MagicMock()
            result.stdout = "abc1234\n" if call_count < 5 else "HEAD info"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert "Error:" in info.full_status

    def test_version_from_git_describe(self) -> None:
        """Version should come from git describe when tags exist."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:  # First call is git describe
                result.stdout = "v0.7.0\n"
            else:
                result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == "v0.7.0"
        assert "=== VERSION ===" in info.full_status
        assert "v0.7.0" in info.full_status

    def test_version_empty_when_no_tags(self) -> None:
        """Version should be empty when git describe fails."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            if call_count == 1:  # First call is git describe
                raise subprocess.CalledProcessError(128, "git")
            result = MagicMock()
            result.stdout = "abc1234\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == ""
        assert "=== VERSION ===" not in info.full_status

    def test_full_status_includes_version_section_when_tagged(self) -> None:
        """full_status should include VERSION section when tag exists."""
        call_count = 0

        def side_effect(*args, **kwargs) -> MagicMock:
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:  # git describe
                result.stdout = "v0.7.0-3-gabc1234\n"
            elif call_count == 2:  # rev-parse --short
                result.stdout = "abc1234\n"
            else:
                result.stdout = "mock output\n"
            return result

        with patch("subprocess.run", side_effect=side_effect):
            info = _get_git_version_info_live()
        assert info.version == "v0.7.0-3-gabc1234"
        assert "=== VERSION ===\nv0.7.0-3-gabc1234 (abc1234)" in (
            info.full_status
        )


# ── InstallSource ──────────────────────────────────────────────────


class TestInstallSource:
    """Tests for InstallSource dataclass."""

    def test_pypi_defaults(self) -> None:
        """PyPI source has no URL or VCS fields."""
        src = InstallSource(kind="pypi")
        assert src.kind == "pypi"
        assert src.url is None
        assert src.vcs_commit is None
        assert src.vcs_requested_revision is None

    def test_vcs_fields(self) -> None:
        """VCS source stores URL and commit info."""
        src = InstallSource(
            kind="vcs",
            url="https://github.com/airutorg/airut.git",
            vcs_commit="abc123",
            vcs_requested_revision="main",
        )
        assert src.kind == "vcs"
        assert src.url == "https://github.com/airutorg/airut.git"
        assert src.vcs_commit == "abc123"
        assert src.vcs_requested_revision == "main"


# ── get_install_source ─────────────────────────────────────────────


def _mock_dist(direct_url_json: str | None) -> MagicMock:
    """Create a mock distribution with optional direct_url.json."""
    mock = MagicMock()
    mock.read_text.return_value = direct_url_json
    return mock


class TestGetInstallSource:
    """Tests for get_install_source function."""

    @patch("lib.version.distribution")
    def test_pypi_install(self, mock_distribution: MagicMock) -> None:
        """Returns 'pypi' when no direct_url.json exists."""
        mock_distribution.return_value = _mock_dist(None)
        src = get_install_source()
        assert src.kind == "pypi"
        assert src.url is None

    @patch("lib.version.distribution")
    def test_vcs_install(self, mock_distribution: MagicMock) -> None:
        """Returns 'vcs' with commit info for git+https installs."""
        direct_url = json.dumps(
            {
                "url": "https://github.com/airutorg/airut.git",
                "vcs_info": {
                    "vcs": "git",
                    "requested_revision": "main",
                    "commit_id": "abc123def456",
                },
            }
        )
        mock_distribution.return_value = _mock_dist(direct_url)
        src = get_install_source()
        assert src.kind == "vcs"
        assert src.url == "https://github.com/airutorg/airut.git"
        assert src.vcs_commit == "abc123def456"
        assert src.vcs_requested_revision == "main"

    @patch("lib.version.distribution")
    def test_editable_install(self, mock_distribution: MagicMock) -> None:
        """Returns 'editable' for pip install -e."""
        direct_url = json.dumps(
            {
                "url": "file:///home/user/airut",
                "dir_info": {"editable": True},
            }
        )
        mock_distribution.return_value = _mock_dist(direct_url)
        src = get_install_source()
        assert src.kind == "editable"
        assert src.url == "file:///home/user/airut"

    @patch("lib.version.distribution")
    def test_local_dir_install(self, mock_distribution: MagicMock) -> None:
        """Returns 'local-dir' for non-editable local install."""
        direct_url = json.dumps(
            {
                "url": "file:///home/user/airut",
                "dir_info": {},
            }
        )
        mock_distribution.return_value = _mock_dist(direct_url)
        src = get_install_source()
        assert src.kind == "local-dir"

    @patch("lib.version.distribution")
    def test_archive_install(self, mock_distribution: MagicMock) -> None:
        """Returns 'archive' for direct URL archive installs."""
        direct_url = json.dumps(
            {
                "url": "https://example.com/airut-0.8.0.tar.gz",
                "archive_info": {"hashes": {"sha256": "abc"}},
            }
        )
        mock_distribution.return_value = _mock_dist(direct_url)
        src = get_install_source()
        assert src.kind == "archive"
        assert src.url == "https://example.com/airut-0.8.0.tar.gz"

    @patch("lib.version.distribution")
    def test_package_not_found(self, mock_distribution: MagicMock) -> None:
        """Returns 'unknown' when package is not installed."""
        mock_distribution.side_effect = PackageNotFoundError("airut")
        src = get_install_source()
        assert src.kind == "unknown"

    @patch("lib.version.distribution")
    def test_malformed_json(self, mock_distribution: MagicMock) -> None:
        """Returns 'unknown' for malformed direct_url.json."""
        mock_distribution.return_value = _mock_dist("{invalid json")
        src = get_install_source()
        assert src.kind == "unknown"

    @patch("lib.version.distribution")
    def test_unknown_direct_url_structure(
        self, mock_distribution: MagicMock
    ) -> None:
        """Returns 'unknown' for unrecognized direct_url.json fields."""
        direct_url = json.dumps({"url": "https://x.com", "custom": True})
        mock_distribution.return_value = _mock_dist(direct_url)
        src = get_install_source()
        assert src.kind == "unknown"


# ── UpstreamVersion ────────────────────────────────────────────────


class TestUpstreamVersion:
    """Tests for UpstreamVersion dataclass."""

    def test_update_available(self) -> None:
        """Correctly stores update availability flag."""
        uv = UpstreamVersion(
            source="pypi",
            latest="0.9.0",
            current="0.8.0",
            update_available=True,
        )
        assert uv.update_available is True
        assert uv.source == "pypi"

    def test_no_update(self) -> None:
        """No update when versions match."""
        uv = UpstreamVersion(
            source="pypi",
            latest="0.8.0",
            current="0.8.0",
            update_available=False,
        )
        assert uv.update_available is False


# ── _check_pypi ────────────────────────────────────────────────────


def _make_vi(**kwargs: object) -> GitVersionInfo:
    """Create a GitVersionInfo with defaults."""
    defaults: dict[str, object] = {
        "version": "v0.8.0",
        "sha_short": "abc1234",
        "sha_full": "a" * 40,
        "full_status": "",
    }
    defaults.update(kwargs)
    return GitVersionInfo(**defaults)  # type: ignore[arg-type]


class TestCheckPyPI:
    """Tests for _check_pypi function."""

    @patch("lib.version.urllib.request.urlopen")
    def test_update_available(self, mock_urlopen: MagicMock) -> None:
        """Detects when PyPI has a newer version."""
        body = json.dumps({"info": {"version": "0.9.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.source == "pypi"
        assert result.latest == "0.9.0"
        assert result.current == "0.8.0"
        assert result.update_available is True

    @patch("lib.version.urllib.request.urlopen")
    def test_up_to_date(self, mock_urlopen: MagicMock) -> None:
        """No update when versions match."""
        body = json.dumps({"info": {"version": "0.8.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is False

    @patch("lib.version.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        """Returns None on network failure."""
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        result = _check_pypi(_make_vi())
        assert result is None

    @patch("lib.version.urllib.request.urlopen")
    def test_empty_version(self, mock_urlopen: MagicMock) -> None:
        """Returns None when PyPI returns empty version."""
        body = json.dumps({"info": {"version": ""}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_pypi(_make_vi())
        assert result is None

    @patch("lib.version.urllib.request.urlopen")
    def test_malformed_response(self, mock_urlopen: MagicMock) -> None:
        """Returns None on malformed JSON response."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"not json"
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_pypi(_make_vi())
        assert result is None


# ── _check_github ──────────────────────────────────────────────────


class TestCheckGitHub:
    """Tests for _check_github function."""

    @patch("lib.version.urllib.request.urlopen")
    def test_update_available(self, mock_urlopen: MagicMock) -> None:
        """Detects when GitHub has a newer commit."""
        new_sha = "b" * 40
        body = json.dumps({"commit": {"sha": new_sha}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_github(_make_vi(sha_full="a" * 40))
        assert result is not None
        assert result.source == "github"
        assert result.latest == new_sha
        assert result.current == "a" * 40
        assert result.update_available is True

    @patch("lib.version.urllib.request.urlopen")
    def test_up_to_date(self, mock_urlopen: MagicMock) -> None:
        """No update when commit SHAs match."""
        sha = "a" * 40
        body = json.dumps({"commit": {"sha": sha}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_github(_make_vi(sha_full=sha))
        assert result is not None
        assert result.update_available is False

    @patch("lib.version.urllib.request.urlopen")
    def test_network_error(self, mock_urlopen: MagicMock) -> None:
        """Returns None on network failure."""
        mock_urlopen.side_effect = OSError("connection refused")
        result = _check_github(_make_vi())
        assert result is None

    @patch("lib.version.urllib.request.urlopen")
    def test_empty_sha(self, mock_urlopen: MagicMock) -> None:
        """Returns None when GitHub returns empty SHA."""
        body = json.dumps({"commit": {"sha": ""}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = _check_github(_make_vi())
        assert result is None

    @patch("lib.version.urllib.request.urlopen")
    def test_custom_branch(self, mock_urlopen: MagicMock) -> None:
        """Uses the specified branch in the API URL."""
        body = json.dumps({"commit": {"sha": "b" * 40}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        _check_github(_make_vi(), branch="develop")
        call_args = mock_urlopen.call_args
        req = call_args[0][0]
        assert "branches/develop" in req.full_url


# ── check_upstream_version ─────────────────────────────────────────


class TestCheckUpstreamVersion:
    """Tests for check_upstream_version routing."""

    @patch("lib.version._check_pypi")
    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(kind="pypi"),
    )
    def test_routes_to_pypi(
        self, _src: MagicMock, mock_pypi: MagicMock
    ) -> None:
        """Calls _check_pypi for PyPI installs."""
        mock_pypi.return_value = UpstreamVersion(
            source="pypi",
            latest="0.9.0",
            current="0.8.0",
            update_available=True,
        )
        result = check_upstream_version(_make_vi())
        assert result is not None
        assert result.source == "pypi"
        mock_pypi.assert_called_once()

    @patch("lib.version._check_github")
    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(
            kind="vcs",
            url="https://github.com/airutorg/airut.git",
            vcs_commit="abc123",
            vcs_requested_revision="develop",
        ),
    )
    def test_routes_to_github(
        self, _src: MagicMock, mock_gh: MagicMock
    ) -> None:
        """Calls _check_github for VCS installs with correct branch."""
        mock_gh.return_value = UpstreamVersion(
            source="github",
            latest="b" * 40,
            current="a" * 40,
            update_available=True,
        )
        result = check_upstream_version(_make_vi())
        assert result is not None
        assert result.source == "github"
        mock_gh.assert_called_once()
        # Verify branch was passed from vcs_requested_revision.
        _, kwargs = mock_gh.call_args
        assert kwargs["branch"] == "develop"

    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(
            kind="vcs",
            url="https://github.com/airutorg/airut.git",
            vcs_commit="abc123",
        ),
    )
    @patch("lib.version._check_github")
    def test_vcs_defaults_to_main(
        self, mock_gh: MagicMock, _src: MagicMock
    ) -> None:
        """Uses 'main' branch when vcs_requested_revision is None."""
        mock_gh.return_value = None
        check_upstream_version(_make_vi())
        _, kwargs = mock_gh.call_args
        assert kwargs["branch"] == "main"

    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(kind="editable"),
    )
    def test_returns_none_for_editable(self, _src: MagicMock) -> None:
        """Returns None for editable installs."""
        result = check_upstream_version(_make_vi())
        assert result is None

    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(kind="local-dir"),
    )
    def test_returns_none_for_local_dir(self, _src: MagicMock) -> None:
        """Returns None for local directory installs."""
        result = check_upstream_version(_make_vi())
        assert result is None

    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(kind="unknown"),
    )
    def test_returns_none_for_unknown(self, _src: MagicMock) -> None:
        """Returns None for unknown install sources."""
        result = check_upstream_version(_make_vi())
        assert result is None

    @patch(
        "lib.version.get_install_source",
        return_value=InstallSource(kind="archive"),
    )
    def test_returns_none_for_archive(self, _src: MagicMock) -> None:
        """Returns None for archive installs."""
        result = check_upstream_version(_make_vi())
        assert result is None


# ── _is_older ──────────────────────────────────────────────────────


class TestIsOlder:
    """Tests for _is_older helper."""

    def test_older_version(self) -> None:
        """Returns True when candidate is older."""
        assert _is_older("0.7.0", "0.8.0") is True

    def test_newer_version(self) -> None:
        """Returns False when candidate is newer."""
        assert _is_older("0.9.0", "0.8.0") is False

    def test_equal_version(self) -> None:
        """Returns False when versions are equal."""
        assert _is_older("0.8.0", "0.8.0") is False

    def test_invalid_candidate(self) -> None:
        """Returns False when candidate is unparseable."""
        assert _is_older("not-a-version", "0.8.0") is False

    def test_invalid_reference(self) -> None:
        """Returns False when reference is unparseable."""
        assert _is_older("0.8.0", "not-a-version") is False

    def test_pre_release(self) -> None:
        """Handles pre-release versions correctly."""
        assert _is_older("0.8.0a1", "0.8.0") is True
        assert _is_older("0.8.0", "0.8.0a1") is False


# ── URL helpers ───────────────────────────────────────────────────


class TestIsExactVersionTag:
    """Tests for is_exact_version_tag helper."""

    def test_exact_tag_with_v(self) -> None:
        """Exact tag like v0.9.0 returns True."""
        assert is_exact_version_tag("v0.9.0") is True

    def test_exact_tag_without_v(self) -> None:
        """Exact tag like 0.9.0 returns True."""
        assert is_exact_version_tag("0.9.0") is True

    def test_git_describe_with_commits(self) -> None:
        """Git describe output with commits after tag returns False."""
        assert is_exact_version_tag("v0.9.0-4-gecb890e") is False

    def test_pre_release(self) -> None:
        """Pre-release version like v0.9.0a1 returns True."""
        assert is_exact_version_tag("v0.9.0a1") is True

    def test_empty_string(self) -> None:
        """Empty string returns False."""
        assert is_exact_version_tag("") is False

    def test_garbage(self) -> None:
        """Non-version string returns False."""
        assert is_exact_version_tag("not-a-version") is False


class TestGitHubReleaseUrl:
    """Tests for github_release_url helper."""

    def test_with_v_prefix(self) -> None:
        """Version with v prefix is used as-is."""
        assert github_release_url("v0.9.0") == (
            "https://github.com/airutorg/airut/releases/tag/v0.9.0"
        )

    def test_without_v_prefix(self) -> None:
        """Version without v prefix gets one added."""
        assert github_release_url("0.9.0") == (
            "https://github.com/airutorg/airut/releases/tag/v0.9.0"
        )


class TestGitHubCommitUrl:
    """Tests for github_commit_url helper."""

    def test_full_sha(self) -> None:
        """Constructs URL for full 40-character SHA."""
        sha = "a" * 40
        assert github_commit_url(sha) == (
            f"https://github.com/airutorg/airut/commit/{sha}"
        )

    def test_short_sha(self) -> None:
        """Constructs URL for short SHA."""
        assert github_commit_url("abc1234") == (
            "https://github.com/airutorg/airut/commit/abc1234"
        )


# ── _fetch_pypi_version ───────────────────────────────────────────


class TestFetchPyPIVersion:
    """Tests for _fetch_pypi_version helper."""

    @patch("lib.version.urllib.request.urlopen")
    def test_returns_version(self, mock_urlopen: MagicMock) -> None:
        """Returns version string from PyPI response."""
        body = json.dumps({"info": {"version": "0.9.0"}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        assert _fetch_pypi_version() == "0.9.0"

    @patch("lib.version.urllib.request.urlopen")
    def test_returns_none_on_network_error(
        self, mock_urlopen: MagicMock
    ) -> None:
        """Returns None on network failure."""
        mock_urlopen.side_effect = urllib.error.URLError("timeout")
        assert _fetch_pypi_version() is None

    @patch("lib.version.urllib.request.urlopen")
    def test_returns_none_on_empty_version(
        self, mock_urlopen: MagicMock
    ) -> None:
        """Returns None when PyPI returns empty version string."""
        body = json.dumps({"info": {"version": ""}}).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = body
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        assert _fetch_pypi_version() is None


# ── _check_pypi retry / downgrade prevention ──────────────────────


class TestCheckPyPIRetryAndDowngrade:
    """Tests for _check_pypi retry and downgrade prevention."""

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_retries_when_upstream_older_than_installed(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Retries PyPI fetch when first result is older than installed."""
        # First call returns stale (older) version, second returns fresh.
        mock_fetch.side_effect = ["0.7.0", "0.8.0"]
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is False
        assert result.latest == "0.8.0"
        assert mock_fetch.call_count == 2
        mock_sleep.assert_called_once()

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_retry_succeeds_with_newer_version(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Retry returns newer version after stale first response."""
        mock_fetch.side_effect = ["0.7.0", "0.9.0"]
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is True
        assert result.latest == "0.9.0"
        assert mock_fetch.call_count == 2

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_no_retry_when_upstream_newer(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Does not retry when upstream is newer than installed."""
        mock_fetch.return_value = "0.9.0"
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is True
        assert mock_fetch.call_count == 1
        mock_sleep.assert_not_called()

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_no_retry_when_versions_equal(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Does not retry when versions match."""
        mock_fetch.return_value = "0.8.0"
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is False
        assert mock_fetch.call_count == 1
        mock_sleep.assert_not_called()

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_downgrade_never_reported(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Never reports update_available when upstream is older."""
        # Both attempts return old version.
        mock_fetch.side_effect = ["0.7.0", "0.7.0"]
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        assert result.update_available is False
        assert result.latest == "0.7.0"
        assert result.current == "0.8.0"

    @patch("lib.version.time.sleep")
    @patch("lib.version._fetch_pypi_version")
    def test_retry_returns_none_keeps_first_result(
        self, mock_fetch: MagicMock, mock_sleep: MagicMock
    ) -> None:
        """Uses first result when retry fetch fails."""
        mock_fetch.side_effect = ["0.7.0", None]
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is not None
        # Still older → no update reported.
        assert result.update_available is False
        assert result.latest == "0.7.0"

    @patch("lib.version._fetch_pypi_version")
    def test_first_fetch_fails(self, mock_fetch: MagicMock) -> None:
        """Returns None when first fetch fails."""
        mock_fetch.return_value = None
        result = _check_pypi(_make_vi(version="v0.8.0"))
        assert result is None
