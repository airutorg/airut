# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/update_vendor.py."""

from pathlib import Path
from unittest.mock import patch

import pytest
import scripts.update_vendor as update_vendor


class TestParseVersionFile:
    """Tests for parse_version_file."""

    def test_parses_valid_file(self, tmp_path: Path) -> None:
        """Parses a valid VERSION file."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")
        result = update_vendor.parse_version_file(version_file)
        assert result == {"htmx": "2.0.8", "htmx-ext-sse": "2.2.4"}

    def test_skips_blank_lines_and_comments(self, tmp_path: Path) -> None:
        """Skips blank lines and comments."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("# comment\n\nhtmx 2.0.8\n")
        result = update_vendor.parse_version_file(version_file)
        assert result == {"htmx": "2.0.8"}

    def test_handles_missing_file(self, tmp_path: Path) -> None:
        """Returns empty dict if file doesn't exist."""
        result = update_vendor.parse_version_file(tmp_path / "nonexistent")
        assert result == {}


class TestWriteVersionFile:
    """Tests for write_version_file."""

    def test_writes_versions(self, tmp_path: Path) -> None:
        """Writes versions to file."""
        version_file = tmp_path / "VERSION"
        update_vendor.write_version_file(
            version_file, {"htmx": "2.0.9", "htmx-ext-sse": "2.2.5"}
        )
        content = version_file.read_text()
        assert "htmx 2.0.9\n" in content
        assert "htmx-ext-sse 2.2.5\n" in content


class TestGetLatestVersion:
    """Tests for get_latest_version."""

    def test_returns_version_without_v_prefix(self) -> None:
        """Strips 'v' prefix from tag name."""
        with patch(
            "scripts.update_vendor.urlopen",
        ) as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = b'{"tag_name": "v2.0.9"}'
            result = update_vendor.get_latest_version("bigskysoftware", "htmx")

        assert result == "2.0.9"

    def test_raises_on_non_dict_response(self) -> None:
        """Raises ValueError for unexpected response."""
        with (
            patch("scripts.update_vendor.urlopen") as mock_urlopen,
            pytest.raises(ValueError, match="Unexpected response"),
        ):
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = b"[]"
            update_vendor.get_latest_version("bigskysoftware", "htmx")


class TestDownloadFile:
    """Tests for download_file."""

    def test_returns_content(self) -> None:
        """Downloads and returns file content."""
        with patch("scripts.update_vendor.urlopen") as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = b"file content"
            result = update_vendor.download_file("https://example.com/f")

        assert result == b"file content"


class TestUpdatePackage:
    """Tests for update_package."""

    def test_skips_when_up_to_date(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports no update needed when versions match."""
        versions = {"htmx": "2.0.8"}
        info = {
            "npm_package": "htmx.org",
            "github_owner": "bigskysoftware",
            "github_repo": "htmx",
            "file": "htmx.min.js",
            "unpkg_path": "dist/htmx.min.js",
        }
        with patch(
            "scripts.update_vendor.get_latest_version", return_value="2.0.8"
        ):
            current, latest, updated = update_vendor.update_package(
                "htmx", info, versions, check_only=False
            )

        assert current == "2.0.8"
        assert latest == "2.0.8"
        assert not updated
        captured = capsys.readouterr()
        assert "up to date" in captured.out

    def test_check_only_does_not_download(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """In check mode, reports update but doesn't download."""
        versions = {"htmx": "2.0.7"}
        info = {
            "npm_package": "htmx.org",
            "github_owner": "bigskysoftware",
            "github_repo": "htmx",
            "file": "htmx.min.js",
            "unpkg_path": "dist/htmx.min.js",
        }
        with patch(
            "scripts.update_vendor.get_latest_version", return_value="2.0.8"
        ):
            current, latest, updated = update_vendor.update_package(
                "htmx", info, versions, check_only=True
            )

        assert current == "2.0.7"
        assert latest == "2.0.8"
        assert not updated
        assert versions["htmx"] == "2.0.7"  # not modified

    def test_downloads_and_updates_version(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Downloads new version and updates version dict."""
        versions = {"htmx": "2.0.7"}
        info = {
            "npm_package": "htmx.org",
            "github_owner": "bigskysoftware",
            "github_repo": "htmx",
            "file": "htmx.min.js",
            "unpkg_path": "dist/htmx.min.js",
        }
        with (
            patch(
                "scripts.update_vendor.get_latest_version", return_value="2.0.8"
            ),
            patch(
                "scripts.update_vendor.download_file",
                return_value=b"new js content",
            ),
            patch.object(update_vendor, "VENDOR_DIR", tmp_path),
        ):
            current, latest, updated = update_vendor.update_package(
                "htmx", info, versions, check_only=False
            )

        assert current == "2.0.7"
        assert latest == "2.0.8"
        assert updated
        assert versions["htmx"] == "2.0.8"
        assert (tmp_path / "htmx.min.js").read_bytes() == b"new js content"

    def test_handles_empty_latest(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports error when latest version is empty."""
        versions = {"htmx": "2.0.8"}
        info = {
            "npm_package": "htmx.org",
            "github_owner": "bigskysoftware",
            "github_repo": "htmx",
            "file": "htmx.min.js",
            "unpkg_path": "dist/htmx.min.js",
        }
        with patch("scripts.update_vendor.get_latest_version", return_value=""):
            current, latest, updated = update_vendor.update_package(
                "htmx", info, versions, check_only=False
            )

        assert not updated
        captured = capsys.readouterr()
        assert "Could not determine" in captured.out


class TestMain:
    """Tests for main function."""

    def test_succeeds_when_up_to_date(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 0 when everything is up to date."""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        version_file = vendor_dir / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")

        def mock_latest(owner: str, repo: str) -> str:
            if repo == "htmx":
                return "2.0.8"
            return "2.2.4"

        with (
            patch.object(update_vendor, "VENDOR_DIR", vendor_dir),
            patch.object(update_vendor, "VERSION_FILE", version_file),
            patch(
                "scripts.update_vendor.get_latest_version",
                side_effect=mock_latest,
            ),
            patch("scripts.update_vendor.download_file"),
            patch("sys.argv", ["scripts.update_vendor.py"]),
        ):
            result = update_vendor.main()

        assert result == 0
        captured = capsys.readouterr()
        assert "up to date" in captured.out

    def test_fails_when_vendor_dir_missing(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when vendor directory doesn't exist."""
        with (
            patch.object(
                update_vendor,
                "VENDOR_DIR",
                tmp_path / "nonexistent",
            ),
            patch("sys.argv", ["scripts.update_vendor.py"]),
        ):
            result = update_vendor.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_fails_on_download_error(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when a download fails."""
        from urllib.error import URLError

        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        version_file = vendor_dir / "VERSION"
        version_file.write_text("htmx 2.0.7\nhtmx-ext-sse 2.2.4\n")

        def mock_latest(owner: str, repo: str) -> str:
            return "2.0.8"

        with (
            patch.object(update_vendor, "VENDOR_DIR", vendor_dir),
            patch.object(update_vendor, "VERSION_FILE", version_file),
            patch(
                "scripts.update_vendor.get_latest_version",
                side_effect=mock_latest,
            ),
            patch(
                "scripts.update_vendor.download_file",
                side_effect=URLError("timeout"),
            ),
            patch("sys.argv", ["scripts.update_vendor.py"]),
        ):
            result = update_vendor.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_check_mode_no_download(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Check mode reports updates without downloading."""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        version_file = vendor_dir / "VERSION"
        version_file.write_text("htmx 2.0.7\nhtmx-ext-sse 2.2.4\n")

        with (
            patch.object(update_vendor, "VENDOR_DIR", vendor_dir),
            patch.object(update_vendor, "VERSION_FILE", version_file),
            patch(
                "scripts.update_vendor.get_latest_version",
                return_value="2.0.8",
            ),
            patch("sys.argv", ["scripts.update_vendor.py", "--check"]),
        ):
            result = update_vendor.main()

        assert result == 0
        # VERSION file should not be modified
        assert "2.0.7" in version_file.read_text()

    def test_updates_and_writes_version_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Downloads updates and writes VERSION file on success."""
        vendor_dir = tmp_path / "vendor"
        vendor_dir.mkdir()
        version_file = vendor_dir / "VERSION"
        version_file.write_text("htmx 2.0.7\nhtmx-ext-sse 2.2.3\n")

        with (
            patch.object(update_vendor, "VENDOR_DIR", vendor_dir),
            patch.object(update_vendor, "VERSION_FILE", version_file),
            patch(
                "scripts.update_vendor.get_latest_version",
                return_value="2.0.8",
            ),
            patch(
                "scripts.update_vendor.download_file",
                return_value=b"new content",
            ),
            patch("sys.argv", ["scripts.update_vendor.py"]),
        ):
            result = update_vendor.main()

        assert result == 0
        captured = capsys.readouterr()
        assert "Updated" in captured.out
        # VERSION file should be updated
        content = version_file.read_text()
        assert "2.0.8" in content
