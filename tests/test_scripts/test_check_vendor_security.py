# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_vendor_security.py."""

from pathlib import Path
from unittest.mock import patch

import pytest
import scripts.check_vendor_security as check_vendor_security


class TestParseVersionFile:
    """Tests for parse_version_file."""

    def test_parses_valid_file(self, tmp_path: Path) -> None:
        """Parses a valid VERSION file."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")
        result = check_vendor_security.parse_version_file(version_file)
        assert result == {"htmx": "2.0.8", "htmx-ext-sse": "2.2.4"}

    def test_skips_blank_lines_and_comments(self, tmp_path: Path) -> None:
        """Skips blank lines and comments."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("# comment\n\nhtmx 2.0.8\n")
        result = check_vendor_security.parse_version_file(version_file)
        assert result == {"htmx": "2.0.8"}

    def test_empty_file(self, tmp_path: Path) -> None:
        """Returns empty dict for empty file."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("")
        result = check_vendor_security.parse_version_file(version_file)
        assert result == {}

    def test_malformed_lines_ignored(self, tmp_path: Path) -> None:
        """Lines without exactly two parts are ignored."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nbadline\na b c\n")
        result = check_vendor_security.parse_version_file(version_file)
        assert result == {"htmx": "2.0.8"}


class TestParseVersion:
    """Tests for _parse_version."""

    def test_parses_semver(self) -> None:
        """Parses a standard semver string."""
        assert check_vendor_security._parse_version("2.0.8") == (2, 0, 8)

    def test_parses_two_part(self) -> None:
        """Parses a two-part version."""
        assert check_vendor_security._parse_version("2.0") == (2, 0)

    def test_returns_none_for_invalid(self) -> None:
        """Returns None for non-numeric version."""
        assert check_vendor_security._parse_version("abc") is None


class TestVersionInRange:
    """Tests for _version_in_range."""

    def test_simple_less_than(self) -> None:
        """Matches simple less-than range."""
        assert check_vendor_security._version_in_range("2.0.4", "< 2.0.5")
        assert not check_vendor_security._version_in_range("2.0.5", "< 2.0.5")

    def test_compound_range(self) -> None:
        """Matches compound range with >= and <."""
        assert check_vendor_security._version_in_range(
            "2.0.4", ">= 2.0.0, < 2.0.5"
        )
        assert not check_vendor_security._version_in_range(
            "1.9.0", ">= 2.0.0, < 2.0.5"
        )
        assert not check_vendor_security._version_in_range(
            "2.0.5", ">= 2.0.0, < 2.0.5"
        )

    def test_empty_range(self) -> None:
        """Returns False for empty range."""
        assert not check_vendor_security._version_in_range("2.0.8", "")

    def test_gte_only(self) -> None:
        """Matches >= range."""
        assert check_vendor_security._version_in_range("2.0.8", ">= 2.0.0")
        assert not check_vendor_security._version_in_range("1.9.9", ">= 2.0.0")

    def test_trailing_comma_in_range(self) -> None:
        """Handles trailing comma creating empty condition."""
        assert check_vendor_security._version_in_range("2.0.4", "< 2.0.5,")

    def test_invalid_version(self) -> None:
        """Returns False for non-parseable version."""
        assert not check_vendor_security._version_in_range("abc", "< 2.0.5")


class TestCheckCondition:
    """Tests for _check_condition."""

    def test_greater_than(self) -> None:
        """Tests > operator."""
        assert check_vendor_security._check_condition((2, 0, 8), "> 2.0.7")
        assert not check_vendor_security._check_condition((2, 0, 8), "> 2.0.8")

    def test_less_than_or_equal(self) -> None:
        """Tests <= operator."""
        assert check_vendor_security._check_condition((2, 0, 8), "<= 2.0.8")
        assert not check_vendor_security._check_condition((2, 0, 9), "<= 2.0.8")

    def test_equal(self) -> None:
        """Tests = operator."""
        assert check_vendor_security._check_condition((2, 0, 8), "= 2.0.8")
        assert not check_vendor_security._check_condition((2, 0, 9), "= 2.0.8")

    def test_not_equal(self) -> None:
        """Tests != operator."""
        assert check_vendor_security._check_condition((2, 0, 9), "!= 2.0.8")
        assert not check_vendor_security._check_condition((2, 0, 8), "!= 2.0.8")

    def test_invalid_target(self) -> None:
        """Returns False for invalid target version."""
        assert not check_vendor_security._check_condition((2, 0, 8), "> abc")

    def test_no_operator_match(self) -> None:
        """Returns False when no operator matches."""
        assert not check_vendor_security._check_condition((2, 0, 8), "~2.0.8")


class TestCheckAdvisories:
    """Tests for check_advisories."""

    def test_returns_matching_advisories(self) -> None:
        """Returns advisories that match the vendored version."""
        api_response = [
            {
                "ghsa_id": "GHSA-test-1234-abcd",
                "severity": "high",
                "summary": "XSS in htmx",
                "html_url": "https://github.com/advisories/GHSA-test-1234-abcd",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "htmx.org",
                            "ecosystem": "npm",
                        },
                        "vulnerable_version_range": ">= 2.0.0, < 2.0.9",
                    }
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert len(result) == 1
        assert result[0]["ghsa_id"] == "GHSA-test-1234-abcd"
        assert result[0]["severity"] == "high"

    def test_skips_non_matching_version(self) -> None:
        """Skips advisories that don't match the vendored version."""
        api_response = [
            {
                "ghsa_id": "GHSA-old-0000-0000",
                "severity": "medium",
                "summary": "Old issue",
                "html_url": "",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "htmx.org",
                            "ecosystem": "npm",
                        },
                        "vulnerable_version_range": "< 1.0.0",
                    }
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_different_package(self) -> None:
        """Skips advisories for a different package."""
        api_response = [
            {
                "ghsa_id": "GHSA-test-0000-0000",
                "severity": "high",
                "summary": "Issue",
                "html_url": "",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "other-package",
                            "ecosystem": "npm",
                        },
                        "vulnerable_version_range": ">= 2.0.0, < 3.0.0",
                    }
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_different_ecosystem(self) -> None:
        """Skips advisories for a different ecosystem."""
        api_response = [
            {
                "ghsa_id": "GHSA-test-0000-0000",
                "severity": "high",
                "summary": "Issue",
                "html_url": "",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "htmx.org",
                            "ecosystem": "pip",
                        },
                        "vulnerable_version_range": ">= 2.0.0, < 3.0.0",
                    }
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_handles_non_list_response(self) -> None:
        """Returns empty list for unexpected API response."""
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value={"error": True},
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_non_dict_items(self) -> None:
        """Skips non-dict items in advisory list."""
        api_response = ["not a dict", 42, None]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_advisory_without_vulnerabilities_list(self) -> None:
        """Skips advisories where vulnerabilities is not a list."""
        api_response = [
            {
                "ghsa_id": "GHSA-test",
                "vulnerabilities": "not a list",
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_non_dict_vulnerability(self) -> None:
        """Skips non-dict items in vulnerabilities list."""
        api_response = [
            {
                "ghsa_id": "GHSA-test",
                "vulnerabilities": ["not a dict"],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_vulnerability_with_non_dict_package(self) -> None:
        """Skips vulnerabilities where package is not a dict."""
        api_response = [
            {
                "ghsa_id": "GHSA-test",
                "vulnerabilities": [
                    {"package": "not a dict"},
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []

    def test_skips_non_string_version_range(self) -> None:
        """Skips vulnerabilities with non-string version range."""
        api_response = [
            {
                "ghsa_id": "GHSA-test",
                "vulnerabilities": [
                    {
                        "package": {
                            "name": "htmx.org",
                            "ecosystem": "npm",
                        },
                        "vulnerable_version_range": 42,
                    }
                ],
            }
        ]
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=api_response,
        ):
            result = check_vendor_security.check_advisories("htmx.org", "2.0.8")

        assert result == []


class TestGithubGet:
    """Tests for _github_get."""

    def test_returns_parsed_json(self) -> None:
        """Fetches and parses JSON from GitHub API."""
        with patch("scripts.check_vendor_security.urlopen") as mock_urlopen:
            mock_response = mock_urlopen.return_value.__enter__.return_value
            mock_response.read.return_value = b'{"key": "value"}'
            result = check_vendor_security._github_get(
                "https://api.github.com/test"
            )

        assert result == {"key": "value"}


class TestGetLatestVersion:
    """Tests for get_latest_version."""

    def test_returns_version_without_v_prefix(self) -> None:
        """Strips 'v' prefix from tag name."""
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value={"tag_name": "v2.0.9"},
        ):
            result = check_vendor_security.get_latest_version(
                "bigskysoftware", "htmx"
            )

        assert result == "2.0.9"

    def test_returns_version_without_prefix(self) -> None:
        """Handles tags without 'v' prefix."""
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value={"tag_name": "2.2.5"},
        ):
            result = check_vendor_security.get_latest_version(
                "bigskysoftware", "htmx-ext-sse"
            )

        assert result == "2.2.5"

    def test_returns_none_on_url_error(self) -> None:
        """Returns None when the API request fails."""
        from urllib.error import URLError

        with patch(
            "scripts.check_vendor_security._github_get",
            side_effect=URLError("timeout"),
        ):
            result = check_vendor_security.get_latest_version(
                "bigskysoftware", "htmx"
            )

        assert result is None

    def test_returns_none_on_non_dict_response(self) -> None:
        """Returns None when the API response is not a dict."""
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value=[],
        ):
            result = check_vendor_security.get_latest_version(
                "bigskysoftware", "htmx"
            )

        assert result is None

    def test_returns_none_on_non_string_tag(self) -> None:
        """Returns None when tag_name is not a string."""
        with patch(
            "scripts.check_vendor_security._github_get",
            return_value={"tag_name": 123},
        ):
            result = check_vendor_security.get_latest_version(
                "bigskysoftware", "htmx"
            )

        assert result is None


class TestMain:
    """Tests for main function."""

    def test_passes_when_no_vulnerabilities(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 0 when no vulnerabilities found."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")

        with (
            patch.object(
                check_vendor_security,
                "VERSION_FILE",
                version_file,
            ),
            patch(
                "scripts.check_vendor_security.check_advisories",
                return_value=[],
            ),
            patch(
                "scripts.check_vendor_security.get_latest_version",
                return_value="2.0.8",
            ),
        ):
            result = check_vendor_security.main()

        assert result == 0
        captured = capsys.readouterr()
        assert "up to date and secure" in captured.out

    def test_fails_on_vulnerability(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when vulnerabilities are found."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")

        advisory = {
            "ghsa_id": "GHSA-test-1234-abcd",
            "severity": "high",
            "summary": "XSS vulnerability",
            "html_url": "https://example.com",
        }

        def mock_check(pkg: str, ver: str) -> list[dict[str, str]]:
            if pkg == "htmx.org":
                return [advisory]
            return []

        with (
            patch.object(
                check_vendor_security,
                "VERSION_FILE",
                version_file,
            ),
            patch(
                "scripts.check_vendor_security.check_advisories",
                side_effect=mock_check,
            ),
            patch(
                "scripts.check_vendor_security.get_latest_version",
                return_value="2.0.8",
            ),
        ):
            result = check_vendor_security.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "VULNERABLE" in captured.out
        assert "GHSA-test-1234-abcd" in captured.out

    def test_warns_on_newer_version(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Prints update warning but returns 0."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")

        def mock_latest(owner: str, repo: str) -> str:
            if repo == "htmx":
                return "2.0.9"
            return "2.2.4"

        with (
            patch.object(
                check_vendor_security,
                "VERSION_FILE",
                version_file,
            ),
            patch(
                "scripts.check_vendor_security.check_advisories",
                return_value=[],
            ),
            patch(
                "scripts.check_vendor_security.get_latest_version",
                side_effect=mock_latest,
            ),
        ):
            result = check_vendor_security.main()

        assert result == 0
        captured = capsys.readouterr()
        assert "UPDATE" in captured.out
        assert "2.0.9" in captured.out

    def test_fails_when_version_file_missing(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when VERSION file is missing."""
        with patch.object(
            check_vendor_security,
            "VERSION_FILE",
            tmp_path / "nonexistent",
        ):
            result = check_vendor_security.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "not found" in captured.out

    def test_fails_when_version_file_empty(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when VERSION file has no versions."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("")

        with patch.object(
            check_vendor_security,
            "VERSION_FILE",
            version_file,
        ):
            result = check_vendor_security.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "No versions found" in captured.out

    def test_warns_on_missing_package_in_version_file(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Warns when a known package is missing from VERSION file."""
        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\n")

        with (
            patch.object(
                check_vendor_security,
                "VERSION_FILE",
                version_file,
            ),
            patch(
                "scripts.check_vendor_security.check_advisories",
                return_value=[],
            ),
            patch(
                "scripts.check_vendor_security.get_latest_version",
                return_value="2.0.8",
            ),
        ):
            result = check_vendor_security.main()

        assert result == 0
        captured = capsys.readouterr()
        assert "htmx-ext-sse not found" in captured.out

    def test_fails_on_advisory_check_failure(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Returns 1 when advisory check fails (cannot confirm safe)."""
        from urllib.error import URLError

        version_file = tmp_path / "VERSION"
        version_file.write_text("htmx 2.0.8\nhtmx-ext-sse 2.2.4\n")

        call_count = 0

        def mock_check(pkg: str, ver: str) -> list[dict[str, str]]:
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise URLError("connection refused")
            return []

        with (
            patch.object(
                check_vendor_security,
                "VERSION_FILE",
                version_file,
            ),
            patch(
                "scripts.check_vendor_security.check_advisories",
                side_effect=mock_check,
            ),
            patch(
                "scripts.check_vendor_security.get_latest_version",
                return_value="2.2.4",
            ),
        ):
            result = check_vendor_security.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "Could not check advisories" in captured.out
