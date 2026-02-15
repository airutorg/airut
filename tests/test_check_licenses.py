# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_licenses.py."""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# Import the module under test
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts"))
import check_licenses  # type: ignore[import-not-found]


UV_TREE_OUTPUT = """\
airut
├── msal v1.34.0
│   ├── cryptography v46.0.5
│   │   └── cffi v2.0.0
│   │       └── pycparser v3.0
│   ├── pyjwt[crypto] v2.11.0
│   │   └── cryptography v46.0.5 (extra: crypto) (*)
│   └── requests v2.32.5
│       ├── certifi v2026.1.4
│       ├── charset-normalizer v3.4.4
│       ├── idna v3.11
│       └── urllib3 v2.6.3
├── platformdirs v4.9.1
├── python-dotenv v1.2.1
├── pyyaml v6.0.3
└── werkzeug v3.1.5
    └── markupsafe v3.0.3
(*) Package tree already displayed
"""


class TestResolveRuntimePackages:
    """Tests for resolve_runtime_packages."""

    def test_parses_uv_tree_output(self) -> None:
        """Extracts package names from uv tree output."""
        mock_result = MagicMock(stdout=UV_TREE_OUTPUT)
        with patch(
            "check_licenses.subprocess.run", return_value=mock_result
        ) as mock_run:
            packages = check_licenses.resolve_runtime_packages()
            mock_run.assert_called_once_with(
                ["uv", "tree", "--no-dev", "--depth", "100"],
                capture_output=True,
                text=True,
                check=True,
            )

        assert packages == [
            "certifi",
            "cffi",
            "charset-normalizer",
            "cryptography",
            "idna",
            "markupsafe",
            "msal",
            "platformdirs",
            "pycparser",
            "pyjwt",
            "python-dotenv",
            "pyyaml",
            "requests",
            "urllib3",
            "werkzeug",
        ]

    def test_excludes_root_project(self) -> None:
        """Root project name (no tree prefix) is excluded."""
        mock_result = MagicMock(stdout=UV_TREE_OUTPUT)
        with patch("check_licenses.subprocess.run", return_value=mock_result):
            packages = check_licenses.resolve_runtime_packages()

        assert "airut" not in packages

    def test_strips_extras_notation(self) -> None:
        """Extras like pyjwt[crypto] are stripped to pyjwt."""
        mock_result = MagicMock(stdout=UV_TREE_OUTPUT)
        with patch("check_licenses.subprocess.run", return_value=mock_result):
            packages = check_licenses.resolve_runtime_packages()

        assert "pyjwt" in packages
        assert not any("[" in p for p in packages)

    def test_deduplicates_packages(self) -> None:
        """Packages appearing multiple times in tree are deduplicated."""
        mock_result = MagicMock(stdout=UV_TREE_OUTPUT)
        with patch("check_licenses.subprocess.run", return_value=mock_result):
            packages = check_licenses.resolve_runtime_packages()

        # cryptography appears twice in the tree
        assert packages.count("cryptography") == 1

    def test_empty_tree(self) -> None:
        """Returns empty list for project with no dependencies."""
        mock_result = MagicMock(stdout="airut\n")
        with patch("check_licenses.subprocess.run", return_value=mock_result):
            packages = check_licenses.resolve_runtime_packages()

        assert packages == []


class TestMain:
    """Tests for main function."""

    def test_passes_packages_to_pip_licenses(self) -> None:
        """Resolves packages and passes them to pip-licenses."""
        with (
            patch(
                "check_licenses.resolve_runtime_packages",
                return_value=["msal", "pyyaml"],
            ),
            patch("check_licenses.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            result = check_licenses.main()

        assert result == 0
        mock_run.assert_called_once_with(
            ["uv", "run", "pip-licenses", "--packages", "msal", "pyyaml"],
            text=True,
        )

    def test_returns_pip_licenses_exit_code(self) -> None:
        """Returns exit code from pip-licenses."""
        with (
            patch(
                "check_licenses.resolve_runtime_packages",
                return_value=["msal"],
            ),
            patch("check_licenses.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=1)
            result = check_licenses.main()

        assert result == 1

    def test_fails_when_no_packages_resolved(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns error when no runtime packages are found."""
        with patch("check_licenses.resolve_runtime_packages", return_value=[]):
            result = check_licenses.main()

        assert result == 1
        captured = capsys.readouterr()
        assert "No runtime packages resolved" in captured.err
