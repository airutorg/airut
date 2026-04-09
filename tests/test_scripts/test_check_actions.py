# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for scripts/check_actions.py."""

from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError

import pytest
import scripts.check_actions as check_actions


class TestRepoFromAction:
    """Tests for _repo_from_action."""

    def test_simple(self) -> None:
        assert (
            check_actions._repo_from_action("actions/checkout")
            == "actions/checkout"
        )

    def test_subpath(self) -> None:
        assert (
            check_actions._repo_from_action("actions/cache/restore")
            == "actions/cache"
        )

    def test_deep_subpath(self) -> None:
        assert (
            check_actions._repo_from_action("owner/repo/a/b/c") == "owner/repo"
        )


class TestMajorRef:
    """Tests for _major_ref."""

    def test_semver(self) -> None:
        assert check_actions._major_ref("v4.3.1") == "v4"

    def test_two_part(self) -> None:
        assert check_actions._major_ref("v1.14") == "v1"

    def test_major_only(self) -> None:
        assert check_actions._major_ref("v4") == "v4"

    def test_branch_style(self) -> None:
        assert check_actions._major_ref("release/v1") == "release/v1"

    def test_no_match(self) -> None:
        assert check_actions._major_ref("release") == "release"


class TestResolveTagSha:
    """Tests for resolve_tag_sha."""

    def test_lightweight_tag(self) -> None:
        """Resolves a lightweight tag (type=commit) directly."""
        api_response = {
            "object": {"type": "commit", "sha": "abc123" + "0" * 34}
        }
        with patch.object(
            check_actions, "_github_get", return_value=api_response
        ):
            result = check_actions.resolve_tag_sha("actions/checkout", "v4")
        assert result == "abc123" + "0" * 34

    def test_annotated_tag(self) -> None:
        """Dereferences an annotated tag (type=tag) to the commit."""
        tag_sha = "tag000" + "0" * 34
        commit_sha = "commit" + "0" * 34
        tag_ref_response = {"object": {"type": "tag", "sha": tag_sha}}
        tag_obj_response = {"object": {"type": "commit", "sha": commit_sha}}

        def mock_get(url: str) -> dict:  # type: ignore[type-arg]
            if "/git/ref/" in url:
                return tag_ref_response
            return tag_obj_response

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("astral-sh/setup-uv", "v4")
        assert result == commit_sha

    def test_falls_back_to_branch(self) -> None:
        """Falls back to heads/ when tags/ returns 404."""
        branch_response = {
            "object": {"type": "commit", "sha": "branch" + "0" * 34}
        }

        def mock_get(url: str) -> dict:  # type: ignore[type-arg]
            if "/tags/" in url:
                raise HTTPError(url, 404, "Not Found", {}, None)  # ty:ignore[invalid-argument-type]
            return branch_response

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha(
                "pypa/gh-action-pypi-publish", "release/v1"
            )
        assert result == "branch" + "0" * 34

    def test_returns_none_when_not_found(self) -> None:
        """Returns None when neither tag nor branch exists."""

        def mock_get(url: str) -> dict:  # type: ignore[type-arg]
            raise HTTPError(url, 404, "Not Found", {}, None)  # ty:ignore[invalid-argument-type]

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("owner/repo", "v99")
        assert result is None

    def test_annotated_tag_dereference_fails(self) -> None:
        """Returns tag SHA when dereference fails."""
        tag_sha = "tag000" + "0" * 34
        tag_ref_response = {"object": {"type": "tag", "sha": tag_sha}}

        def mock_get(url: str) -> dict:  # type: ignore[type-arg]
            if "/git/ref/" in url:
                return tag_ref_response
            raise HTTPError(url, 500, "Server Error", {}, None)  # ty:ignore[invalid-argument-type]

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result == tag_sha

    def test_invalid_response_shape(self) -> None:
        """Returns None for non-dict response."""
        with patch.object(
            check_actions, "_github_get", return_value="not a dict"
        ):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result is None

    def test_missing_object_key(self) -> None:
        """Returns None when object key is missing."""
        with patch.object(
            check_actions, "_github_get", return_value={"other": 1}
        ):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result is None

    def test_non_string_sha(self) -> None:
        """Returns None when sha is not a string."""
        response = {"object": {"type": "commit", "sha": 12345}}
        with patch.object(check_actions, "_github_get", return_value=response):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result is None

    def test_annotated_tag_inner_non_dict(self) -> None:
        """Returns tag SHA when inner tag object is malformed."""
        tag_sha = "tag000" + "0" * 34
        tag_ref_response = {"object": {"type": "tag", "sha": tag_sha}}

        def mock_get(url: str) -> object:
            if "/git/ref/" in url:
                return tag_ref_response
            return {"object": "not-a-dict"}

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result == tag_sha

    def test_annotated_tag_inner_sha_not_string(self) -> None:
        """Returns tag SHA when inner commit sha is not a string."""
        tag_sha = "tag000" + "0" * 34
        tag_ref_response = {"object": {"type": "tag", "sha": tag_sha}}

        def mock_get(url: str) -> object:
            if "/git/ref/" in url:
                return tag_ref_response
            return {"object": {"type": "commit", "sha": 999}}

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result == tag_sha

    def test_non_dict_object_value(self) -> None:
        """Returns None when object value is not a dict."""
        response = {"object": "string-not-dict"}
        with patch.object(check_actions, "_github_get", return_value=response):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result is None

    def test_annotated_tag_non_dict_tag_data(self) -> None:
        """Returns tag SHA when tag data response is not a dict."""
        tag_sha = "tag000" + "0" * 34
        tag_ref_response = {"object": {"type": "tag", "sha": tag_sha}}

        def mock_get(url: str) -> object:
            if "/git/ref/" in url:
                return tag_ref_response
            return "not-a-dict"

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.resolve_tag_sha("owner/repo", "v1")
        assert result == tag_sha


class TestGetGithubHeaders:
    """Tests for _get_github_headers."""

    def test_no_token(self) -> None:
        """Returns base headers when no token is set."""
        with patch.dict("os.environ", {}, clear=True):
            headers = check_actions._get_github_headers()
        assert "Authorization" not in headers
        assert "Accept" in headers

    def test_github_token(self) -> None:
        """Includes Authorization when GITHUB_TOKEN is set."""
        with patch.dict(
            "os.environ", {"GITHUB_TOKEN": "ghp_test123"}, clear=True
        ):
            headers = check_actions._get_github_headers()
        assert headers["Authorization"] == "Bearer ghp_test123"

    def test_gh_token_fallback(self) -> None:
        """Falls back to GH_TOKEN when GITHUB_TOKEN is unset."""
        with patch.dict("os.environ", {"GH_TOKEN": "gho_fallback"}, clear=True):
            headers = check_actions._get_github_headers()
        assert headers["Authorization"] == "Bearer gho_fallback"


class TestGithubGet:
    """Tests for _github_get."""

    def test_returns_parsed_json(self) -> None:
        """Returns parsed JSON from the response."""
        from unittest.mock import MagicMock

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.read.return_value = b'{"key": "value"}'

        with patch.object(check_actions, "urlopen", return_value=mock_resp):
            result = check_actions._github_get("https://example.com")
        assert result == {"key": "value"}


class TestLatestVersionTag:
    """Tests for latest_version_tag."""

    def test_finds_latest(self) -> None:
        """Returns the highest semver tag for the major version."""
        tags = [
            {"name": "v4.1.0"},
            {"name": "v4.3.1"},
            {"name": "v4.2.0"},
            {"name": "v3.5.0"},
        ]
        with patch.object(check_actions, "_github_get", return_value=tags):
            result = check_actions.latest_version_tag("actions/checkout", "v4")
        assert result == "v4.3.1"

    def test_no_matching_tags(self) -> None:
        """Returns major version when no patch tags exist."""
        tags = [{"name": "v3.5.0"}]
        with patch.object(check_actions, "_github_get", return_value=tags):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result == "v4"

    def test_http_error(self) -> None:
        """Returns None on HTTP error."""

        def mock_get(url: str) -> object:
            raise HTTPError(url, 500, "Error", {}, None)  # ty:ignore[invalid-argument-type]

        with patch.object(check_actions, "_github_get", side_effect=mock_get):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result is None

    def test_non_list_response(self) -> None:
        """Returns None for non-list response."""
        with patch.object(check_actions, "_github_get", return_value="bad"):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result is None

    def test_non_dict_tag_entries(self) -> None:
        """Skips non-dict entries in tag list."""
        tags = ["not-a-dict", {"name": "v4.1.0"}]
        with patch.object(check_actions, "_github_get", return_value=tags):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result == "v4.1.0"

    def test_non_string_name(self) -> None:
        """Skips entries with non-string name."""
        tags = [{"name": 123}, {"name": "v4.1.0"}]
        with patch.object(check_actions, "_github_get", return_value=tags):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result == "v4.1.0"

    def test_invalid_version_numbers(self) -> None:
        """Skips tags with non-numeric parts."""
        tags = [{"name": "v4.beta.1"}, {"name": "v4.1.0"}]
        with patch.object(check_actions, "_github_get", return_value=tags):
            result = check_actions.latest_version_tag("owner/repo", "v4")
        assert result == "v4.1.0"


class TestScanWorkflowFiles:
    """Tests for scan_workflow_files."""

    def test_finds_workflow_files(self, tmp_path: Path) -> None:
        """Finds yml files in .github/workflows/."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("name: CI")
        (wf_dir / "publish.yml").write_text("name: Publish")

        result = check_actions.scan_workflow_files(root=tmp_path)
        assert len(result) == 2

    def test_includes_action_yml(self, tmp_path: Path) -> None:
        """Includes action.yml when it exists."""
        (tmp_path / "action.yml").write_text("name: Test")
        result = check_actions.scan_workflow_files(root=tmp_path)
        assert len(result) == 1

    def test_empty_when_no_files(self, tmp_path: Path) -> None:
        """Returns empty list when no matching files exist."""
        result = check_actions.scan_workflow_files(root=tmp_path)
        assert result == []

    def test_defaults_to_cwd(self, tmp_path: Path) -> None:
        """Uses current directory when root is None."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        (wf_dir / "ci.yml").write_text("name: CI")

        import os

        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = check_actions.scan_workflow_files()
        finally:
            os.chdir(old_cwd)
        assert len(result) == 1


SHA_A = "a" * 40
SHA_B = "b" * 40


class TestCheckActions:
    """Tests for check_actions."""

    def test_no_files(self, capsys: pytest.CaptureFixture[str]) -> None:
        """Returns 0 when no workflow files exist."""
        with patch.object(
            check_actions, "scan_workflow_files", return_value=[]
        ):
            result = check_actions.check_actions()
        assert result == 0
        assert "No workflow files found" in capsys.readouterr().out

    def test_up_to_date(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Returns 0 when all actions are up to date."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.1\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
        ):
            result = check_actions.check_actions()
        assert result == 0
        assert "up to date" in capsys.readouterr().out

    def test_outdated_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports outdated actions and returns 1."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.0\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_B),
            patch.object(
                check_actions, "latest_version_tag", return_value="v4.3.1"
            ),
        ):
            result = check_actions.check_actions()
        assert result == 1
        out = capsys.readouterr().out
        assert "Outdated" in out
        assert "v4.3.0 → v4.3.1" in out

    def test_outdated_fix(self, tmp_path: Path) -> None:
        """Fix mode updates SHA and version in the file."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.0\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_B),
            patch.object(
                check_actions, "latest_version_tag", return_value="v4.3.1"
            ),
        ):
            result = check_actions.check_actions(fix=True)
        assert result == 0
        content = wf.read_text()
        assert SHA_B in content
        assert "v4.3.1" in content
        assert SHA_A not in content

    def test_unpinned_reports(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports unpinned (tag-referenced) actions."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: actions/checkout@v4\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(
                check_actions,
                "_resolve_unpinned_ref",
                return_value=(SHA_A, "v4.3.1"),
            ),
        ):
            result = check_actions.check_actions()
        assert result == 1
        out = capsys.readouterr().out
        assert "Unpinned" in out

    def test_unpinned_fix(self, tmp_path: Path) -> None:
        """Fix mode pins unpinned actions."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: actions/checkout@v4\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(
                check_actions,
                "_resolve_unpinned_ref",
                return_value=(SHA_A, "v4.3.1"),
            ),
        ):
            result = check_actions.check_actions(fix=True)
        assert result == 0
        content = wf.read_text()
        assert f"@{SHA_A} # v4.3.1" in content

    def test_excluded_actions_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Excluded actions are not checked."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: airutorg/sandbox-action@main\n")

        with patch.object(
            check_actions, "scan_workflow_files", return_value=[wf]
        ):
            result = check_actions.check_actions()
        assert result == 0
        assert "up to date" in capsys.readouterr().out

    def test_excluded_pinned_action_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Excluded actions are skipped even when SHA-pinned."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: airutorg/sandbox-action@{SHA_A} # v1.0.0\n")

        with patch.object(
            check_actions, "scan_workflow_files", return_value=[wf]
        ):
            result = check_actions.check_actions()
        assert result == 0

    def test_self_reference_dot_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Bare dot self-references are not checked."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: .@v1\n")

        with patch.object(
            check_actions, "scan_workflow_files", return_value=[wf]
        ):
            result = check_actions.check_actions()
        assert result == 0

    def test_self_reference_skipped(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Self-references (./) are not checked."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: ./local@v1\n")

        with patch.object(
            check_actions, "scan_workflow_files", return_value=[wf]
        ):
            result = check_actions.check_actions()
        assert result == 0

    def test_resolve_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports errors when SHA cannot be resolved."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.1\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=None),
        ):
            result = check_actions.check_actions()
        assert result == 1
        assert "cannot resolve" in capsys.readouterr().out

    def test_verbose_shows_up_to_date(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Verbose mode shows up-to-date actions."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.1\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
        ):
            result = check_actions.check_actions(verbose=True)
        assert result == 0
        assert "Up to date" in capsys.readouterr().out

    def test_subpath_action(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Handles actions with subpaths like actions/cache/restore."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/cache/restore@{SHA_A} # v4.3.0\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
        ):
            result = check_actions.check_actions()
        assert result == 0

    def test_resolve_falls_back_to_release_branch(self, tmp_path: Path) -> None:
        """Falls back to release/vN when vN tag doesn't exist."""
        wf = tmp_path / "ci.yml"
        wf.write_text(
            f"    - uses: pypa/gh-action-pypi-publish@{SHA_A} # v1.14.0\n"
        )

        call_args: list[tuple[str, str]] = []

        def mock_resolve(repo: str, ref: str) -> str | None:
            call_args.append((repo, ref))
            if ref == "v1":
                return None
            if ref == "release/v1":
                return SHA_A
            return None

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(
                check_actions, "resolve_tag_sha", side_effect=mock_resolve
            ),
        ):
            result = check_actions.check_actions()
        assert result == 0
        assert ("pypa/gh-action-pypi-publish", "v1") in call_args
        assert ("pypa/gh-action-pypi-publish", "release/v1") in call_args

    def test_unpinned_resolve_failure(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Reports error when unpinned ref cannot be resolved."""
        wf = tmp_path / "ci.yml"
        wf.write_text("    - uses: actions/checkout@v4\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(
                check_actions, "_resolve_unpinned_ref", return_value=None
            ),
        ):
            result = check_actions.check_actions()
        assert result == 1
        assert "cannot resolve" in capsys.readouterr().out

    def test_outdated_fix_latest_version_none(self, tmp_path: Path) -> None:
        """Uses major version when latest_version_tag returns None."""
        wf = tmp_path / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.0\n")

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_B),
            patch.object(
                check_actions, "latest_version_tag", return_value=None
            ),
        ):
            result = check_actions.check_actions(fix=True)
        assert result == 0
        content = wf.read_text()
        assert f"@{SHA_B} # v4" in content

    def test_repo_argument_threads_through(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """The repo argument is passed to scan_workflow_files."""
        wf_dir = tmp_path / ".github" / "workflows"
        wf_dir.mkdir(parents=True)
        wf = wf_dir / "ci.yml"
        wf.write_text(f"    - uses: actions/checkout@{SHA_A} # v4.3.1\n")

        with patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A):
            result = check_actions.check_actions(root=tmp_path)
        assert result == 0
        assert "up to date" in capsys.readouterr().out

    def test_pinned_count_in_summary(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Summary shows count of pinned actions."""
        wf = tmp_path / "ci.yml"
        wf.write_text(
            f"    - uses: actions/checkout@{SHA_A} # v4.3.1\n"
            f"    - uses: actions/cache@{SHA_A} # v4.3.0\n"
        )

        with (
            patch.object(
                check_actions, "scan_workflow_files", return_value=[wf]
            ),
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
        ):
            result = check_actions.check_actions()
        assert result == 0
        assert "2 pinned" in capsys.readouterr().out


class TestResolveUnpinnedRef:
    """Tests for _resolve_unpinned_ref."""

    def test_resolves_tag(self) -> None:
        """Resolves a tag ref to SHA and version."""
        with (
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
            patch.object(
                check_actions, "latest_version_tag", return_value="v4.3.1"
            ),
        ):
            result = check_actions._resolve_unpinned_ref(
                "actions/checkout", "v4"
            )
        assert result == (SHA_A, "v4.3.1")

    def test_returns_none_on_failure(self) -> None:
        """Returns None when SHA resolution fails."""
        with patch.object(check_actions, "resolve_tag_sha", return_value=None):
            result = check_actions._resolve_unpinned_ref("owner/repo", "v99")
        assert result is None

    def test_uses_ref_when_no_version(self) -> None:
        """Uses ref as label when latest_version_tag returns None."""
        with (
            patch.object(check_actions, "resolve_tag_sha", return_value=SHA_A),
            patch.object(
                check_actions, "latest_version_tag", return_value=None
            ),
        ):
            result = check_actions._resolve_unpinned_ref(
                "owner/repo", "release/v1"
            )
        assert result == (SHA_A, "release/v1")


class TestMain:
    """Tests for CLI entry point."""

    def test_check_mode(self) -> None:
        """Runs in check mode by default."""
        with (
            patch("sys.argv", ["check_actions.py"]),
            patch.object(
                check_actions, "check_actions", return_value=0
            ) as mock_check,
        ):
            result = check_actions.main()
        assert result == 0
        mock_check.assert_called_once_with(fix=False, verbose=False, root=None)

    def test_fix_mode(self) -> None:
        """Passes fix=True when --fix is given."""
        with (
            patch("sys.argv", ["check_actions.py", "--fix"]),
            patch.object(
                check_actions, "check_actions", return_value=0
            ) as mock_check,
        ):
            result = check_actions.main()
        assert result == 0
        mock_check.assert_called_once_with(fix=True, verbose=False, root=None)

    def test_verbose_mode(self) -> None:
        """Passes verbose=True when --verbose is given."""
        with (
            patch("sys.argv", ["check_actions.py", "--verbose"]),
            patch.object(
                check_actions, "check_actions", return_value=0
            ) as mock_check,
        ):
            result = check_actions.main()
        assert result == 0
        mock_check.assert_called_once_with(fix=False, verbose=True, root=None)

    def test_repo_argument(self) -> None:
        """Passes repo path when --repo is given."""
        with (
            patch("sys.argv", ["check_actions.py", "--repo", "/tmp/other"]),
            patch.object(
                check_actions, "check_actions", return_value=0
            ) as mock_check,
        ):
            result = check_actions.main()
        assert result == 0
        mock_check.assert_called_once_with(
            fix=False, verbose=False, root=Path("/tmp/other")
        )
