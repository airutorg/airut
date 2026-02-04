# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for usage_stats module."""

from pathlib import Path
from unittest.mock import patch

from lib.gateway.service import (
    UsageStats,
    capture_version_info,
    extract_response_text,
    extract_usage_stats,
)
from lib.git_version import GitVersionInfo


class TestCaptureVersionInfo:
    """Tests for capture_version_info function."""

    def test_capture_clean_worktree(self) -> None:
        mock_git_version = GitVersionInfo(
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=True,
            full_status="=== HEAD COMMIT ===\ncommit abc1234",
        )

        with (
            patch(
                "lib.gateway.service.gateway.get_git_version_info"
            ) as mock_get_version,
            patch("time.time", return_value=1000.0),
        ):
            mock_get_version.return_value = mock_git_version
            result = capture_version_info()

        assert result.git_sha == "abc1234"
        assert (
            result.git_sha_full == "abc1234567890abcdef1234567890abcdef123456"
        )
        assert result.worktree_clean is True
        assert result.full_status == "=== HEAD COMMIT ===\ncommit abc1234"
        assert result.started_at == 1000.0

    def test_capture_dirty_worktree(self) -> None:
        mock_git_version = GitVersionInfo(
            sha_short="def5678",
            sha_full="def5678901234567890abcdef1234567890abcdef",
            worktree_clean=False,
            full_status="=== HEAD COMMIT ===\ncommit def5678",
        )

        with (
            patch(
                "lib.gateway.service.gateway.get_git_version_info"
            ) as mock_get_version,
            patch("time.time", return_value=2000.0),
        ):
            mock_get_version.return_value = mock_git_version
            result = capture_version_info()

        assert result.git_sha == "def5678"
        assert result.worktree_clean is False
        assert result.started_at == 2000.0

    def test_capture_passes_repo_root(self) -> None:
        mock_git_version = GitVersionInfo(
            sha_short="abc1234",
            sha_full="abc1234567890abcdef1234567890abcdef123456",
            worktree_clean=True,
            full_status="status",
        )
        repo_root = Path("/custom/repo")

        with (
            patch(
                "lib.gateway.service.gateway.get_git_version_info"
            ) as mock_get_version,
            patch("time.time", return_value=3000.0),
        ):
            mock_get_version.return_value = mock_git_version
            capture_version_info(repo_root)

        mock_get_version.assert_called_once_with(repo_root)


class TestUsageStats:
    """Tests for UsageStats dataclass."""

    def test_default_values(self) -> None:
        stats = UsageStats()
        assert stats.total_cost_usd is None
        assert stats.web_search_requests == 0
        assert stats.web_fetch_requests == 0
        assert stats.is_subscription is False

    def test_has_any_false_when_empty(self) -> None:
        assert UsageStats().has_any() is False

    def test_has_any_true_with_cost(self) -> None:
        assert UsageStats(total_cost_usd=0.01).has_any() is True

    def test_has_any_true_with_web_search(self) -> None:
        assert UsageStats(web_search_requests=1).has_any() is True

    def test_has_any_true_with_web_fetch(self) -> None:
        assert UsageStats(web_fetch_requests=1).has_any() is True

    def test_has_any_false_with_cost_and_subscription(self) -> None:
        assert (
            UsageStats(total_cost_usd=0.01, is_subscription=True).has_any()
            is False
        )

    def test_has_any_true_subscription_with_web_search(self) -> None:
        assert (
            UsageStats(is_subscription=True, web_search_requests=1).has_any()
            is True
        )

    def test_format_summary_empty(self) -> None:
        assert UsageStats().format_summary() == ""

    def test_format_summary_cost_only(self) -> None:
        assert (
            UsageStats(total_cost_usd=0.0123).format_summary()
            == "Cost: $0.0123"
        )

    def test_format_summary_web_search_only(self) -> None:
        assert (
            UsageStats(web_search_requests=3).format_summary()
            == "Web searches: 3"
        )

    def test_format_summary_web_fetch_only(self) -> None:
        assert (
            UsageStats(web_fetch_requests=2).format_summary()
            == "Web fetches: 2"
        )

    def test_format_summary_all_stats(self) -> None:
        stats = UsageStats(
            total_cost_usd=0.0567,
            web_search_requests=5,
            web_fetch_requests=3,
        )
        assert (
            stats.format_summary()
            == "Cost: $0.0567 · Web searches: 5 · Web fetches: 3"
        )

    def test_format_summary_cost_and_search(self) -> None:
        stats = UsageStats(total_cost_usd=0.1, web_search_requests=2)
        assert stats.format_summary() == "Cost: $0.1000 · Web searches: 2"

    def test_format_summary_subscription_excludes_cost(self) -> None:
        stats = UsageStats(
            total_cost_usd=0.0567,
            web_search_requests=5,
            web_fetch_requests=3,
            is_subscription=True,
        )
        assert stats.format_summary() == "Web searches: 5 · Web fetches: 3"

    def test_format_summary_subscription_cost_only_is_empty(self) -> None:
        stats = UsageStats(total_cost_usd=0.0567, is_subscription=True)
        assert stats.format_summary() == ""


class TestExtractResponseText:
    def test_none_output(self) -> None:
        assert extract_response_text(None) == "No output received from Claude."

    def test_non_dict_output(self) -> None:
        result = extract_response_text("not a dict")  # type: ignore[arg-type]
        assert "Invalid output type" in result

    def test_text_from_events(self) -> None:
        output = {
            "events": [
                {
                    "type": "assistant",
                    "message": {
                        "content": [{"type": "text", "text": "Hello world"}]
                    },
                }
            ]
        }
        assert extract_response_text(output) == "Hello world"

    def test_multiple_text_blocks(self) -> None:
        output = {
            "events": [
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "text", "text": "Part 1"},
                            {"type": "text", "text": "Part 2"},
                        ]
                    },
                }
            ]
        }
        assert extract_response_text(output) == "Part 1\n\nPart 2"

    def test_fallback_to_result_string(self) -> None:
        output = {"events": [], "result": "fallback text"}
        assert extract_response_text(output) == "fallback text"

    def test_fallback_to_result_dict(self) -> None:
        output = {
            "events": [],
            "result": {"content": [{"type": "text", "text": "from dict"}]},
        }
        assert extract_response_text(output) == "from dict"

    def test_result_dict_no_text(self) -> None:
        output = {"events": [], "result": {"content": []}}
        assert extract_response_text(output) == "No text output."

    def test_result_none(self) -> None:
        output = {"events": []}
        assert "No output received" in extract_response_text(output)

    def test_result_unexpected_type(self) -> None:
        output = {"events": [], "result": 42}
        assert "Unexpected result type" in extract_response_text(output)

    def test_exception_handling(self) -> None:
        """KeyError/TypeError/AttributeError -> graceful fallback."""
        # events with bad structure that causes TypeError
        output = {"events": [{"type": "assistant", "message": None}]}
        assert "Could not parse" in extract_response_text(output)

    def test_last_assistant_event_used(self) -> None:
        output = {
            "events": [
                {
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": "First"}]},
                },
                {
                    "type": "assistant",
                    "message": {"content": [{"type": "text", "text": "Last"}]},
                },
            ]
        }
        assert extract_response_text(output) == "Last"

    def test_skips_non_text_blocks(self) -> None:
        output = {
            "events": [
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "name": "Bash"},
                            {"type": "text", "text": "Done"},
                        ]
                    },
                }
            ]
        }
        assert extract_response_text(output) == "Done"


class TestExtractUsageStats:
    def test_none_output(self) -> None:
        stats = extract_usage_stats(None)
        assert stats.total_cost_usd is None

    def test_non_dict_output(self) -> None:
        stats = extract_usage_stats("bad")  # type: ignore[arg-type]
        assert stats.total_cost_usd is None

    def test_extracts_cost(self) -> None:
        output = {"total_cost_usd": 0.05, "events": []}
        stats = extract_usage_stats(output)
        assert stats.total_cost_usd == 0.05

    def test_invalid_cost_value(self) -> None:
        output = {"total_cost_usd": "not-a-number", "events": []}
        stats = extract_usage_stats(output)
        assert stats.total_cost_usd is None

    def test_counts_web_search_and_fetch(self) -> None:
        output = {
            "events": [
                {
                    "type": "assistant",
                    "message": {
                        "content": [
                            {"type": "tool_use", "name": "WebSearch"},
                            {"type": "tool_use", "name": "WebFetch"},
                            {"type": "tool_use", "name": "WebSearch"},
                            {"type": "tool_use", "name": "Bash"},
                        ]
                    },
                }
            ]
        }
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 2
        assert stats.web_fetch_requests == 1

    def test_subscription_flag_from_container_env(self) -> None:
        stats = extract_usage_stats({"events": []}, is_subscription=True)
        assert stats.is_subscription is True

    def test_no_subscription_without_oauth(self) -> None:
        stats = extract_usage_stats({"events": []})
        assert stats.is_subscription is False

    def test_skips_non_assistant_events(self) -> None:
        output = {
            "events": [
                {
                    "type": "system",
                    "message": {
                        "content": [{"type": "tool_use", "name": "WebSearch"}]
                    },
                }
            ]
        }
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 0

    def test_skips_non_dict_events(self) -> None:
        output = {"events": ["not-a-dict", None, 42]}
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 0

    def test_skips_non_dict_message(self) -> None:
        output = {"events": [{"type": "assistant", "message": "bad"}]}
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 0

    def test_skips_non_list_content(self) -> None:
        output = {
            "events": [{"type": "assistant", "message": {"content": "bad"}}]
        }
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 0

    def test_skips_non_dict_content_blocks(self) -> None:
        output = {
            "events": [
                {"type": "assistant", "message": {"content": ["bad", None]}}
            ]
        }
        stats = extract_usage_stats(output)
        assert stats.web_search_requests == 0
