# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for the error explainer module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from lib.error_explainer import (
    _SYSTEM_PROMPT,
    _call_anthropic,
    _fallback_explanation,
    explain_error,
)


class TestFallbackExplanation:
    """Tests for the fixed-template fallback."""

    def test_with_exception(self) -> None:
        """Fallback includes exception type and message."""
        err = ValueError("bad input")
        result = _fallback_explanation(err, "")
        assert "ValueError: bad input" in result
        assert "An error occurred" in result
        assert "retry" in result.lower()

    def test_with_error_message(self) -> None:
        """Fallback includes error message when no exception."""
        result = _fallback_explanation(None, "something broke")
        assert "something broke" in result
        assert "An error occurred" in result

    def test_with_both(self) -> None:
        """Exception takes precedence over error_message."""
        err = RuntimeError("boom")
        result = _fallback_explanation(err, "other info")
        assert "RuntimeError: boom" in result

    def test_with_neither(self) -> None:
        """Fallback with no error details."""
        result = _fallback_explanation(None, "")
        assert "An error occurred" in result
        # No "Error:" line when no detail
        assert "Error:" not in result

    def test_no_traceback_in_fallback(self) -> None:
        """Fallback never includes traceback-like content."""
        err = ValueError("test")
        result = _fallback_explanation(err, "")
        assert "Traceback" not in result
        assert "File " not in result

    def test_no_administrator_language(self) -> None:
        """Fallback does not mention administrator."""
        err = ValueError("test")
        result = _fallback_explanation(err, "")
        assert "administrator" not in result.lower()
        assert "notified" not in result.lower()


class TestCallAnthropic:
    """Tests for the Anthropic API call."""

    def test_successful_call(self) -> None:
        """Successful API call returns text content."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "The error was caused by X."}]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("lib.error_explainer.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = _call_anthropic(
                "sk-test", "claude-haiku-4-5", "error info"
            )
            assert result == "The error was caused by X."

            # Verify request structure
            call_kwargs = mock_client.post.call_args
            assert call_kwargs[0][0].endswith("/messages")
            headers = call_kwargs[1]["headers"]
            assert headers["x-api-key"] == "sk-test"
            json_body = call_kwargs[1]["json"]
            assert json_body["model"] == "claude-haiku-4-5"
            assert json_body["system"] == _SYSTEM_PROMPT
            assert json_body["max_tokens"] == 256

    def test_multiple_content_blocks(self) -> None:
        """Multiple text blocks are joined."""
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [
                {"type": "text", "text": "First part."},
                {"type": "text", "text": "Second part."},
            ]
        }
        mock_response.raise_for_status = MagicMock()

        with patch("lib.error_explainer.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            result = _call_anthropic("sk-test", "claude-haiku-4-5", "error")
            assert "First part." in result
            assert "Second part." in result

    def test_http_error_propagates(self) -> None:
        """HTTP errors from API are propagated."""
        with patch("lib.error_explainer.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)

            mock_request = MagicMock()
            mock_response = MagicMock()
            mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
                "401 Unauthorized",
                request=mock_request,
                response=mock_response,
            )
            mock_client.post.return_value = mock_response
            mock_client_cls.return_value = mock_client

            with pytest.raises(httpx.HTTPStatusError):
                _call_anthropic("bad-key", "claude-haiku-4-5", "error")

    def test_timeout_propagates(self) -> None:
        """Timeout exceptions are propagated."""
        with patch("lib.error_explainer.httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.TimeoutException("timed out")
            mock_client_cls.return_value = mock_client

            with pytest.raises(httpx.TimeoutException):
                _call_anthropic("sk-test", "claude-haiku-4-5", "error")


class TestExplainError:
    """Tests for the main explain_error function."""

    def test_no_api_key_uses_fallback(self) -> None:
        """Without API key, fallback template is used."""
        result = explain_error(
            error=ValueError("bad"),
            api_key=None,
        )
        assert "ValueError: bad" in result
        assert "An error occurred" in result

    def test_empty_api_key_uses_fallback(self) -> None:
        """Empty API key string uses fallback."""
        result = explain_error(
            error=ValueError("bad"),
            api_key="",
        )
        assert "ValueError: bad" in result

    def test_api_key_calls_anthropic(self) -> None:
        """With API key, Anthropic API is called."""
        with patch(
            "lib.error_explainer._call_anthropic",
            return_value="LLM explanation",
        ) as mock_call:
            result = explain_error(
                error=RuntimeError("boom"),
                error_message="extra info",
                traceback_str="Traceback...\nFile...",
                api_key="sk-test",
                model="claude-haiku-4-5",
            )

            assert result == "LLM explanation"
            mock_call.assert_called_once()
            call_args = mock_call.call_args
            assert call_args[0][0] == "sk-test"
            assert call_args[0][1] == "claude-haiku-4-5"
            raw_info = call_args[0][2]
            assert "RuntimeError" in raw_info
            assert "boom" in raw_info
            assert "extra info" in raw_info
            assert "Traceback" in raw_info

    def test_api_failure_falls_back(self) -> None:
        """API failure falls back to template."""
        with patch(
            "lib.error_explainer._call_anthropic",
            side_effect=httpx.TimeoutException("timeout"),
        ):
            result = explain_error(
                error=ValueError("test"),
                api_key="sk-test",
            )
            # Should use fallback, not raise
            assert "ValueError: test" in result
            assert "An error occurred" in result

    def test_api_http_error_falls_back(self) -> None:
        """HTTP error from API falls back to template."""
        with patch(
            "lib.error_explainer._call_anthropic",
            side_effect=httpx.HTTPStatusError(
                "401",
                request=MagicMock(),
                response=MagicMock(),
            ),
        ):
            result = explain_error(
                error=RuntimeError("crash"),
                api_key="sk-test",
            )
            assert "RuntimeError: crash" in result

    def test_only_error_message(self) -> None:
        """Works with only error_message, no exception."""
        result = explain_error(error_message="disk full")
        assert "disk full" in result

    def test_only_traceback(self) -> None:
        """Works with only traceback (no exception or message)."""
        with patch(
            "lib.error_explainer._call_anthropic",
            return_value="Summarized",
        ) as mock_call:
            result = explain_error(
                traceback_str="Traceback:\n  File...",
                api_key="sk-test",
            )
            assert result == "Summarized"
            raw_info = mock_call.call_args[0][2]
            assert "Traceback" in raw_info

    def test_no_error_info_at_all(self) -> None:
        """Handles case with no error info gracefully."""
        result = explain_error()
        assert "An error occurred" in result

    def test_context_parameter_accepted(self) -> None:
        """Context parameter is accepted without error."""
        result = explain_error(
            error=ValueError("test"),
            context="dashboard",
        )
        assert "ValueError: test" in result
