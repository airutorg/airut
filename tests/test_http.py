# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for airut/http.py."""

from __future__ import annotations

from email.message import Message
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

import pytest

from airut.http import _RETRYABLE_STATUS_CODES, urlopen_with_retry


_URLOPEN = "airut.http.urllib.request.urlopen"
_SLEEP = "airut.http.time.sleep"


def _mock_response(data: bytes = b"ok") -> MagicMock:
    """Create a mock urlopen() return value."""
    resp = MagicMock()
    resp.read.return_value = data
    resp.__enter__ = MagicMock(return_value=resp)
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _http_error(code: int) -> HTTPError:
    """Create an HTTPError with the given status code."""
    return HTTPError(
        url="https://example.com",
        code=code,
        msg=f"HTTP {code}",
        hdrs=Message(),
        fp=None,
    )


# -------------------------------------------------------------------
# Success cases
# -------------------------------------------------------------------


class TestSuccess:
    """Tests for successful requests."""

    def test_succeeds_first_try(self) -> None:
        """Returns response on first attempt."""
        resp = _mock_response()
        with patch(_URLOPEN, return_value=resp) as mock:
            result = urlopen_with_retry("https://example.com")
        assert result is resp
        mock.assert_called_once()

    def test_timeout_forwarded(self) -> None:
        """Custom timeout is passed to urlopen."""
        resp = _mock_response()
        with patch(_URLOPEN, return_value=resp) as mock:
            urlopen_with_retry("https://example.com", timeout=60)
        mock.assert_called_once_with("https://example.com", timeout=60)


# -------------------------------------------------------------------
# Retry on connection errors
# -------------------------------------------------------------------


class TestConnectionRetry:
    """Tests for retry on URLError (connection failures)."""

    def test_retries_on_connection_error(self) -> None:
        """Retries and succeeds after transient connection error."""
        resp = _mock_response()
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP) as mock_sleep,
        ):
            mock_urlopen.side_effect = [URLError("timeout"), resp]
            result = urlopen_with_retry(
                "https://example.com", max_retries=2, backoff_base=1.0
            )
        assert result is resp
        assert mock_urlopen.call_count == 2
        mock_sleep.assert_called_once_with(1.0)

    def test_exhausts_retries_on_connection_error(self) -> None:
        """Raises URLError after exhausting all retries."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP),
            pytest.raises(URLError, match="persistent"),
        ):
            mock_urlopen.side_effect = [
                URLError("fail1"),
                URLError("fail2"),
                URLError("persistent"),
            ]
            urlopen_with_retry(
                "https://example.com", max_retries=2, backoff_base=0.1
            )

    def test_no_sleep_after_last_attempt(self) -> None:
        """Does not sleep after the final failed attempt."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP) as mock_sleep,
            pytest.raises(URLError),
        ):
            mock_urlopen.side_effect = [URLError("a"), URLError("b")]
            urlopen_with_retry(
                "https://example.com", max_retries=1, backoff_base=1.0
            )
        # Only 1 sleep (between attempt 1 and 2), not after attempt 2
        mock_sleep.assert_called_once()


# -------------------------------------------------------------------
# Retry on HTTP errors
# -------------------------------------------------------------------


class TestHTTPRetry:
    """Tests for retry on retryable HTTP status codes."""

    @pytest.mark.parametrize("status", sorted(_RETRYABLE_STATUS_CODES))
    def test_retries_on_retryable_status(self, status: int) -> None:
        """Retries on each retryable HTTP status code."""
        resp = _mock_response()
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP),
        ):
            mock_urlopen.side_effect = [_http_error(status), resp]
            result = urlopen_with_retry(
                "https://example.com", max_retries=1, backoff_base=0.1
            )
        assert result is resp

    def test_does_not_retry_client_error(self) -> None:
        """Does not retry non-retryable client errors (e.g. 404)."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            pytest.raises(HTTPError) as exc_info,
        ):
            mock_urlopen.side_effect = _http_error(404)
            urlopen_with_retry("https://example.com", max_retries=3)
        assert exc_info.value.code == 404
        mock_urlopen.assert_called_once()

    def test_does_not_retry_403(self) -> None:
        """Does not retry 403 Forbidden."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            pytest.raises(HTTPError) as exc_info,
        ):
            mock_urlopen.side_effect = _http_error(403)
            urlopen_with_retry("https://example.com", max_retries=3)
        assert exc_info.value.code == 403
        mock_urlopen.assert_called_once()

    def test_exhausts_retries_on_server_error(self) -> None:
        """Raises HTTPError after exhausting retries on 503."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP),
            pytest.raises(HTTPError) as exc_info,
        ):
            mock_urlopen.side_effect = [
                _http_error(503),
                _http_error(503),
                _http_error(503),
            ]
            urlopen_with_retry(
                "https://example.com", max_retries=2, backoff_base=0.1
            )
        assert exc_info.value.code == 503


# -------------------------------------------------------------------
# Backoff behavior
# -------------------------------------------------------------------


class TestBackoff:
    """Tests for exponential backoff timing."""

    def test_exponential_backoff_delays(self) -> None:
        """Sleep durations follow exponential backoff."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP) as mock_sleep,
            pytest.raises(URLError),
        ):
            mock_urlopen.side_effect = [
                URLError("a"),
                URLError("b"),
                URLError("c"),
                URLError("d"),
            ]
            urlopen_with_retry(
                "https://example.com", max_retries=3, backoff_base=2.0
            )
        # Delays: 2*2^0=2, 2*2^1=4, 2*2^2=8
        assert mock_sleep.call_args_list == [
            ((2.0,),),
            ((4.0,),),
            ((8.0,),),
        ]

    def test_backoff_capped_at_max(self) -> None:
        """Backoff delay is capped at backoff_max."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP) as mock_sleep,
            pytest.raises(URLError),
        ):
            mock_urlopen.side_effect = [
                URLError("a"),
                URLError("b"),
                URLError("c"),
            ]
            urlopen_with_retry(
                "https://example.com",
                max_retries=2,
                backoff_base=10.0,
                backoff_max=15.0,
            )
        # Delays: min(10*2^0, 15)=10, min(10*2^1, 15)=15
        assert mock_sleep.call_args_list == [
            ((10.0,),),
            ((15.0,),),
        ]

    def test_zero_retries_no_sleep(self) -> None:
        """No sleep when max_retries=0 (single attempt)."""
        with (
            patch(_URLOPEN) as mock_urlopen,
            patch(_SLEEP) as mock_sleep,
            pytest.raises(URLError),
        ):
            mock_urlopen.side_effect = URLError("fail")
            urlopen_with_retry(
                "https://example.com", max_retries=0, backoff_base=1.0
            )
        mock_sleep.assert_not_called()
        mock_urlopen.assert_called_once()


# -------------------------------------------------------------------
# Retryable status codes constant
# -------------------------------------------------------------------


class TestRetryableStatusCodes:
    """Tests for the _RETRYABLE_STATUS_CODES constant."""

    def test_contains_expected_codes(self) -> None:
        """Retryable set contains 429 and 5xx codes."""
        assert 429 in _RETRYABLE_STATUS_CODES
        assert 500 in _RETRYABLE_STATUS_CODES
        assert 502 in _RETRYABLE_STATUS_CODES
        assert 503 in _RETRYABLE_STATUS_CODES
        assert 504 in _RETRYABLE_STATUS_CODES

    def test_excludes_client_errors(self) -> None:
        """Client errors (except 429) are not retryable."""
        assert 400 not in _RETRYABLE_STATUS_CODES
        assert 401 not in _RETRYABLE_STATUS_CODES
        assert 403 not in _RETRYABLE_STATUS_CODES
        assert 404 not in _RETRYABLE_STATUS_CODES
