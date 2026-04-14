# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""HTTP utilities built on Python stdlib.

Provides :func:`urlopen_with_retry`, a thin wrapper around
:func:`urllib.request.urlopen` that adds exponential-backoff retry
for transient failures (connection errors, timeouts, 5xx responses).
"""

from __future__ import annotations

import http.client
import logging
import time
import urllib.error
import urllib.request


logger = logging.getLogger(__name__)

#: HTTP status codes considered transient and worth retrying.
_RETRYABLE_STATUS_CODES = frozenset({429, 500, 502, 503, 504})


def urlopen_with_retry(
    url: str,
    *,
    timeout: int = 30,
    max_retries: int = 3,
    backoff_base: float = 1.0,
    backoff_max: float = 30.0,
) -> http.client.HTTPResponse:
    """Open a URL with automatic retry on transient failures.

    Retries on connection errors (:class:`urllib.error.URLError` that
    are *not* HTTP errors), timeouts, and HTTP responses with status
    codes in :data:`_RETRYABLE_STATUS_CODES` (429, 5xx).

    Uses exponential backoff: ``backoff_base * 2^attempt`` seconds,
    capped at *backoff_max*.

    Args:
        url: URL to fetch.
        timeout: Per-request timeout in seconds.
        max_retries: Maximum number of retry attempts after the
            initial request.  Total attempts = 1 + max_retries.
        backoff_base: Base delay in seconds for exponential backoff.
        backoff_max: Maximum delay in seconds between retries.

    Returns:
        HTTP response (usable as context manager).

    Raises:
        urllib.error.URLError: If all attempts fail due to connection
            errors.
        urllib.error.HTTPError: If all attempts fail with a retryable
            HTTP status, or immediately for non-retryable HTTP errors.
    """
    last_error: urllib.error.URLError | None = None

    for attempt in range(1 + max_retries):
        try:
            return urllib.request.urlopen(url, timeout=timeout)
        except urllib.error.HTTPError as e:
            if e.code not in _RETRYABLE_STATUS_CODES:
                raise
            last_error = e
            logger.debug(
                "HTTP %d from %s (attempt %d/%d)",
                e.code,
                url,
                attempt + 1,
                1 + max_retries,
            )
        except urllib.error.URLError as e:
            last_error = e
            logger.debug(
                "Fetch failed for %s: %s (attempt %d/%d)",
                url,
                e,
                attempt + 1,
                1 + max_retries,
            )

        if attempt < max_retries:
            delay = min(backoff_base * (2**attempt), backoff_max)
            logger.debug("Retrying in %.1fs", delay)
            time.sleep(delay)

    assert last_error is not None
    raise last_error
