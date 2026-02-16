# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for proxy module tests.

Installs mitmproxy mocks so ``airut._bundled.proxy.proxy_filter`` can be
imported without the real mitmproxy package (which is only installed
inside the proxy container).
"""

import sys
import types
from unittest.mock import MagicMock


def _install_mitmproxy_mock() -> None:
    """Install a mock ``mitmproxy`` package into sys.modules.

    This allows ``from mitmproxy import ctx, http`` to succeed outside
    the container.  Must be called before any import of proxy_filter.
    """
    if "mitmproxy" in sys.modules:
        return  # Already installed (or real mitmproxy available)

    mitmproxy_mod = types.ModuleType("mitmproxy")
    mitmproxy_mod.ctx = MagicMock()  # type: ignore[attr-defined]

    # Build a minimal http module with HTTPFlow and Response.make
    http_mod = types.ModuleType("mitmproxy.http")

    class _MockHeaders(dict):
        """Minimal mitmproxy Headers stand-in (dict-like)."""

        @property
        def fields(self) -> list[tuple[bytes, bytes]]:
            return [(k.encode(), v.encode()) for k, v in self.items()]

    class _MockRequest:
        """Minimal mitmproxy Request stand-in."""

        def __init__(
            self,
            *,
            method: str = "GET",
            url: str = "https://example.com/",
            host: str = "example.com",
            path: str = "/",
            headers: dict | None = None,
            stream: bool = False,
            content: bytes = b"",
        ) -> None:
            self.method = method
            self.url = url
            self.pretty_host = host
            self.pretty_url = url
            self.path = path
            self.headers = _MockHeaders(headers or {})
            self.stream = stream
            self.content = content

    class _MockResponse:
        """Minimal mitmproxy Response stand-in."""

        def __init__(
            self,
            status_code: int = 200,
            content: bytes = b"",
        ) -> None:
            self.status_code = status_code
            self.content = content

        @staticmethod
        def make(
            status_code: int,
            content: str = "",
            headers: dict | None = None,
        ) -> "_MockResponse":
            resp = _MockResponse(status_code)
            resp._content = content  # type: ignore[attr-defined]
            resp._headers = headers  # type: ignore[attr-defined]
            return resp

    class _MockError:
        """Minimal mitmproxy Error stand-in."""

        def __init__(self, msg: str = "") -> None:
            self.msg = msg

    class _MockHTTPFlow:
        """Minimal mitmproxy HTTPFlow stand-in."""

        def __init__(
            self,
            request: _MockRequest | None = None,
            response: _MockResponse | None = None,
            error: _MockError | None = None,
        ) -> None:
            self.request = request or _MockRequest()
            self.response = response
            self.error = error
            self.metadata: dict = {}

    http_mod.HTTPFlow = _MockHTTPFlow  # type: ignore[attr-defined]
    http_mod.Response = _MockResponse  # type: ignore[attr-defined]

    sys.modules["mitmproxy"] = mitmproxy_mod
    sys.modules["mitmproxy.http"] = http_mod

    # Expose mock helpers for test files
    mitmproxy_mod.http = http_mod  # type: ignore[attr-defined]
    http_mod.MockRequest = _MockRequest  # type: ignore[attr-defined]
    http_mod.MockResponse = _MockResponse  # type: ignore[attr-defined]
    http_mod.MockHTTPFlow = _MockHTTPFlow  # type: ignore[attr-defined]
    http_mod.MockError = _MockError  # type: ignore[attr-defined]
    http_mod.MockHeaders = _MockHeaders  # type: ignore[attr-defined]


def _add_proxy_to_path() -> None:
    """Add ``airut/_bundled/proxy/``.

    to sys.path for bare ``import aws_signing``.
    Inside the container, ``aws_signing.py`` lives at ``/aws_signing.py``
    and is imported via bare ``from aws_signing import ...``.  In tests,
    ``airut/_bundled/proxy/`` must be on sys.path for that import to work.
    """
    from importlib.resources import files

    proxy_dir = str(files("airut._bundled.proxy"))
    if proxy_dir not in sys.path:
        sys.path.insert(0, proxy_dir)


# Run at import time (before any test collection touches proxy_filter)
_install_mitmproxy_mock()
_add_proxy_to_path()
