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
from collections.abc import Iterator
from unittest.mock import MagicMock


def _install_mitmproxy_mock() -> None:
    """Install a mock ``mitmproxy`` package into sys.modules.

    This allows ``from mitmproxy import ctx, http`` to succeed outside
    the container.  Must be called before any import of proxy_filter.
    """
    if "mitmproxy" in sys.modules:
        return  # Already installed (or real mitmproxy available)

    mitmproxy_mod = types.ModuleType("mitmproxy")
    mitmproxy_mod.ctx = MagicMock()  # ty:ignore[unresolved-attribute]

    # Build a minimal http module with HTTPFlow and Response.make
    http_mod = types.ModuleType("mitmproxy.http")

    class _MockHeaders:
        """Minimal mitmproxy Headers stand-in (multidict-like).

        Supports duplicate header names, matching real mitmproxy behavior:
        - ``__getitem__`` returns the **first** value for a name
        - ``__setitem__`` updates the **first** matching entry (or appends)
        - ``__delitem__`` removes **all** entries for a name
        - iteration yields all names **including duplicates**
        """

        def __init__(
            self,
            data: dict | list[tuple[str, str]] | None = None,
        ) -> None:
            self._entries: list[tuple[str, str]] = []
            if isinstance(data, dict):
                for k, v in data.items():
                    self._entries.append((k, v))
            elif isinstance(data, list):
                for k, v in data:
                    self._entries.append((k, v))

        def __getitem__(self, name: str) -> str:
            name_lower = name.lower()
            for k, v in self._entries:
                if k.lower() == name_lower:
                    return v
            raise KeyError(name)

        def __setitem__(self, name: str, value: str) -> None:
            name_lower = name.lower()
            for i, (k, _v) in enumerate(self._entries):
                if k.lower() == name_lower:
                    self._entries[i] = (k, value)
                    return
            self._entries.append((name, value))

        def __delitem__(self, name: str) -> None:
            name_lower = name.lower()
            self._entries = [
                (k, v) for k, v in self._entries if k.lower() != name_lower
            ]

        def __contains__(self, name: object) -> bool:
            if not isinstance(name, str):
                return False
            name_lower = name.lower()
            return any(k.lower() == name_lower for k, _v in self._entries)

        def __iter__(self) -> Iterator[str]:
            for k, _v in self._entries:
                yield k

        def __len__(self) -> int:
            return len(self._entries)

        def __repr__(self) -> str:
            return f"_MockHeaders({self._entries!r})"

        def keys(self) -> list[str]:
            return [k for k, _v in self._entries]

        def items(self) -> list[tuple[str, str]]:
            return list(self._entries)

        def get(self, name: str, default: str | None = None) -> str | None:
            try:
                return self[name]
            except KeyError:
                return default

        def pop(self, name: str, *args: str | None) -> str | None:
            name_lower = name.lower()
            for i, (k, v) in enumerate(self._entries):
                if k.lower() == name_lower:
                    del self._entries[i]
                    return v
            if args:
                return args[0]
            raise KeyError(name)

        @property
        def fields(self) -> list[tuple[bytes, bytes]]:
            return [(k.encode(), v.encode()) for k, v in self._entries]

        @fields.setter
        def fields(self, value: list[tuple[bytes, bytes]]) -> None:
            self._entries = [
                (
                    k.decode() if isinstance(k, bytes) else k,
                    v.decode() if isinstance(v, bytes) else v,
                )
                for k, v in value
            ]

    class _MockRequest:
        """Minimal mitmproxy Request stand-in."""

        def __init__(
            self,
            *,
            method: str = "GET",
            url: str = "https://example.com/",
            host: str = "example.com",
            url_host: str | None = None,
            path: str = "/",
            headers: dict | None = None,
            stream: bool = False,
            content: bytes = b"",
        ) -> None:
            self.method = method
            self.url = url
            self.host = url_host if url_host is not None else host
            self.pretty_host = host
            self.pretty_url = url
            self.path = path
            self.port = 443
            self.headers = _MockHeaders(headers if headers is not None else {})
            self.stream = stream
            self.content = content

        def get_content(self) -> bytes:
            return self.content

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
            resp._content = content  # ty:ignore[unresolved-attribute]
            resp._headers = headers  # ty:ignore[unresolved-attribute]
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

    http_mod.Headers = _MockHeaders  # ty:ignore[unresolved-attribute]
    http_mod.HTTPFlow = _MockHTTPFlow  # ty:ignore[unresolved-attribute]
    http_mod.Response = _MockResponse  # ty:ignore[unresolved-attribute]

    sys.modules["mitmproxy"] = mitmproxy_mod
    sys.modules["mitmproxy.http"] = http_mod

    # Expose mock helpers for test files
    mitmproxy_mod.http = http_mod  # ty:ignore[unresolved-attribute]
    http_mod.MockRequest = _MockRequest  # ty:ignore[unresolved-attribute]
    http_mod.MockResponse = _MockResponse  # ty:ignore[unresolved-attribute]
    http_mod.MockHTTPFlow = _MockHTTPFlow  # ty:ignore[unresolved-attribute]
    http_mod.MockError = _MockError  # ty:ignore[unresolved-attribute]
    http_mod.MockHeaders = _MockHeaders  # ty:ignore[unresolved-attribute]


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
