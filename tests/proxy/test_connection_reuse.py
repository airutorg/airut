# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for connection_reuse — no reuse of failed upstream connections.

mitmproxy itself is mocked (see ``conftest.py``), so these tests patch the
mock ``GetHttpConnection``, whose ``connection_spec_matches`` follows
mitmproxy's contract.  Each test patches a fresh subclass, because the
patch mutates the class it is applied to.
"""

import re
from importlib.resources import files
from types import SimpleNamespace
from typing import Protocol

import connection_reuse  # ty:ignore[import-not-found]
import pytest


# mitmproxy release whose HttpLayer.get_connection was checked against the
# patch.  Update only after re-checking connection_reuse.py as described in
# workflows/dependency-updates.md.
VERIFIED_MITMPROXY_VERSION = "12.3.1"

ADDRESS = ("api.example.com", 443)


class _Command(Protocol):
    """The parts of GetHttpConnection the tests use."""

    def __init__(self, address: tuple[str, int], tls: bool) -> None: ...

    def connection_spec_matches(self, connection: SimpleNamespace) -> bool: ...


def _server(
    *, address: tuple[str, int] = ADDRESS, error: str | None = None
) -> SimpleNamespace:
    """Build a stand-in for a mitmproxy upstream Server connection."""
    return SimpleNamespace(
        address=address,
        tls=True,
        via=None,
        transport_protocol="tcp",
        error=error,
    )


@pytest.fixture
def command_cls(monkeypatch: pytest.MonkeyPatch) -> type[_Command]:
    """Fresh subclass of the mock GetHttpConnection as the patch target."""
    base = connection_reuse.GetHttpConnection
    assert not hasattr(
        base.connection_spec_matches, connection_reuse._PATCH_MARKER
    ), "the shared mock must stay unpatched"

    class GetHttpConnection(base):
        pass

    monkeypatch.setattr(
        connection_reuse, "GetHttpConnection", GetHttpConnection
    )
    return GetHttpConnection


class TestSkipFailedConnections:
    """Tests for skip_failed_connections()."""

    def test_failed_connection_does_not_match(
        self, command_cls: type[_Command]
    ) -> None:
        """A connection that failed to open never matches a request."""
        connection_reuse.skip_failed_connections()

        command = command_cls(ADDRESS, tls=True)
        for error in (
            "Connect call failed",
            "[Errno -2] Name or service not known",
            "connection closed",  # TLS handshake closed by server
        ):
            assert not command.connection_spec_matches(_server(error=error))

    def test_healthy_connection_still_matches(
        self, command_cls: type[_Command]
    ) -> None:
        """A connection without an error is still reused."""
        connection_reuse.skip_failed_connections()

        command = command_cls(ADDRESS, tls=True)
        assert command.connection_spec_matches(_server())

    def test_other_upstream_still_does_not_match(
        self, command_cls: type[_Command]
    ) -> None:
        """The original matching rules still apply to healthy connections."""
        connection_reuse.skip_failed_connections()

        command = command_cls(ADDRESS, tls=True)
        assert not command.connection_spec_matches(
            _server(address=("other.example.com", 443))
        )

    def test_idempotent(self, command_cls: type[_Command]) -> None:
        """Applying the patch again (addon reload) does not wrap twice."""
        connection_reuse.skip_failed_connections()
        patched = command_cls.connection_spec_matches

        connection_reuse.skip_failed_connections()

        assert command_cls.connection_spec_matches is patched
        command = command_cls(ADDRESS, tls=True)
        assert command.connection_spec_matches(_server())
        assert not command.connection_spec_matches(_server(error="failed"))

    def test_missing_method_raises(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A mitmproxy without the patched method fails loudly."""
        monkeypatch.setattr(
            connection_reuse, "GetHttpConnection", type("Changed", (), {})
        )

        with pytest.raises(AttributeError):
            connection_reuse.skip_failed_connections()


def test_pinned_mitmproxy_is_verified() -> None:
    """The proxy ships the mitmproxy release the patch was checked against.

    The patch relies on mitmproxy internals that its mock cannot track.
    A mitmproxy bump fails here until connection_reuse.py is re-checked
    against the new release and VERIFIED_MITMPROXY_VERSION is updated.
    """
    requirements = (
        files("airut._bundled.proxy").joinpath("requirements.txt").read_text()
    )
    match = re.search(r"^mitmproxy==(\S+)", requirements, re.MULTILINE)
    assert match is not None
    assert match.group(1) == VERIFIED_MITMPROXY_VERSION
