# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Keep mitmproxy from reusing upstream connections that failed to open.

mitmproxy's HTTP layer keeps every upstream connection it opens for a
client connection.  ``HttpLayer.get_connection`` gives a new request any
of them whose address, TLS flag, upstream proxy and transport match the
request, and answers the request with the connection's ``error`` if that
is set.  A connection that failed to open (unresolvable name, refused
connection, failed TLS handshake) keeps its error and stays in the set, so
every later request for the same upstream on that client connection gets
the first failure back without a new attempt, for as long as the client
connection lives (mitmproxy 12.3.1).  mitmproxy documents this as
intended: ``Connection.error`` signals that no new connections to the
endpoint should be attempted, for example after an untrusted certificate.

An HTTP/1 client is not affected because mitmproxy closes the client
connection after the error, and the client reconnects.  An HTTP/2 client
keeps the connection, so its retries can never succeed: ``curl --retry``
gets the same 502 on every try although the upstream is back.

``skip_failed_connections`` makes a failed connection never match a
request, so the request opens a new upstream connection.  Every attempt
goes through the same checks, so an upstream with an untrusted
certificate still fails each time.  The failed connection stays in the
HTTP layer's connection map, which still routes events that arrive for it
after the failure (such as the close that follows a failed TLS
handshake).  Like the closed connections mitmproxy already keeps there,
each failed attempt stays in the map until the client connection ends.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from mitmproxy.proxy.layers.http import GetHttpConnection


if TYPE_CHECKING:
    from mitmproxy.connection import Connection


_PATCH_MARKER = "_airut_skips_failed_connections"


def skip_failed_connections() -> None:
    """Patch mitmproxy so a failed upstream connection is never reused.

    Idempotent: mitmproxy re-executes the addon script on reload, but
    this module stays imported and the patch is applied only once.

    Raises:
        AttributeError: mitmproxy no longer has
            ``GetHttpConnection.connection_spec_matches``.  Raised at
            addon load, which makes mitmdump exit instead of running
            without the fix.
    """
    original = GetHttpConnection.connection_spec_matches
    if getattr(original, _PATCH_MARKER, False):
        return

    def connection_spec_matches(
        self: GetHttpConnection, connection: Connection
    ) -> bool:
        if connection.error:
            return False
        return original(self, connection)

    setattr(connection_spec_matches, _PATCH_MARKER, True)
    GetHttpConnection.connection_spec_matches = connection_spec_matches
