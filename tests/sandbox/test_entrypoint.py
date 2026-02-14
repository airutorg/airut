# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_entrypoint.py -- container entrypoint generation."""

from lib.sandbox._entrypoint import ENTRYPOINT_SCRIPT, get_entrypoint_content


class TestGetEntrypointContent:
    """Tests for get_entrypoint_content function."""

    def test_returns_bytes(self) -> None:
        """Returns bytes, not str."""
        content = get_entrypoint_content()
        assert isinstance(content, bytes)

    def test_utf8_encoded(self) -> None:
        """Content is valid UTF-8."""
        content = get_entrypoint_content()
        decoded = content.decode("utf-8")
        assert isinstance(decoded, str)

    def test_matches_script_constant(self) -> None:
        """Returned bytes match the ENTRYPOINT_SCRIPT constant."""
        content = get_entrypoint_content()
        assert content == ENTRYPOINT_SCRIPT.encode("utf-8")

    def test_starts_with_shebang(self) -> None:
        """Content starts with bash shebang."""
        content = get_entrypoint_content()
        assert content.startswith(b"#!/usr/bin/env bash")

    def test_contains_is_sandbox(self) -> None:
        """Content sets IS_SANDBOX environment variable."""
        content = get_entrypoint_content()
        assert b"IS_SANDBOX=1" in content

    def test_contains_ca_trust(self) -> None:
        """Content handles CA certificate trust."""
        content = get_entrypoint_content()
        assert b"update-ca-certificates" in content
        assert b"mitmproxy-ca.crt" in content

    def test_contains_exec_claude(self) -> None:
        """Content execs claude with arguments."""
        content = get_entrypoint_content()
        assert b'exec claude "$@"' in content

    def test_contains_set_euo_pipefail(self) -> None:
        """Content uses strict bash error handling."""
        content = get_entrypoint_content()
        assert b"set -euo pipefail" in content

    def test_idempotent(self) -> None:
        """Multiple calls return the same content."""
        c1 = get_entrypoint_content()
        c2 = get_entrypoint_content()
        assert c1 == c2
