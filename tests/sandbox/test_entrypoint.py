# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_entrypoint.py -- container entrypoint generation."""

from airut.sandbox._entrypoint import (
    AGENT_ENTRYPOINT_SCRIPT,
    PASSTHROUGH_ENTRYPOINT_SCRIPT,
    get_entrypoint_content,
)


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
        """Returned bytes match the AGENT_ENTRYPOINT_SCRIPT constant."""
        content = get_entrypoint_content()
        assert content == AGENT_ENTRYPOINT_SCRIPT.encode("utf-8")

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


class TestPassthroughEntrypoint:
    """Tests for passthrough entrypoint variant."""

    def test_passthrough_returns_bytes(self) -> None:
        """Passthrough entrypoint returns bytes."""
        content = get_entrypoint_content(passthrough=True)
        assert isinstance(content, bytes)

    def test_passthrough_matches_constant(self) -> None:
        """Passthrough content matches PASSTHROUGH_ENTRYPOINT_SCRIPT."""
        content = get_entrypoint_content(passthrough=True)
        assert content == PASSTHROUGH_ENTRYPOINT_SCRIPT.encode("utf-8")

    def test_passthrough_starts_with_shebang(self) -> None:
        """Passthrough content starts with bash shebang."""
        content = get_entrypoint_content(passthrough=True)
        assert content.startswith(b"#!/usr/bin/env bash")

    def test_passthrough_contains_is_sandbox(self) -> None:
        """Passthrough content sets IS_SANDBOX."""
        content = get_entrypoint_content(passthrough=True)
        assert b"IS_SANDBOX=1" in content

    def test_passthrough_contains_ca_trust(self) -> None:
        """Passthrough content handles CA certificate trust."""
        content = get_entrypoint_content(passthrough=True)
        assert b"update-ca-certificates" in content
        assert b"mitmproxy-ca.crt" in content

    def test_passthrough_does_not_exec_claude(self) -> None:
        """Passthrough does NOT exec claude."""
        content = get_entrypoint_content(passthrough=True)
        assert b'exec claude "$@"' not in content

    def test_passthrough_execs_args(self) -> None:
        """Passthrough execs the command directly."""
        content = get_entrypoint_content(passthrough=True)
        assert b'exec "$@"' in content

    def test_passthrough_different_from_agent(self) -> None:
        """Agent and passthrough entrypoints are different."""
        agent = get_entrypoint_content(passthrough=False)
        passthrough = get_entrypoint_content(passthrough=True)
        assert agent != passthrough

    def test_passthrough_contains_set_euo_pipefail(self) -> None:
        """Passthrough content uses strict bash error handling."""
        content = get_entrypoint_content(passthrough=True)
        assert b"set -euo pipefail" in content
