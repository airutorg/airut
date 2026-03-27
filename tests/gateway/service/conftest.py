# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for gateway service tests."""

import threading
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from airut.gateway.channel import RawMessage
from airut.gateway.config import RepoServerConfig
from airut.gateway.service import GatewayService
from airut.gateway.service.repo_handler import RepoHandler
from airut.sandbox.types import ResourceLimits


class InterruptEvent(threading.Event):
    """Event whose bare ``wait()`` raises ``KeyboardInterrupt``.

    Useful for tests that need to exit the ``shutdown_event.wait()``
    call in ``GatewayService.start()`` without affecting other threads
    that call ``wait(timeout=N)``.
    """

    def wait(self, timeout=None):
        if timeout is None:
            raise KeyboardInterrupt
        return super().wait(timeout)


def make_message(
    *,
    sender: str = "user@example.com",
    to: str = "claude@example.com",
    subject: str = "Test",
    body: str = "Hello",
    message_id: str = "<msg1@example.com>",
    references: str = "",
    auth_results: str = "mx.google.com; dmarc=pass; spf=pass",
) -> RawMessage:
    """Build a RawMessage wrapping an email Message for testing."""
    raw = (
        f"From: {sender}\r\n"
        f"To: {to}\r\n"
        f"Subject: {subject}\r\n"
        f"Message-ID: {message_id}\r\n"
    )
    if references:
        raw += f"References: {references}\r\n"
    if auth_results:
        raw += f"Authentication-Results: {auth_results}\r\n"
    raw += f"\r\n{body}"
    email_msg = BytesParser().parsebytes(raw.encode())
    return RawMessage(sender=sender, content=email_msg, display_title=subject)


def update_global(
    svc: GatewayService, **overrides: bool | int | str | None
) -> None:
    """Update global config with new values (frozen dataclass)."""
    for key, value in overrides.items():
        object.__setattr__(svc.global_config, key, value)


_EMAIL_FIELDS = {
    "imap_server",
    "imap_port",
    "smtp_server",
    "smtp_port",
    "username",
    "password",
    "from_address",
    "authorized_senders",
    "trusted_authserv_id",
    "poll_interval_seconds",
    "use_imap_idle",
    "idle_reconnect_interval_seconds",
    "smtp_require_auth",
    "microsoft_internal_auth_fallback",
    "microsoft_oauth2_tenant_id",
    "microsoft_oauth2_client_id",
    "microsoft_oauth2_client_secret",
}


def update_repo(
    handler: RepoHandler,
    **overrides: bool | int | str | ResourceLimits | None,
) -> None:
    """Update repo config with new values (frozen dataclass)."""
    for key, value in overrides.items():
        if key in _EMAIL_FIELDS:
            object.__setattr__(handler.config.channels["email"], key, value)
        else:
            object.__setattr__(handler.config, key, value)


def make_service(
    email_config: RepoServerConfig,
    tmp_path: Path,
    **config_overrides: bool | int | str | None,
) -> tuple[Any, Any]:
    """Create a GatewayService with all external deps mocked.

    Returns ``Any`` because the returned GatewayService and RepoHandler
    have internal attributes (tracker, sandbox, adapters,
    conversation_manager) replaced with MagicMock.  Tests access both
    the real interface and mock attributes (.return_value, .side_effect,
    .assert_called_*), which no single static type can express.

    Returns:
        Tuple of (service, handler) where handler is
        svc.repo_handlers["test"].
    """
    from dataclasses import fields

    from airut.gateway.config import GlobalConfig, ServerConfig

    # Split overrides into global vs per-repo
    global_field_names = {f.name for f in fields(GlobalConfig)}
    global_overrides = {
        k: v for k, v in config_overrides.items() if k in global_field_names
    }
    repo_overrides = {
        k: v for k, v in config_overrides.items() if k not in global_field_names
    }

    # Build GlobalConfig with overrides
    # Any: dict unpacked into GlobalConfig whose params have
    # incompatible types (bool, int, str, None).
    global_kwargs: dict[str, Any] = {"dashboard_enabled": False}
    global_kwargs.update(global_overrides)
    global_config = GlobalConfig(**global_kwargs)

    # Build ServerConfig
    server_config = ServerConfig(
        global_config=global_config, repos={"test": email_config}
    )

    with (
        patch(
            "airut.gateway.service.repo_handler.create_adapters"
        ) as mock_create,
        patch("airut.gateway.service.repo_handler.ConversationManager"),
        patch("airut.gateway.service.gateway.capture_version_info") as mock_ver,
        patch("airut.gateway.service.gateway.TaskTracker"),
        patch("airut.gateway.service.gateway.Sandbox"),
        patch("airut.gateway.service.gateway.ClaudeBinaryCache"),
        patch(
            "airut.gateway.service.gateway.get_system_resolver",
            return_value="127.0.0.53",
        ),
    ):
        mock_adapter = MagicMock()
        mock_create.return_value = {"email": mock_adapter}
        mock_ver.return_value = (MagicMock(git_sha="abc1234"), MagicMock())
        svc = GatewayService(server_config, repo_root=tmp_path)

    # Configure claude_binary_cache mock to return a valid (path, version).
    # claude_binary_cache is a MagicMock (patched above), but ty sees the
    # declared type.
    svc.claude_binary_cache.ensure.return_value = (  # type: ignore[union-attr]
        Path("/fake/claude"),
        "1.0.0",
    )

    handler = svc.repo_handlers["test"]

    # Apply repo-level overrides
    for key, value in repo_overrides.items():
        object.__setattr__(handler.config, key, value)

    return svc, handler


@pytest.fixture
def service_and_handler(
    email_config: RepoServerConfig, tmp_path: Path
) -> tuple[Any, Any]:
    """Fixture providing a service and handler tuple.

    Returns ``Any`` — see ``make_service`` docstring.
    """
    return make_service(email_config, tmp_path)
