# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared fixtures for gateway service tests."""

from email.message import Message
from email.parser import BytesParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from lib.gateway.service import EmailGatewayService


def make_message(
    *,
    sender: str = "user@example.com",
    to: str = "claude@example.com",
    subject: str = "Test",
    body: str = "Hello",
    message_id: str = "<msg1@example.com>",
    references: str = "",
    auth_results: str = "mx.google.com; dmarc=pass; spf=pass",
) -> Message:
    """Build a simple email Message for testing."""
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
    return BytesParser().parsebytes(raw.encode())


def update_global(svc: Any, **overrides: Any) -> None:
    """Update global config with new values (frozen dataclass)."""
    for key, value in overrides.items():
        object.__setattr__(svc.global_config, key, value)


def update_repo(handler: Any, **overrides: Any) -> None:
    """Update repo config with new values (frozen dataclass)."""
    for key, value in overrides.items():
        object.__setattr__(handler.config, key, value)


def make_service(
    email_config: Any, tmp_path: Path, **config_overrides: Any
) -> tuple[Any, Any]:
    """Create an EmailGatewayService with all external deps mocked.

    Returns:
        Tuple of (service, handler) where handler is svc.repo_handlers["test"].
    """
    from dataclasses import fields

    from lib.gateway.config import GlobalConfig, ServerConfig

    # Split overrides into global vs per-repo
    global_field_names = {f.name for f in fields(GlobalConfig)}
    global_overrides = {
        k: v for k, v in config_overrides.items() if k in global_field_names
    }
    repo_overrides = {
        k: v for k, v in config_overrides.items() if k not in global_field_names
    }

    # Build GlobalConfig with overrides
    global_kwargs: dict[str, Any] = {"dashboard_enabled": False}
    global_kwargs.update(global_overrides)
    global_config = GlobalConfig(**global_kwargs)  # type: ignore[arg-type]

    # Build ServerConfig
    server_config = ServerConfig(
        global_config=global_config, repos={"test": email_config}
    )

    with (
        patch("lib.gateway.service.repo_handler.EmailListener"),
        patch("lib.gateway.service.repo_handler.EmailResponder"),
        patch("lib.gateway.service.repo_handler.SenderAuthenticator"),
        patch("lib.gateway.service.repo_handler.SenderAuthorizer"),
        patch("lib.gateway.service.repo_handler.ConversationManager"),
        patch("lib.gateway.service.gateway.UpdateLock"),
        patch("lib.gateway.service.gateway.capture_version_info") as mock_ver,
        patch("lib.gateway.service.gateway.TaskTracker"),
        patch("lib.gateway.service.gateway.Sandbox"),
        patch(
            "lib.gateway.service.gateway.get_system_resolver",
            return_value="127.0.0.53",
        ),
    ):
        mock_ver.return_value = MagicMock(
            git_sha="abc1234", worktree_clean=True
        )
        svc = EmailGatewayService(server_config, repo_root=tmp_path)

    handler = svc.repo_handlers["test"]

    # Apply repo-level overrides
    for key, value in repo_overrides.items():
        object.__setattr__(handler.config, key, value)

    return svc, handler


@pytest.fixture
def service_and_handler(email_config: Any, tmp_path: Path) -> tuple[Any, Any]:
    """Fixture providing a service and handler tuple."""
    return make_service(email_config, tmp_path)
