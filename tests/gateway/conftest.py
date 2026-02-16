# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for email gateway tests."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mock_sandbox(tmp_path: Path):
    """Mock Sandbox and redirect XDG state for gateway tests.

    The sandbox calls podman which isn't available in test
    environments. Provide a mock that returns sensible defaults.

    Also redirects ``get_storage_dir()`` to use ``tmp_path`` so
    tests don't touch the real filesystem.
    """
    mock_sandbox_class = MagicMock()
    mock_sandbox_instance = MagicMock()
    mock_sandbox_class.return_value = mock_sandbox_instance
    storage_root = tmp_path / "state"
    storage_root.mkdir(exist_ok=True)
    with (
        patch("airut.gateway.service.gateway.Sandbox", mock_sandbox_class),
        patch(
            "airut.gateway.config.user_state_path",
            return_value=storage_root,
        ),
    ):
        yield


@pytest.fixture
def email_config(tmp_path: Path, master_repo: Path):
    """Test email service configuration."""
    from airut.gateway.config import EmailChannelConfig, RepoServerConfig

    return RepoServerConfig(
        repo_id="test",
        git_repo_url=str(master_repo),
        email=EmailChannelConfig(
            imap_server="imap.example.com",
            imap_port=993,
            smtp_server="smtp.example.com",
            smtp_port=587,
            username="test@example.com",
            password="test_password",
            from_address="Test Service <test@example.com>",
            authorized_senders=["authorized@example.com"],
            trusted_authserv_id="mx.example.com",
        ),
    )


@pytest.fixture
def microsoft_oauth2_email_config(tmp_path: Path, master_repo: Path):
    """Test email config with Microsoft OAuth2 credentials.

    Mocks MSAL ConfidentialClientApplication to prevent network requests
    during tests.
    """
    from airut.gateway.config import EmailChannelConfig, RepoServerConfig

    with patch(
        "airut.gateway.email.microsoft_oauth2.ConfidentialClientApplication"
    ):
        yield RepoServerConfig(
            repo_id="test",
            git_repo_url=str(master_repo),
            email=EmailChannelConfig(
                imap_server="outlook.office365.com",
                imap_port=993,
                smtp_server="smtp.office365.com",
                smtp_port=587,
                username="test@company.com",
                password="",
                from_address="Test Service <test@company.com>",
                authorized_senders=["authorized@company.com"],
                trusted_authserv_id="mx.company.com",
                microsoft_oauth2_tenant_id="test-tenant-id",
                microsoft_oauth2_client_id="test-client-id",
                microsoft_oauth2_client_secret="test-client-secret",
            ),
        )
