# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for email gateway tests."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mock_sandbox():
    """Mock Sandbox for email gateway tests.

    The sandbox calls podman which isn't available in test
    environments. Provide a mock that returns sensible defaults.
    """
    mock_sandbox_class = MagicMock()
    mock_sandbox_instance = MagicMock()
    mock_sandbox_class.return_value = mock_sandbox_instance
    with patch("lib.gateway.service.gateway.Sandbox", mock_sandbox_class):
        yield


@pytest.fixture
def email_config(tmp_path: Path, master_repo: Path):
    """Test email service configuration."""
    from lib.gateway.config import RepoServerConfig

    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    return RepoServerConfig(
        repo_id="test",
        imap_server="imap.example.com",
        imap_port=993,
        smtp_server="smtp.example.com",
        smtp_port=587,
        email_username="test@example.com",
        email_password="test_password",
        email_from="Test Service <test@example.com>",
        authorized_senders=["authorized@example.com"],
        trusted_authserv_id="mx.example.com",
        git_repo_url=str(master_repo),
        storage_dir=storage_dir,
    )


@pytest.fixture
def microsoft_oauth2_email_config(tmp_path: Path, master_repo: Path):
    """Test email config with Microsoft OAuth2 credentials.

    Mocks MSAL ConfidentialClientApplication to prevent network requests
    during tests.
    """
    from lib.gateway.config import RepoServerConfig

    storage_dir = tmp_path / "storage"
    storage_dir.mkdir()

    with patch("lib.gateway.microsoft_oauth2.ConfidentialClientApplication"):
        yield RepoServerConfig(
            repo_id="test",
            imap_server="outlook.office365.com",
            imap_port=993,
            smtp_server="smtp.office365.com",
            smtp_port=587,
            email_username="test@company.com",
            email_password="",
            email_from="Test Service <test@company.com>",
            authorized_senders=["authorized@company.com"],
            trusted_authserv_id="mx.company.com",
            git_repo_url=str(master_repo),
            storage_dir=storage_dir,
            microsoft_oauth2_tenant_id="test-tenant-id",
            microsoft_oauth2_client_id="test-client-id",
            microsoft_oauth2_client_secret="test-client-secret",
        )
