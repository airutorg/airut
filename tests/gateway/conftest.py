# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Shared pytest fixtures for email gateway tests."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _mock_network_sandbox():
    """Disable network sandbox for email gateway tests.

    The network module calls podman which isn't available in test
    environments. Return empty args so executor tests run without it.
    """
    mock_pm_class = MagicMock()
    mock_pm_instance = MagicMock()
    mock_pm_instance.start_task_proxy.return_value = None
    mock_pm_class.return_value = mock_pm_instance
    with (
        patch("lib.container.executor.get_network_args", return_value=[]),
        patch("lib.gateway.service.gateway.ProxyManager", mock_pm_class),
    ):
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
