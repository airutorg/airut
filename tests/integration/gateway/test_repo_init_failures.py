# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for graceful repo initialization failure handling.

Tests that the service handles repo initialization errors correctly:
1. IMAP connection failures (bad credentials, unreachable server)
2. Git clone failures (invalid URL, missing credentials)
3. Partial failures (some repos work, others fail)
4. Dashboard visibility of repo status
"""

import sys
import threading
from pathlib import Path

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from airut.dashboard.tracker import RepoStatus
from airut.gateway.config import (
    EmailChannelConfig,
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)

from .conftest import MOCK_CONTAINER_COMMAND
from .environment import IntegrationEnvironment, create_test_repo


class TestImapConnectionFailures:
    """Test handling of IMAP connection failures during repo init."""

    def test_invalid_imap_port_fails_gracefully(
        self,
        tmp_path: Path,
    ) -> None:
        """Repo with no IMAP server listening is marked as failed."""
        # Create a valid environment first
        master_repo = create_test_repo(tmp_path / "master_repo")
        # Infrastructure files
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir()
        (docker_dir / "airut-entrypoint.sh").write_text(
            '#!/usr/bin/env bash\nexec claude "$@"\n'
        )
        proxy_dir = tmp_path / "proxy"
        proxy_dir.mkdir()
        (proxy_dir / "proxy.dockerfile").write_text("FROM scratch\n")

        # Create config pointing to a port with nothing listening
        # Port 9999 is typically unused
        global_config = GlobalConfig(
            dashboard_enabled=False,
            container_command=MOCK_CONTAINER_COMMAND,
        )
        repo_config = RepoServerConfig(
            repo_id="test",
            git_repo_url=str(master_repo),
            channels={
                "email": EmailChannelConfig(
                    imap_server="127.0.0.1",
                    imap_port=9999,  # No server listening on this port
                    smtp_server="127.0.0.1",
                    smtp_port=25,
                    username="test",
                    password="test",
                    from_address="test@test.local",
                    authorized_senders=["user@test.local"],
                    trusted_authserv_id="test.local",
                    use_imap_idle=False,
                    poll_interval_seconds=1,
                )
            },
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"test": repo_config},
        )

        from airut.gateway.service import GatewayService

        service = GatewayService(config, repo_root=tmp_path)

        # Starting should fail since all repos fail
        with pytest.raises(RuntimeError, match="All 1 repo"):
            service.start()

        # Repo should be marked as failed with error details
        repo_states = {r.repo_id: r for r in service._repos_store.get().value}
        assert len(repo_states) == 1
        assert repo_states["test"].status == RepoStatus.FAILED
        assert repo_states["test"].error_message is not None
        # Should mention connection or socket error
        error_msg = repo_states["test"].error_message.lower()
        assert (
            "connect" in error_msg
            or "refused" in error_msg
            or "error" in error_msg
        )

    def test_connection_refused_imap_server_fails_gracefully(
        self,
        tmp_path: Path,
    ) -> None:
        """Repo with IMAP connection refused is marked as failed."""
        master_repo = create_test_repo(tmp_path / "master_repo")
        # Infrastructure files
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir()
        (docker_dir / "airut-entrypoint.sh").write_text(
            '#!/usr/bin/env bash\nexec claude "$@"\n'
        )
        proxy_dir = tmp_path / "proxy"
        proxy_dir.mkdir()
        (proxy_dir / "proxy.dockerfile").write_text("FROM scratch\n")

        global_config = GlobalConfig(
            dashboard_enabled=False,
            container_command=MOCK_CONTAINER_COMMAND,
        )
        repo_config = RepoServerConfig(
            repo_id="unreachable",
            git_repo_url=str(master_repo),
            channels={
                "email": EmailChannelConfig(
                    imap_server="127.0.0.1",  # Refused on port 1
                    imap_port=1,  # Privileged port - immediate refusal
                    smtp_server="127.0.0.1",
                    smtp_port=25,
                    username="test",
                    password="test",
                    from_address="test@test.local",
                    authorized_senders=["user@test.local"],
                    trusted_authserv_id="test.local",
                    use_imap_idle=False,
                    poll_interval_seconds=1,
                )
            },
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"unreachable": repo_config},
        )

        from airut.gateway.service import GatewayService

        service = GatewayService(config, repo_root=tmp_path)

        # Starting should fail
        with pytest.raises(RuntimeError, match="All 1 repo"):
            service.start()

        repo_states = {r.repo_id: r for r in service._repos_store.get().value}
        assert repo_states["unreachable"].status == RepoStatus.FAILED


class TestGitCloneFailures:
    """Test handling of git clone failures during repo init."""

    def test_invalid_git_url_fails_gracefully(
        self,
        tmp_path: Path,
    ) -> None:
        """Repo with invalid git URL is marked as failed."""
        # Infrastructure files
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir()
        (docker_dir / "airut-entrypoint.sh").write_text(
            '#!/usr/bin/env bash\nexec claude "$@"\n'
        )
        proxy_dir = tmp_path / "proxy"
        proxy_dir.mkdir()
        (proxy_dir / "proxy.dockerfile").write_text("FROM scratch\n")

        global_config = GlobalConfig(
            dashboard_enabled=False,
            container_command=MOCK_CONTAINER_COMMAND,
        )
        repo_config = RepoServerConfig(
            repo_id="bad-git",
            git_repo_url="/nonexistent/path/that/does/not/exist",
            channels={
                "email": EmailChannelConfig(
                    imap_server="127.0.0.1",
                    imap_port=9999,  # No server listening
                    smtp_server="127.0.0.1",
                    smtp_port=25,
                    username="test",
                    password="test",
                    from_address="test@test.local",
                    authorized_senders=["user@test.local"],
                    trusted_authserv_id="test.local",
                    use_imap_idle=False,
                    poll_interval_seconds=1,
                )
            },
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"bad-git": repo_config},
        )

        from airut.gateway.service import GatewayService

        service = GatewayService(config, repo_root=tmp_path)

        with pytest.raises(RuntimeError, match="All 1 repo"):
            service.start()

        repo_states = {r.repo_id: r for r in service._repos_store.get().value}
        assert repo_states["bad-git"].status == RepoStatus.FAILED
        # Error should mention git or mirror
        error_msg = repo_states["bad-git"].error_message or ""
        assert "mirror" in error_msg.lower() or "git" in error_msg.lower()


class TestPartialFailures:
    """Test handling when some repos succeed and others fail."""

    def test_partial_failure_continues_with_working_repos(
        self,
        tmp_path: Path,
        create_email,
    ) -> None:
        """Service continues when some repos fail but others succeed."""
        from .conftest import get_message_text

        # Create a working environment
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["working", "broken"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Sabotage the 'broken' repo by breaking its git mirror URL
            broken_config = env.config.repos["broken"]
            object.__setattr__(
                broken_config,
                "git_repo_url",
                "/nonexistent/broken/repo",
            )

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            # Give service time to initialize
            import time

            time.sleep(2)

            try:
                # Check repo states
                repo_states = {
                    r.repo_id: r for r in service._repos_store.get().value
                }
                assert len(repo_states) == 2

                # Working repo should be live
                assert repo_states["working"].status == RepoStatus.LIVE

                # Broken repo should be failed
                assert repo_states["broken"].status == RepoStatus.FAILED
                assert repo_states["broken"].error_message is not None

                # Service should still process emails for working repo
                mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Working repo response"),
    generate_result_event(session_id, "Done"),
]
"""
                msg = create_email(
                    subject="Test working repo",
                    body=mock_code,
                    recipient="working@test.local",
                )
                env.email_server.inject_message_to("working", msg)

                response = env.email_server.wait_for_sent(
                    lambda m: (
                        "working repo response" in get_message_text(m).lower()
                    ),
                    timeout=15.0,
                )
                assert response is not None, (
                    "Should receive response from working repo"
                )

            finally:
                service.stop()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()


class TestDashboardRepoStatus:
    """Test dashboard visibility of repo initialization status."""

    def test_dashboard_shows_repo_status(
        self,
        tmp_path: Path,
    ) -> None:
        """Dashboard includes repo status in health endpoint."""
        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["healthy", "sick"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Enable dashboard for this test
            object.__setattr__(
                env.config.global_config,
                "dashboard_enabled",
                True,
            )

            # Sabotage one repo
            sick_config = env.config.repos["sick"]
            object.__setattr__(
                sick_config,
                "git_repo_url",
                "/nonexistent/sick/repo",
            )

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            import time

            time.sleep(2)

            try:
                # Check dashboard is running and service has repo states
                assert service.dashboard is not None
                repo_states = list(service._repos_store.get().value)
                assert len(repo_states) == 2

                # Verify health endpoint would show correct status
                live_count = sum(
                    1 for r in repo_states if r.status == RepoStatus.LIVE
                )
                failed_count = sum(
                    1 for r in repo_states if r.status == RepoStatus.FAILED
                )
                assert live_count == 1
                assert failed_count == 1

            finally:
                service.stop()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_api_repos_endpoint_returns_status(
        self,
        tmp_path: Path,
    ) -> None:
        """The /api/repos endpoint returns repo status information."""
        import json

        from werkzeug.test import Client

        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["user@test.local"],
            dashboard_enabled=True,
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            import time

            time.sleep(2)

            try:
                assert service.dashboard is not None
                client = Client(service.dashboard._wsgi_app)

                # Check /api/repos endpoint
                response = client.get("/api/repos")
                assert response.status_code == 200

                data = json.loads(response.get_data(as_text=True))
                assert len(data) == 1
                assert data[0]["repo_id"] == "test"
                assert data[0]["status"] == "live"

                # Check /api/health includes repo info
                health_resp = client.get("/api/health")
                assert health_resp.status_code == 200

                health_data = json.loads(health_resp.get_data(as_text=True))
                assert health_data["status"] == "ok"
                assert health_data["repos"]["live"] == 1
                assert health_data["repos"]["failed"] == 0

            finally:
                service.stop()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()
