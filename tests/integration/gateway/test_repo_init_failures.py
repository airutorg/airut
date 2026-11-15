# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for graceful repo initialization failure handling.

Tests that the service handles repo initialization errors correctly:
1. IMAP failures (a rejected login fails the repo; an unreachable server
   starts it degraded, retrying in the background)
2. Git clone failures (invalid URL, missing credentials)
3. Partial failures (some repos work, others fail)
4. Dashboard visibility of repo status
"""

import socket
import sys
import threading
import types
from pathlib import Path
from unittest.mock import patch

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))


from airut.dashboard.tracker import BootPhase, RepoStatus
from airut.gateway.config import (
    EmailAccountConfig,
    EmailAuthConfig,
    EmailChannelConfig,
    GlobalConfig,
    ImapConfig,
    RepoServerConfig,
    ServerConfig,
    SmtpConfig,
)

from .conftest import MOCK_CONTAINER_COMMAND, wait_for_boot
from .email_server import find_free_port
from .environment import IntegrationEnvironment
from .test_config_reload import wait_for_repo_status


def _email_config() -> EmailChannelConfig:
    """Build an EmailChannelConfig for integration tests."""
    return EmailChannelConfig(
        account=EmailAccountConfig(
            username="test",
            password="test",
            from_address="test@test.local",
        ),
        imap=ImapConfig(
            server="127.0.0.1",
            port=9999,
            use_idle=False,
            connect_retries=1,
            poll_interval=0.1,
        ),
        smtp=SmtpConfig(server="127.0.0.1", port=25),
        auth=EmailAuthConfig(
            authorized_senders=["user@test.local"],
            trusted_authserv_id="test.local",
        ),
    )


def _email_channel(
    env: IntegrationEnvironment, repo_id: str
) -> EmailChannelConfig:
    """Return a repo's email channel config from *env*."""
    channel = env.config.repos[repo_id].channels["email"]
    assert isinstance(channel, EmailChannelConfig)
    return channel


class _TcpForwarder:
    """Forwards connections on a local port to another local port.

    Stands in for an IMAP server that becomes reachable only after the
    gateway has started.  Listens from construction until the ``with``
    block ends.

    Attributes:
        connections: Number of connections accepted so far.
    """

    def __init__(self, port: int, target_port: int) -> None:
        self._target_port = target_port
        self._server = socket.create_server(("127.0.0.1", port))
        self._sockets = [self._server]
        self.connections = 0
        threading.Thread(target=self._accept, daemon=True).start()

    def __enter__(self) -> "_TcpForwarder":
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: types.TracebackType | None,
    ) -> None:
        for sock in self._sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass  # Not connected, or already shut down
            sock.close()

    def _accept(self) -> None:
        while True:
            try:
                client, _ = self._server.accept()
            except OSError:
                return  # Closed
            self.connections += 1
            upstream = socket.create_connection(
                ("127.0.0.1", self._target_port)
            )
            self._sockets += [client, upstream]
            for src, dst in ((client, upstream), (upstream, client)):
                threading.Thread(
                    target=self._pump, args=(src, dst), daemon=True
                ).start()

    @staticmethod
    def _pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while data := src.recv(65536):
                dst.sendall(data)
        except OSError:
            pass  # Either side closed
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass


class TestImapConnectionFailures:
    """Test handling of IMAP failures during repo init."""

    def test_unreachable_imap_server_starts_degraded(
        self,
        tmp_path: Path,
        create_email,
    ) -> None:
        """A repo whose IMAP server refuses connections starts DEGRADED.

        The service boots instead of failing the repo, and the repos
        after it start and process mail as usual.
        """
        from .conftest import get_message_text

        env = IntegrationEnvironment.create_multi_repo(
            tmp_path,
            repo_ids=["down", "working"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            # Nothing listens on the port: connections are refused.
            imap = _email_channel(env, "down").imap
            object.__setattr__(imap, "port", find_free_port())
            object.__setattr__(imap, "connect_retries", 1)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)
            service_thread.start()

            wait_for_boot(service)

            try:
                boot = service._boot_store.get().value
                assert boot.phase == BootPhase.READY
                repo_states = {
                    r.repo_id: r for r in service._repos_store.get().value
                }
                down = repo_states["down"]
                assert down.status == RepoStatus.DEGRADED
                assert down.error_type == "IMAPConnectionError"
                assert down.error_message is not None
                assert "refused" in down.error_message.lower()
                assert repo_states["working"].status == RepoStatus.LIVE

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
                assert response is not None
            finally:
                service.stop()
                service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_imap_server_reachable_after_startup_recovers(
        self,
        tmp_path: Path,
        create_email,
    ) -> None:
        """A repo started DEGRADED goes LIVE once its server is reachable.

        The listener keeps reconnecting in the background, so the repo
        recovers without a restart and processes mail.
        """
        from .conftest import get_message_text

        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["user@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            imap = _email_channel(env, "test").imap
            late_port = find_free_port()
            object.__setattr__(imap, "port", late_port)
            object.__setattr__(imap, "connect_retries", 1)

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)

            # Shorten the reconnect backoff (10s at first) to keep the
            # test fast.
            with patch(
                "airut.gateway.email.channel_listener.reconnect_delay",
                return_value=0.2,
            ):
                service_thread.start()
                wait_for_boot(service)

                try:
                    (state,) = service._repos_store.get().value
                    assert state.status == RepoStatus.DEGRADED

                    with _TcpForwarder(late_port, env.email_server.imap_port):
                        wait_for_repo_status(
                            service, "test", "live", timeout=15.0
                        )

                        mock_code = """
events = [
    generate_system_event(session_id),
    generate_assistant_event("Recovered repo response"),
    generate_result_event(session_id, "Done"),
]
"""
                        msg = create_email(
                            subject="Test recovered repo",
                            body=mock_code,
                        )
                        env.email_server.inject_message(msg)

                        response = env.email_server.wait_for_sent(
                            lambda m: (
                                "recovered repo response"
                                in get_message_text(m).lower()
                            ),
                            timeout=15.0,
                        )
                        assert response is not None
                finally:
                    service.stop()
                    service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_imap_login_rejected_after_startup_fails_repo(
        self,
        tmp_path: Path,
    ) -> None:
        """A repo started DEGRADED fails once its server rejects the login.

        As at startup, the rejected login is not repeated.
        """
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["user@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            channel = _email_channel(env, "test")
            late_port = find_free_port()
            object.__setattr__(channel.imap, "port", late_port)
            object.__setattr__(channel.imap, "connect_retries", 1)
            object.__setattr__(channel.account, "password", "wrong")

            service = env.create_service()
            service_thread = threading.Thread(target=service.start, daemon=True)

            # Shorten the reconnect backoff: a listener that kept retrying
            # would reconnect many times before the repo turns FAILED.
            with patch(
                "airut.gateway.email.channel_listener.reconnect_delay",
                return_value=0.2,
            ):
                service_thread.start()
                wait_for_boot(service)

                try:
                    (state,) = service._repos_store.get().value
                    assert state.status == RepoStatus.DEGRADED

                    with _TcpForwarder(
                        late_port, env.email_server.imap_port
                    ) as forwarder:
                        wait_for_repo_status(
                            service, "test", "failed", timeout=15.0
                        )
                        assert forwarder.connections == 1

                    (state,) = service._repos_store.get().value
                    assert state.error_type == "IMAPLoginError"
                finally:
                    service.stop()
                    service_thread.join(timeout=10.0)
        finally:
            env.cleanup()

    def test_rejected_imap_login_fails_repo(
        self,
        tmp_path: Path,
    ) -> None:
        """A repo whose IMAP login is rejected is marked as failed."""
        env = IntegrationEnvironment.create(
            tmp_path,
            authorized_senders=["user@test.local"],
            container_command=MOCK_CONTAINER_COMMAND,
        )

        try:
            account = _email_channel(env, "test").account
            object.__setattr__(account, "password", "wrong")

            service = env.create_service()

            with pytest.raises(RuntimeError, match="All 1 repo"):
                service.start()

            repo_states = {
                r.repo_id: r for r in service._repos_store.get().value
            }
            assert repo_states["test"].status == RepoStatus.FAILED
            assert repo_states["test"].error_type == "IMAPLoginError"
        finally:
            env.cleanup()


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
            channels={"email": _email_config()},
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

            wait_for_boot(service)

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

            wait_for_boot(service)

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

            wait_for_boot(service)

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
