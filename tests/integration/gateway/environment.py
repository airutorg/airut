# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration test environment orchestrator.

Provides a complete test environment including:
- Git repository for conversations
- Test email server (SMTP/IMAP)
- ServerConfig configured for testing
"""

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from lib.gateway.config import (
    GlobalConfig,
    RepoServerConfig,
    ServerConfig,
)

from .email_server import TestEmailServer


logger = logging.getLogger(__name__)


def create_test_repo(path: Path) -> Path:
    """Create a minimal git repository for testing.

    Args:
        path: Directory to initialize as git repo.

    Returns:
        Path to the created repository.
    """
    path.mkdir(parents=True, exist_ok=True)

    # Initialize git repo
    subprocess.run(
        ["git", "init"],
        cwd=path,
        check=True,
        capture_output=True,
    )

    # Configure git user (required for commits)
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@test.local"],
        cwd=path,
        check=True,
        capture_output=True,
    )

    # Create initial commit
    readme = path / "README.md"
    readme.write_text("# Test Repository\n\nCreated for integration testing.\n")

    # Add network sandbox config (read from git mirror by ProxyManager)
    airut_dir = path / ".airut"
    airut_dir.mkdir()
    (airut_dir / "network-allowlist.yaml").write_text(
        "domains: []\nurl_prefixes: []\n"
    )
    (airut_dir / "airut.yaml").write_text(
        "git:\n"
        "  user: Test User\n"
        "  email: test@test.local\n"
        "default_model: sonnet\n"
        "timeout: 30\n"
    )

    # Add container Dockerfile (read from git mirror by ClaudeExecutor)
    container_dir = airut_dir / "container"
    container_dir.mkdir()
    (container_dir / "Dockerfile").write_text(
        "FROM python:3.13-slim\nRUN pip install claude-code\n"
    )

    subprocess.run(
        ["git", "add", "."],
        cwd=path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "commit", "-m", "Initial commit"],
        cwd=path,
        check=True,
        capture_output=True,
    )

    logger.debug("Created test repository at %s", path)
    return path


@dataclass
class IntegrationEnvironment:
    """Complete integration test environment.

    Provides all components needed for integration testing:
    - master_repo: Git repository to clone for conversations
    - storage_dir: Directory for conversation checkouts
    - email_server: Combined SMTP/IMAP test server
    - config: ServerConfig for the service
    - egress_network: Unique network name to avoid conflicts in parallel tests

    Use the create() classmethod to create and start the environment.
    """

    master_repo: Path
    storage_dir: Path
    email_server: TestEmailServer
    smtp_port: int
    imap_port: int
    config: ServerConfig
    mitmproxy_confdir: Path
    repo_root: Path
    egress_network: str

    @classmethod
    def create(
        cls,
        tmp_path: Path,
        authorized_senders: list[str],
        dashboard_enabled: bool = True,
        container_command: str = "podman",
    ) -> "IntegrationEnvironment":
        """Create and start an integration test environment.

        Args:
            tmp_path: Temporary directory for test files.
            authorized_senders: Email patterns allowed to send commands.
            dashboard_enabled: Whether to enable the dashboard.
            container_command: Container runtime command.

        Returns:
            A started IntegrationEnvironment.
        """
        import uuid

        # Unique network name to avoid conflicts in parallel tests
        egress_network = f"airut-egress-{uuid.uuid4().hex[:8]}"

        # Create directories
        master_repo = create_test_repo(tmp_path / "master_repo")
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        mitmproxy_confdir = tmp_path / "mitmproxy-confdir"

        # Create docker infrastructure files
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir(exist_ok=True)
        (docker_dir / "proxy.dockerfile").write_text("FROM scratch\n")
        (docker_dir / "proxy-allowlist.py").write_text("")
        (docker_dir / "airut-entrypoint.sh").write_text(
            '#!/usr/bin/env bash\nexec claude "$@"\n'
        )

        # Start email server
        email_server = TestEmailServer(username="test", password="test")
        smtp_port, imap_port = email_server.start()

        # Create config
        global_config = GlobalConfig(
            max_concurrent_executions=2,
            shutdown_timeout_seconds=5,
            dashboard_enabled=dashboard_enabled,
            dashboard_host="127.0.0.1",
            dashboard_port=0,  # Dynamic port
            container_command=container_command,
        )
        repo_config = RepoServerConfig(
            repo_id="test",
            imap_server="127.0.0.1",
            imap_port=imap_port,
            smtp_server="127.0.0.1",
            smtp_port=smtp_port,
            email_username="test",
            email_password="test",
            email_from="Claude Test <claude@test.local>",
            authorized_senders=authorized_senders,
            trusted_authserv_id="test.local",
            git_repo_url=str(master_repo),
            storage_dir=storage_dir,
            use_imap_idle=False,  # Use polling for predictable testing
            poll_interval_seconds=1,  # Fast polling for tests
            smtp_require_auth=False,  # Test server doesn't support AUTH
        )
        config = ServerConfig(
            global_config=global_config,
            repos={"test": repo_config},
        )

        logger.info(
            "Created integration environment: repo=%s, smtp=%d, imap=%d",
            master_repo,
            smtp_port,
            imap_port,
        )

        return cls(
            master_repo=master_repo,
            storage_dir=storage_dir,
            email_server=email_server,
            smtp_port=smtp_port,
            imap_port=imap_port,
            config=config,
            mitmproxy_confdir=mitmproxy_confdir,
            repo_root=tmp_path,
            egress_network=egress_network,
        )

    @classmethod
    def create_multi_repo(
        cls,
        tmp_path: Path,
        repo_ids: list[str],
        container_command: str = "podman",
        authorized_senders_per_repo: dict[str, list[str]] | None = None,
    ) -> "IntegrationEnvironment":
        """Create environment with multiple repositories.

        Each repo gets its own git repo, storage directory, and IMAP inbox
        (via distinct email usernames). All share one email server.

        Args:
            tmp_path: Temporary directory for test files.
            repo_ids: List of repo identifiers (at least 2).
            container_command: Container runtime command.
            authorized_senders_per_repo: Optional per-repo sender allowlists.
                Keys are repo IDs, values are lists of authorized sender
                patterns.  Repos not in the dict default to
                ``["user@test.local"]``.

        Returns:
            A started IntegrationEnvironment with multiple repos configured.
        """
        import uuid

        # Unique network name to avoid conflicts in parallel tests
        egress_network = f"airut-egress-{uuid.uuid4().hex[:8]}"

        # Create per-repo git repos and storage
        storage_dir = tmp_path / "storage"
        storage_dir.mkdir()
        mitmproxy_confdir = tmp_path / "mitmproxy-confdir"

        # Docker infrastructure files (shared)
        docker_dir = tmp_path / "docker"
        docker_dir.mkdir(exist_ok=True)
        (docker_dir / "proxy.dockerfile").write_text("FROM scratch\n")
        (docker_dir / "proxy-allowlist.py").write_text("")
        (docker_dir / "airut-entrypoint.sh").write_text(
            '#!/usr/bin/env bash\nexec claude "$@"\n'
        )

        # Start email server with per-repo inboxes
        email_server = TestEmailServer(username="test", password="test")
        for repo_id in repo_ids:
            email_server.add_inbox(repo_id)
        smtp_port, imap_port = email_server.start()

        global_config = GlobalConfig(
            max_concurrent_executions=2,
            shutdown_timeout_seconds=5,
            dashboard_enabled=False,
            dashboard_host="127.0.0.1",
            dashboard_port=0,
            container_command=container_command,
        )

        repos: dict[str, RepoServerConfig] = {}
        first_master_repo: Path | None = None
        for repo_id in repo_ids:
            master_repo = create_test_repo(tmp_path / f"master_repo_{repo_id}")
            if first_master_repo is None:
                first_master_repo = master_repo
            repo_storage = storage_dir / repo_id
            repo_storage.mkdir()
            senders = (
                authorized_senders_per_repo.get(repo_id, ["user@test.local"])
                if authorized_senders_per_repo
                else ["user@test.local"]
            )
            repos[repo_id] = RepoServerConfig(
                repo_id=repo_id,
                imap_server="127.0.0.1",
                imap_port=imap_port,
                smtp_server="127.0.0.1",
                smtp_port=smtp_port,
                email_username=repo_id,
                email_password="test",
                email_from=f"{repo_id} <{repo_id}@test.local>",
                authorized_senders=senders,
                trusted_authserv_id="test.local",
                git_repo_url=str(master_repo),
                storage_dir=repo_storage,
                use_imap_idle=False,
                poll_interval_seconds=1,
                smtp_require_auth=False,
            )

        config = ServerConfig(global_config=global_config, repos=repos)

        assert first_master_repo is not None
        logger.info(
            "Created multi-repo integration environment: repos=%s, "
            "smtp=%d, imap=%d",
            ", ".join(repo_ids),
            smtp_port,
            imap_port,
        )

        return cls(
            master_repo=first_master_repo,
            storage_dir=storage_dir,
            email_server=email_server,
            smtp_port=smtp_port,
            imap_port=imap_port,
            config=config,
            mitmproxy_confdir=mitmproxy_confdir,
            repo_root=tmp_path,
            egress_network=egress_network,
        )

    def create_service(self):
        """Create an EmailGatewayService with this environment's config."""
        from lib.gateway.service import EmailGatewayService

        return EmailGatewayService(
            self.config,
            repo_root=self.repo_root,
            egress_network=self.egress_network,
        )

    def cleanup(self) -> None:
        """Stop servers and clean up resources."""
        logger.info("Cleaning up integration environment")
        self.email_server.stop()
