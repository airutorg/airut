# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/sandbox.py -- top-level Sandbox manager."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from lib.sandbox.sandbox import Sandbox, SandboxConfig
from lib.sandbox.task import Task
from lib.sandbox.types import ContainerEnv, Mount


class TestSandboxConfig:
    """Tests for SandboxConfig dataclass."""

    def test_defaults(self) -> None:
        """Default configuration values."""
        config = SandboxConfig()
        assert config.container_command == "podman"
        assert config.proxy_dir == Path("proxy")
        assert config.upstream_dns == "1.1.1.1"
        assert config.max_image_age_hours == 24

    def test_custom_values(self) -> None:
        """Custom configuration values."""
        config = SandboxConfig(
            container_command="docker",
            proxy_dir=Path("/tmp/proxy"),
            upstream_dns="8.8.8.8",
            max_image_age_hours=48,
        )
        assert config.container_command == "docker"
        assert config.proxy_dir == Path("/tmp/proxy")
        assert config.upstream_dns == "8.8.8.8"
        assert config.max_image_age_hours == 48


class TestSandboxInit:
    """Tests for Sandbox initialization."""

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_init_defaults(self, mock_pm_class: MagicMock) -> None:
        """Sandbox initializes with default config."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        assert sandbox._container_command == "podman"
        assert sandbox._repo_images == {}
        assert sandbox._overlay_images == {}

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_init_with_egress_network(self, mock_pm_class: MagicMock) -> None:
        """Sandbox passes egress_network override to ProxyManager."""
        config = SandboxConfig()
        Sandbox(config, egress_network="custom-egress")

        # Verify ProxyManager was created with egress_network
        call_kwargs = mock_pm_class.call_args.kwargs
        assert call_kwargs.get("egress_network") == "custom-egress"

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_proxy_manager_property(self, mock_pm_class: MagicMock) -> None:
        """proxy_manager property returns ProxyManager."""
        config = SandboxConfig()
        sandbox = Sandbox(config)
        assert sandbox.proxy_manager is not None


class TestSandboxStartupShutdown:
    """Tests for Sandbox.startup() and shutdown()."""

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_startup_delegates_to_proxy(self, mock_pm_class: MagicMock) -> None:
        """startup() delegates to ProxyManager.startup()."""
        mock_pm = MagicMock()
        mock_pm_class.return_value = mock_pm

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.startup()

        mock_pm.startup.assert_called_once()

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_shutdown_delegates_to_proxy(
        self, mock_pm_class: MagicMock
    ) -> None:
        """shutdown() delegates to ProxyManager.shutdown()."""
        mock_pm = MagicMock()
        mock_pm_class.return_value = mock_pm

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.shutdown()

        mock_pm.shutdown.assert_called_once()


class TestSandboxEnsureImage:
    """Tests for Sandbox.ensure_image()."""

    @patch("lib.sandbox.sandbox.build_overlay_image")
    @patch("lib.sandbox.sandbox.build_repo_image")
    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_builds_both_layers(
        self,
        mock_pm_class: MagicMock,
        mock_build_repo: MagicMock,
        mock_build_overlay: MagicMock,
    ) -> None:
        """ensure_image() builds both repo and overlay images."""
        mock_build_repo.return_value = "airut-repo:abc123"
        mock_build_overlay.return_value = "airut:def456"

        config = SandboxConfig()
        sandbox = Sandbox(config)

        tag = sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})

        assert tag == "airut:def456"
        mock_build_repo.assert_called_once_with(
            "podman",
            b"FROM ubuntu:24.04\n",
            {},
            sandbox._repo_images,
            24,
        )
        mock_build_overlay.assert_called_once_with(
            "podman",
            "airut-repo:abc123",
            sandbox._overlay_images,
            24,
        )

    @patch("lib.sandbox.sandbox.build_overlay_image")
    @patch("lib.sandbox.sandbox.build_repo_image")
    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_caching_reuses_images(
        self,
        mock_pm_class: MagicMock,
        mock_build_repo: MagicMock,
        mock_build_overlay: MagicMock,
    ) -> None:
        """ensure_image() uses cached images on repeated calls."""
        mock_build_repo.return_value = "airut-repo:abc123"
        mock_build_overlay.return_value = "airut:def456"

        config = SandboxConfig()
        sandbox = Sandbox(config)

        tag1 = sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})
        tag2 = sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})

        assert tag1 == tag2
        # build functions are called with the same cache dicts,
        # so caching happens inside those functions
        assert mock_build_repo.call_count == 2
        assert mock_build_overlay.call_count == 2

    @patch("lib.sandbox.sandbox.build_overlay_image")
    @patch("lib.sandbox.sandbox.build_repo_image")
    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_passes_context_files(
        self,
        mock_pm_class: MagicMock,
        mock_build_repo: MagicMock,
        mock_build_overlay: MagicMock,
    ) -> None:
        """ensure_image() passes context files to build_repo_image."""
        mock_build_repo.return_value = "airut-repo:abc123"
        mock_build_overlay.return_value = "airut:def456"

        config = SandboxConfig()
        sandbox = Sandbox(config)

        context = {"gitconfig": b"[user]\n\tname = Test\n"}
        sandbox.ensure_image(b"FROM ubuntu:24.04\n", context)

        call_args = mock_build_repo.call_args
        assert call_args[0][2] == context


class TestSandboxCreateTask:
    """Tests for Sandbox.create_task()."""

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_returns_task(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() returns a Task instance."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert isinstance(task, Task)
        assert task.execution_context_id == "task-123"

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_passes_mounts_and_env(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() passes mounts and env to Task."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        mounts = [
            Mount(
                host_path=tmp_path / "workspace",
                container_path="/workspace",
            )
        ]
        env = ContainerEnv(variables={"KEY": "value"})

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=mounts,
            env=env,
            execution_context_dir=context_dir,
        )

        assert task._mounts == mounts
        assert task._env == env

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_no_proxy_manager_without_network_sandbox(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() does not pass proxy_manager when no network_sandbox."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert task._proxy_manager is None

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_passes_proxy_manager_with_network_sandbox(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() passes proxy_manager when network_sandbox is set."""
        from lib.allowlist import Allowlist
        from lib.sandbox.secrets import SecretReplacements
        from lib.sandbox.task import NetworkSandboxConfig

        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            network_sandbox=sandbox_config,
        )

        assert task._proxy_manager is not None

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_custom_timeout(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() passes custom timeout to Task."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            timeout_seconds=600,
        )

        assert task._timeout_seconds == 600

    @patch("lib.sandbox.sandbox.ProxyManager")
    def test_network_log_dir(
        self, mock_pm_class: MagicMock, tmp_path: Path
    ) -> None:
        """create_task() passes network_log_dir to Task."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            network_log_dir=log_dir,
        )

        assert task._network_log_dir == log_dir
