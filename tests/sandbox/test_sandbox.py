# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/sandbox.py -- top-level Sandbox manager."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import MagicMock, patch

from airut.sandbox._image_cache import ImageCache
from airut.sandbox.sandbox import Sandbox, SandboxConfig
from airut.sandbox.task import AgentTask, CommandTask
from airut.sandbox.types import ContainerEnv, Mount, ResourceLimits


class TestSandboxConfig:
    """Tests for SandboxConfig dataclass."""

    def test_defaults(self) -> None:
        """Default configuration values."""
        config = SandboxConfig()
        assert config.container_command == "podman"
        assert config.proxy_dir.name == "proxy"
        assert config.proxy_dir.is_absolute()
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

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_init_creates_image_cache(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """Sandbox creates ImageCache with config values."""
        config = SandboxConfig()
        Sandbox(config)

        mock_cache_class.assert_called_once_with(
            container_command="podman",
            resource_prefix="airut",
            max_age_hours=24,
        )

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_init_injects_image_cache_into_proxy_manager(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """Sandbox injects ImageCache into ProxyManager."""
        config = SandboxConfig()
        Sandbox(config)

        pm_call_kwargs = mock_pm_class.call_args.kwargs
        assert pm_call_kwargs["image_cache"] is mock_cache_class.return_value

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_init_with_egress_network(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """Sandbox passes egress_network override to ProxyManager."""
        config = SandboxConfig()
        Sandbox(config, egress_network="custom-egress")

        call_kwargs = mock_pm_class.call_args.kwargs
        assert call_kwargs.get("egress_network") == "custom-egress"

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_proxy_manager_property(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """proxy_manager property returns ProxyManager."""
        config = SandboxConfig()
        sandbox = Sandbox(config)
        assert sandbox.proxy_manager is not None


class TestSandboxStartupShutdown:
    """Tests for Sandbox.startup() and shutdown()."""

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_startup_delegates_to_proxy(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """startup() delegates to ProxyManager.startup()."""
        mock_pm = MagicMock()
        mock_pm_class.return_value = mock_pm

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.startup()

        mock_pm.startup.assert_called_once()

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_shutdown_delegates_to_proxy(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """shutdown() delegates to ProxyManager.shutdown()."""
        mock_pm = MagicMock()
        mock_pm_class.return_value = mock_pm

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.shutdown()

        mock_pm.shutdown.assert_called_once()


class TestSandboxPruneImages:
    """Tests for Sandbox.prune_images()."""

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_delegates_to_image_cache(
        self, mock_cache_class: MagicMock, mock_pm_class: MagicMock
    ) -> None:
        """prune_images() delegates to ImageCache.prune_images()."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.prune_images.return_value = 3

        config = SandboxConfig()
        sandbox = Sandbox(config)
        result = sandbox.prune_images()

        assert result == 3
        mock_cache.prune_images.assert_called_once()


class TestSandboxEnsureImage:
    """Tests for Sandbox.ensure_image()."""

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_builds_both_layers(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
    ) -> None:
        """ensure_image() builds repo and overlay via ImageCache."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.tag_for.return_value = "airut-repo:abc123"
        mock_cache.get_image_created.side_effect = [None, None]
        mock_cache.ensure.side_effect = [
            "airut-repo:abc123",
            "airut-overlay:def456",
        ]

        config = SandboxConfig()
        sandbox = Sandbox(config)

        tag = sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})

        assert tag == "airut-overlay:def456"
        assert mock_cache.ensure.call_count == 2

        # First call: repo spec
        repo_call = mock_cache.ensure.call_args_list[0]
        repo_spec = repo_call[0][0]
        assert repo_spec.kind == "repo"
        assert repo_spec.dockerfile == b"FROM ubuntu:24.04\n"

        # Second call: overlay spec
        overlay_call = mock_cache.ensure.call_args_list[1]
        overlay_spec = overlay_call[0][0]
        assert overlay_spec.kind == "overlay"
        assert b"FROM airut-repo:abc123" in overlay_spec.dockerfile
        assert "airut-entrypoint.sh" in overlay_spec.context_files

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_force_cascades_when_repo_rebuilt(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
    ) -> None:
        """Overlay is force-rebuilt when repo was rebuilt."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.tag_for.return_value = "airut-repo:abc123"
        # Before: None (repo doesn't exist), After: has timestamp
        mock_cache.get_image_created.side_effect = [
            None,
            datetime(2026, 1, 1, tzinfo=UTC),
        ]
        mock_cache.ensure.side_effect = [
            "airut-repo:abc123",
            "airut-overlay:def456",
        ]

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})

        # Overlay call should have force=True
        overlay_call = mock_cache.ensure.call_args_list[1]
        assert overlay_call[1]["force"] is True

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_no_force_when_repo_reused(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
    ) -> None:
        """Overlay is not force-rebuilt when repo was reused."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.tag_for.return_value = "airut-repo:abc123"
        same_ts = "2026-01-01T00:00:00+00:00"
        mock_cache.get_image_created.return_value = same_ts
        mock_cache.ensure.side_effect = [
            "airut-repo:abc123",
            "airut-overlay:def456",
        ]

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.ensure_image(b"FROM ubuntu:24.04\n", {})

        # Overlay call should have force=False
        overlay_call = mock_cache.ensure.call_args_list[1]
        assert overlay_call[1]["force"] is False

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_passes_context_files(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
    ) -> None:
        """ensure_image() passes context files to repo spec."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.tag_for.return_value = "airut-repo:abc123"
        mock_cache.get_image_created.return_value = None
        mock_cache.ensure.side_effect = [
            "airut-repo:abc123",
            "airut-overlay:def456",
        ]

        config = SandboxConfig()
        sandbox = Sandbox(config)

        context = {"gitconfig": b"[user]\n\tname = Test\n"}
        sandbox.ensure_image(b"FROM ubuntu:24.04\n", context)

        repo_spec = mock_cache.ensure.call_args_list[0][0][0]
        assert repo_spec.context_files == context

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_passthrough_entrypoint(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
    ) -> None:
        """ensure_image(passthrough_entrypoint=True) uses passthrough."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache_class.return_value = mock_cache
        mock_cache.tag_for.return_value = "airut-repo:abc123"
        mock_cache.get_image_created.return_value = None
        mock_cache.ensure.side_effect = [
            "airut-repo:abc123",
            "airut-overlay:def456",
        ]

        config = SandboxConfig()
        sandbox = Sandbox(config)
        sandbox.ensure_image(
            b"FROM ubuntu:24.04\n", {}, passthrough_entrypoint=True
        )

        # The overlay spec should contain the passthrough entrypoint
        overlay_spec = mock_cache.ensure.call_args_list[1][0][0]
        entrypoint = overlay_spec.context_files["airut-entrypoint.sh"]
        assert b'exec "$@"' in entrypoint
        assert b"exec claude" not in entrypoint


class TestSandboxCreateTask:
    """Tests for Sandbox.create_task()."""

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_returns_agent_task(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() returns an AgentTask instance."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert isinstance(task, AgentTask)
        assert task.execution_context_id == "task-123"

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_passes_mounts_and_env(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() passes mounts and env to AgentTask."""
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
            image_tag="airut-overlay:test",
            mounts=mounts,
            env=env,
            execution_context_dir=context_dir,
        )

        assert task._mounts == mounts
        assert task._env == env

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_no_proxy_manager_without_network_sandbox(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() does not pass proxy_manager when no network_sandbox."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert task._proxy_manager is None

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_passes_proxy_manager_with_network_sandbox(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() passes proxy_manager when network_sandbox is set."""
        from airut.allowlist import Allowlist
        from airut.sandbox.secrets import SecretReplacements
        from airut.sandbox.task import NetworkSandboxConfig

        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        allowlist = Allowlist(domains=(), url_patterns=())
        replacements = SecretReplacements()
        sandbox_config = NetworkSandboxConfig(allowlist, replacements)

        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            network_sandbox=sandbox_config,
        )

        assert task._proxy_manager is not None

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_custom_resource_limits(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() passes resource_limits to AgentTask."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        limits = ResourceLimits(
            timeout=600, memory="4g", cpus=2, pids_limit=256
        )
        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            resource_limits=limits,
        )

        assert task._resource_limits == limits

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_default_resource_limits(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() uses empty ResourceLimits when not specified."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert task._resource_limits == ResourceLimits()

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_network_log_path(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_task() passes network_log_path to AgentTask."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()
        log_path = tmp_path / "logs" / "network-sandbox.log"
        log_path.parent.mkdir()

        task = sandbox.create_task(
            "task-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            network_log_path=log_path,
        )

        assert task._network_log_path == log_path


class TestSandboxCreateCommandTask:
    """Tests for Sandbox.create_command_task()."""

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_returns_command_task(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_command_task() returns a CommandTask instance."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_command_task(
            "cmd-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert isinstance(task, CommandTask)
        assert task.execution_context_id == "cmd-123"

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_passes_mounts_and_env(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_command_task() passes mounts and env to CommandTask."""
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

        task = sandbox.create_command_task(
            "cmd-123",
            image_tag="airut-overlay:test",
            mounts=mounts,
            env=env,
            execution_context_dir=context_dir,
        )

        assert task._mounts == mounts
        assert task._env == env

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_no_proxy_manager_without_network_sandbox(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_command_task() without network_sandbox has no proxy."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_command_task(
            "cmd-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert task._proxy_manager is None

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_default_resource_limits(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_command_task() uses default ResourceLimits."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        task = sandbox.create_command_task(
            "cmd-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
        )

        assert task._resource_limits == ResourceLimits()

    @patch("airut.sandbox.sandbox.ProxyManager")
    @patch("airut.sandbox.sandbox.ImageCache")
    def test_custom_resource_limits(
        self,
        mock_cache_class: MagicMock,
        mock_pm_class: MagicMock,
        tmp_path: Path,
    ) -> None:
        """create_command_task() passes resource_limits."""
        config = SandboxConfig()
        sandbox = Sandbox(config)

        context_dir = tmp_path / "context"
        context_dir.mkdir()

        limits = ResourceLimits(timeout=120, memory="1g")
        task = sandbox.create_command_task(
            "cmd-123",
            image_tag="airut-overlay:test",
            mounts=[],
            env=ContainerEnv(),
            execution_context_dir=context_dir,
            resource_limits=limits,
        )

        assert task._resource_limits == limits
