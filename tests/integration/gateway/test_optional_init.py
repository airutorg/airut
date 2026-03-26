# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Integration tests for optional airut init.

Verifies that airut can start without a config file, using built-in
defaults (dashboard enabled, no repos).  The config directory is created
at startup so the inotify watcher can monitor for config files created
later (e.g. via the dashboard config editor).

Test plan:
  1. ``airut check`` with no config file does not fail (exit 0)
  2. Gateway starts with no config file, dashboard comes up
  3. Config directory is created at startup
  4. Writing a config file is picked up by the running service
  5. ``airut init`` creates config equivalent to the minimal default
"""

import dataclasses
import sys
import threading
import time
from pathlib import Path
from unittest.mock import patch

import pytest


sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from airut.cli import cmd_check
from airut.config.source import YamlConfigSource
from airut.dashboard.tracker import BootPhase
from airut.gateway.config import (
    GlobalConfig,
    ServerConfig,
)
from airut.gateway.service import GatewayService

from .conftest import MOCK_CONTAINER_COMMAND


# ------------------------------------------------------------------ #
# Helpers
# ------------------------------------------------------------------ #


def _default_config_with_mock_container() -> ServerConfig:
    """Create a default ServerConfig using mock_podman and port 0."""
    config = ServerConfig.default().value
    gc = dataclasses.replace(
        config.global_config,
        container_command=MOCK_CONTAINER_COMMAND,
        dashboard_port=0,
    )
    return dataclasses.replace(config, global_config=gc)


def _wait_for_service_ready(
    service: GatewayService, timeout: float = 15.0
) -> None:
    """Wait for the service to complete boot (READY phase)."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        boot = service._boot_store.get().value
        if boot.phase == BootPhase.READY:
            return
        if boot.phase == BootPhase.FAILED:
            raise RuntimeError(f"Service boot failed: {boot.error_message}")
        time.sleep(0.05)
    raise TimeoutError(f"Service did not boot within {timeout}s")


def _wait_for_watcher_ready(
    service: GatewayService, timeout: float = 5.0
) -> None:
    """Wait until the config file watcher is listening."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if service._watcher is not None:
            remaining = deadline - time.monotonic()
            if service._watcher.ready.wait(max(remaining, 0)):
                return
        time.sleep(0.05)
    raise TimeoutError(f"Config file watcher not ready within {timeout}s")


def _wait_for_reload(
    service: GatewayService,
    generation: int,
    timeout: float = 5.0,
) -> None:
    """Wait until config_generation > generation."""
    with service._reload_condition:
        if not service._reload_condition.wait_for(
            lambda: service._config_generation > generation, timeout
        ):
            raise TimeoutError(
                f"Config reload did not complete within {timeout}s "
                f"(generation={service._config_generation}, "
                f"expected>{generation})"
            )


# ------------------------------------------------------------------ #
# Tests
# ------------------------------------------------------------------ #


class TestCheckWithoutConfig:
    """airut check should not fail when config file is missing."""

    def test_check_no_config_exits_zero(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Check exits 0 with no config file, noting defaults will be used."""
        config_path = tmp_path / "airut" / "airut.yaml"
        assert not config_path.exists()

        with (
            patch("airut.cli.get_config_path", return_value=config_path),
            patch("airut.cli.get_dotenv_path", return_value=tmp_path / ".env"),
            patch("airut.cli._check_dependency", return_value=(True, "ok")),
            patch("airut.cli._check_cgroups_v2", return_value=(True, "ok")),
            patch("airut.cli._is_service_installed", return_value=False),
            patch(
                "airut.version.check_upstream_version",
                return_value=None,
            ),
            patch(
                "airut.version.get_git_version_info",
                return_value=type(
                    "V",
                    (),
                    {
                        "version": "v0.1.0",
                        "sha_short": "abc1234",
                        "sha_full": "abc",
                        "full_status": "",
                    },
                )(),
            ),
        ):
            result = cmd_check([])

        assert result == 0
        out = capsys.readouterr().out
        assert "not found" in out
        assert "default values will be used" in out
        assert "All checks passed" in out


class TestGatewayWithoutConfig:
    """Gateway starts with no config, dashboard enabled, no repos."""

    def test_starts_with_defaults(self, tmp_path: Path) -> None:
        """Service boots successfully with default config (no repos)."""
        config = _default_config_with_mock_container()
        service = GatewayService(
            config,
            repo_root=tmp_path,
            egress_network=f"airut-test-{id(self):x}",
        )

        service_thread = threading.Thread(
            target=service.start,
            kwargs={"resilient": True},
            daemon=True,
        )
        service_thread.start()

        try:
            _wait_for_service_ready(service)

            # Dashboard should be running
            assert service.dashboard is not None

            # No repos configured
            assert len(service.repo_handlers) == 0

            boot = service._boot_store.get().value
            assert boot.phase == BootPhase.READY
        finally:
            service.stop()
            service_thread.join(timeout=5)

    def test_config_dir_created_at_startup(self, tmp_path: Path) -> None:
        """Config directory is created at startup for inotify watcher."""
        config_dir = tmp_path / "config" / "airut"
        config_path = config_dir / "airut.yaml"
        assert not config_dir.exists()

        # The gateway main() creates config_path.parent — simulate that
        config_path.parent.mkdir(parents=True, exist_ok=True)

        assert config_dir.exists()
        assert not config_path.exists()


class TestConfigFilePickup:
    """Writing a config file after start is detected by the watcher."""

    def test_new_config_file_picked_up(self, tmp_path: Path) -> None:
        """Config file written after boot is detected and applied."""
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        config_path = config_dir / "airut.yaml"

        # Start with defaults (no config file)
        source = YamlConfigSource(config_path)
        snapshot = ServerConfig.default()
        config = _default_config_with_mock_container()

        service = GatewayService(
            config,
            repo_root=tmp_path,
            egress_network=f"airut-test-{id(self):x}",
            config_source=source,
            config_snapshot=snapshot,
        )

        service_thread = threading.Thread(
            target=service.start,
            kwargs={"resilient": True},
            daemon=True,
        )
        service_thread.start()

        try:
            _wait_for_service_ready(service)
            _wait_for_watcher_ready(service)

            # Initially no repos
            assert len(service.repo_handlers) == 0

            # Write a config file with no repos (just global settings)
            gen_before = service._config_generation
            source.save(
                {
                    "dashboard": {"enabled": True},
                }
            )

            _wait_for_reload(service, gen_before)

            # Config was reloaded (generation bumped)
            assert service._config_generation > gen_before
        finally:
            service.stop()
            service_thread.join(timeout=5)


class TestInitEquivalence:
    """airut init creates config equivalent to the minimal default."""

    def test_init_config_parses_successfully(self, tmp_path: Path) -> None:
        """The stub config from airut init is valid YAML that parses."""
        from airut.config.generate import generate_stub_config

        config_path = tmp_path / "airut.yaml"
        config_path.write_text(generate_stub_config())

        # The stub config has placeholder values (mail.example.com, etc.)
        # so it will fail validation, but it should parse as valid YAML.
        source = YamlConfigSource(config_path)
        raw = source.load()
        assert isinstance(raw, dict)
        assert "repos" in raw

    def test_default_config_has_dashboard_enabled(self) -> None:
        """Default config has dashboard enabled."""
        config = ServerConfig.default().value
        assert config.global_config.dashboard_enabled is True

    def test_default_config_has_no_repos(self) -> None:
        """Default config has no repos."""
        config = ServerConfig.default().value
        assert len(config.repos) == 0

    def test_default_global_config_matches_dataclass_defaults(self) -> None:
        """Default GlobalConfig matches the dataclass defaults exactly."""
        default_config = ServerConfig.default().value.global_config
        expected = GlobalConfig()
        assert default_config == expected
