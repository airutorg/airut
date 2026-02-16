# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_proxy.py -- per-context proxy lifecycle management."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._proxy import (
    CA_CERT_FILENAME,
    CONTEXT_NETWORK_PREFIX,
    CONTEXT_PROXY_PREFIX,
    EGRESS_NETWORK,
    PROXY_IMAGE_NAME,
    ProxyError,
    ProxyManager,
    _ContextProxy,
)


class TestContextProxy:
    """Tests for _ContextProxy dataclass."""

    def test_create(self) -> None:
        """Creates _ContextProxy with all fields."""
        proxy = _ContextProxy(
            network_name="airut-conv-abc123",
            proxy_container_name="airut-proxy-abc123",
            proxy_ip="10.199.1.100",
        )
        assert proxy.network_name == "airut-conv-abc123"
        assert proxy.proxy_container_name == "airut-proxy-abc123"
        assert proxy.proxy_ip == "10.199.1.100"

    def test_frozen(self) -> None:
        """_ContextProxy is immutable (frozen dataclass)."""
        proxy = _ContextProxy(
            network_name="net",
            proxy_container_name="container",
            proxy_ip="10.0.0.1",
        )
        with pytest.raises(AttributeError):
            proxy.proxy_ip = "10.0.0.2"  # type: ignore[misc]


class TestProxyError:
    """Tests for ProxyError exception."""

    def test_is_exception(self) -> None:
        """ProxyError is an Exception."""
        err = ProxyError("something went wrong")
        assert isinstance(err, Exception)
        assert str(err) == "something went wrong"


class TestProxyManagerInit:
    """Tests for ProxyManager initialization."""

    def test_defaults(self) -> None:
        """ProxyManager sets default values."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        assert pm._cmd == "podman"
        assert pm._proxy_dir.name == "proxy"
        assert pm._proxy_dir.is_absolute()
        assert pm._egress_network == EGRESS_NETWORK
        assert pm._upstream_dns == "1.1.1.1"
        assert pm._active_proxies == {}
        assert pm._allowlist_tmpfiles == {}
        assert pm._replacement_tmpfiles == {}
        assert pm._network_log_files == {}
        assert pm._next_subnet_octet == 1

    def test_custom_values(self) -> None:
        """ProxyManager accepts custom values."""
        pm = ProxyManager(
            container_command="docker",
            proxy_dir=Path("/custom/proxy"),
            egress_network="custom-egress",
            upstream_dns="8.8.8.8",
        )
        assert pm._cmd == "docker"
        assert pm._proxy_dir == Path("/custom/proxy")
        assert pm._egress_network == "custom-egress"
        assert pm._upstream_dns == "8.8.8.8"


class TestProxyManagerStartup:
    """Tests for ProxyManager.startup()."""

    def test_calls_setup_methods(self) -> None:
        """startup() calls cleanup, build, ca cert, and egress network."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        with (
            patch.object(pm, "_cleanup_orphans") as mock_cleanup,
            patch.object(pm, "_build_image") as mock_build,
            patch.object(pm, "_ensure_ca_cert") as mock_cert,
            patch.object(pm, "_recreate_egress_network") as mock_egress,
        ):
            pm.startup()

        mock_cleanup.assert_called_once()
        mock_build.assert_called_once()
        mock_cert.assert_called_once()
        mock_egress.assert_called_once()


class TestProxyManagerShutdown:
    """Tests for ProxyManager.shutdown()."""

    def test_stops_active_proxies_and_removes_egress(self) -> None:
        """shutdown() stops remaining proxies and removes egress network."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="net-1",
            proxy_container_name="proxy-1",
            proxy_ip="10.199.1.100",
        )

        with (
            patch.object(pm, "stop_proxy") as mock_stop,
            patch.object(pm, "_remove_network") as mock_rm_net,
        ):
            pm.shutdown()

        mock_stop.assert_called_once_with("task-1")
        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)

    def test_shutdown_handles_stop_failure(self) -> None:
        """shutdown() logs warning but continues if stop_proxy fails."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="net-1",
            proxy_container_name="proxy-1",
            proxy_ip="10.199.1.100",
        )

        with (
            patch.object(pm, "stop_proxy", side_effect=RuntimeError("oops")),
            patch.object(pm, "_remove_network") as mock_rm_net,
        ):
            pm.shutdown()  # Should not raise

        # Egress network still removed
        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)

    def test_shutdown_empty_proxies(self) -> None:
        """shutdown() with no active proxies only removes egress network."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch.object(pm, "_remove_network") as mock_rm_net:
            pm.shutdown()

        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)


class TestAllocateSubnet:
    """Tests for ProxyManager._allocate_subnet()."""

    def test_first_allocation(self) -> None:
        """First allocation uses octet 1."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        subnet, proxy_ip = pm._allocate_subnet()
        assert subnet == "10.199.1.0/24"
        assert proxy_ip == "10.199.1.100"

    def test_increments_octet(self) -> None:
        """Subsequent allocations increment the octet."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._allocate_subnet()
        subnet, proxy_ip = pm._allocate_subnet()
        assert subnet == "10.199.2.0/24"
        assert proxy_ip == "10.199.2.100"

    def test_wraps_at_254(self) -> None:
        """Octet wraps from 254 back to 1."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._next_subnet_octet = 254
        subnet, proxy_ip = pm._allocate_subnet()
        assert subnet == "10.199.254.0/24"
        assert proxy_ip == "10.199.254.100"

        # Next allocation wraps to 1
        subnet2, proxy_ip2 = pm._allocate_subnet()
        assert subnet2 == "10.199.1.0/24"
        assert proxy_ip2 == "10.199.1.100"


class TestBuildImage:
    """Tests for ProxyManager._build_image()."""

    def test_success(self, tmp_path: Path) -> None:
        """Builds proxy image successfully."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")

        pm = ProxyManager(
            proxy_dir=tmp_path,
            upstream_dns="1.1.1.1",
        )

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._build_image()

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"
        assert "-t" in cmd
        assert PROXY_IMAGE_NAME in cmd
        assert str(dockerfile) in cmd

    def test_dockerfile_not_found(self, tmp_path: Path) -> None:
        """Raises ProxyError when Dockerfile is missing."""
        pm = ProxyManager(
            proxy_dir=tmp_path,
            upstream_dns="1.1.1.1",
        )
        with pytest.raises(ProxyError, match="Proxy Dockerfile not found"):
            pm._build_image()

    def test_build_failure(self, tmp_path: Path) -> None:
        """Raises ProxyError when build command fails."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM invalid\n")

        pm = ProxyManager(
            proxy_dir=tmp_path,
            upstream_dns="1.1.1.1",
        )

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "build"], stderr="build failed"
            )
            with pytest.raises(ProxyError, match="Proxy image build failed"):
                pm._build_image()


class TestEnsureCaCert:
    """Tests for ProxyManager._ensure_ca_cert()."""

    def test_returns_early_when_cert_exists(self, tmp_path: Path) -> None:
        """Returns existing cert path without generating new one."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.write_text("existing-cert")

        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path):
            result = pm._ensure_ca_cert()

        assert result == cert

    def test_generates_cert_when_missing(self, tmp_path: Path) -> None:
        """Generates CA cert via mitmdump when missing."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        cert_path = tmp_path / CA_CERT_FILENAME

        mock_proc = MagicMock()
        mock_proc.terminate.return_value = None
        mock_proc.wait.return_value = None

        with (
            patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path),
            patch(
                "airut.sandbox._proxy.subprocess.Popen", return_value=mock_proc
            ),
            patch("airut.sandbox._proxy.time.sleep") as mock_sleep,
        ):
            # Simulate cert file appearing after a few polls
            call_count = 0

            def side_effect(duration: float) -> None:
                nonlocal call_count
                call_count += 1
                if call_count >= 2:
                    cert_path.write_text("generated-cert")

            mock_sleep.side_effect = side_effect
            result = pm._ensure_ca_cert()

        assert result == cert_path
        mock_proc.terminate.assert_called_once()
        mock_proc.wait.assert_called_once_with(timeout=10)

    def test_raises_when_cert_never_appears(self, tmp_path: Path) -> None:
        """Raises ProxyError when cert is never generated."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        mock_proc = MagicMock()
        mock_proc.terminate.return_value = None
        mock_proc.wait.return_value = None

        with (
            patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path),
            patch(
                "airut.sandbox._proxy.subprocess.Popen", return_value=mock_proc
            ),
            patch("airut.sandbox._proxy.time.sleep"),
        ):
            with pytest.raises(
                ProxyError, match="Failed to generate CA certificate"
            ):
                pm._ensure_ca_cert()

    def test_kills_process_when_wait_times_out(self, tmp_path: Path) -> None:
        """Falls back to kill() when terminate + wait times out."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        cert_path = tmp_path / CA_CERT_FILENAME

        mock_proc = MagicMock()
        mock_proc.terminate.return_value = None
        mock_proc.wait.side_effect = [
            subprocess.TimeoutExpired("podman", 10),
            None,  # second wait() after kill()
        ]
        mock_proc.kill.return_value = None

        with (
            patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path),
            patch(
                "airut.sandbox._proxy.subprocess.Popen", return_value=mock_proc
            ),
            patch("airut.sandbox._proxy.time.sleep") as mock_sleep,
        ):
            call_count = 0

            def side_effect(duration: float) -> None:
                nonlocal call_count
                call_count += 1
                if call_count >= 2:
                    cert_path.write_text("generated-cert")

            mock_sleep.side_effect = side_effect
            result = pm._ensure_ca_cert()

        assert result == cert_path
        mock_proc.terminate.assert_called_once()
        mock_proc.kill.assert_called_once()
        assert mock_proc.wait.call_count == 2


class TestWriteTempFile:
    """Tests for ProxyManager._write_temp_file()."""

    def test_writes_data_and_tracks(self) -> None:
        """Writes data to temp file and tracks for cleanup."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        tracking: dict[str, Path] = {}

        path = pm._write_temp_file(
            "task-1", b'{"key": "value"}', "allowlist", tracking
        )

        assert path.exists()
        assert path.read_bytes() == b'{"key": "value"}'
        assert tracking["task-1"] == path
        assert path.name.startswith("airut-allowlist-")
        assert path.name.endswith(".json")

        # Cleanup
        path.unlink()


class TestCleanupTempFile:
    """Tests for ProxyManager._cleanup_temp_file()."""

    def test_removes_tracked_file(self, tmp_path: Path) -> None:
        """Removes tracked temp file."""
        tmpfile = tmp_path / "test.json"
        tmpfile.write_text("data")
        tracking: dict[str, Path] = {"task-1": tmpfile}

        ProxyManager._cleanup_temp_file("task-1", tracking)

        assert not tmpfile.exists()
        assert "task-1" not in tracking

    def test_noop_for_untracked_task(self) -> None:
        """Does nothing when context_id not in tracking dict."""
        tracking: dict[str, Path] = {}
        ProxyManager._cleanup_temp_file("nonexistent", tracking)
        assert tracking == {}

    def test_handles_already_deleted_file(self, tmp_path: Path) -> None:
        """Handles case where file was already deleted (missing_ok)."""
        tmpfile = tmp_path / "already-gone.json"
        # File doesn't exist on disk, but is tracked
        tracking: dict[str, Path] = {"task-1": tmpfile}

        ProxyManager._cleanup_temp_file("task-1", tracking)

        assert "task-1" not in tracking


class TestCreateNetworkLog:
    """Tests for ProxyManager._create_network_log()."""

    def test_creates_log_file(self, tmp_path: Path) -> None:
        """Creates empty network log file and tracks it."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        log_path = pm._create_network_log("task-1", tmp_path)

        assert log_path.exists()
        assert log_path.name == "network-sandbox.log"
        assert pm._network_log_files["task-1"] == log_path


class TestCleanupNetworkLog:
    """Tests for ProxyManager._cleanup_network_log()."""

    def test_removes_tracking(self, tmp_path: Path) -> None:
        """Removes tracking entry but keeps the file."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        pm._network_log_files["task-1"] = log_path

        pm._cleanup_network_log("task-1")

        assert "task-1" not in pm._network_log_files
        # File is intentionally kept
        assert log_path.exists()

    def test_noop_for_untracked_task(self) -> None:
        """Does nothing when context_id not tracked."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._cleanup_network_log("nonexistent")  # Should not raise


class TestRunProxyContainer:
    """Tests for ProxyManager._run_proxy_container()."""

    def test_success_minimal(self, tmp_path: Path) -> None:
        """Starts proxy container with required args only."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        allowlist_path = tmp_path / "allowlist.json"
        allowlist_path.write_text("[]")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._run_proxy_container(
                "airut-proxy-task1",
                "airut-conv-task1",
                "10.199.1.100",
                allowlist_path,
            )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert "run" in cmd
        assert "--rm" in cmd
        assert "-d" in cmd
        assert "--name" in cmd
        assert "airut-proxy-task1" in cmd
        assert "airut-conv-task1:ip=10.199.1.100" in cmd

    def test_with_replacement_path(self, tmp_path: Path) -> None:
        """Mounts replacement map when provided."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        allowlist_path = tmp_path / "allowlist.json"
        allowlist_path.write_text("[]")
        replacement_path = tmp_path / "replacements.json"
        replacement_path.write_text("{}")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._run_proxy_container(
                "airut-proxy-task1",
                "airut-conv-task1",
                "10.199.1.100",
                allowlist_path,
                replacement_path=replacement_path,
            )

        cmd = mock_run.call_args[0][0]
        replacement_mount = f"{replacement_path}:/replacements.json:ro"
        assert replacement_mount in cmd

    def test_with_network_log_path(self, tmp_path: Path) -> None:
        """Mounts network log file when provided."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        allowlist_path = tmp_path / "allowlist.json"
        allowlist_path.write_text("[]")
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._run_proxy_container(
                "airut-proxy-task1",
                "airut-conv-task1",
                "10.199.1.100",
                allowlist_path,
                network_log_path=log_path,
            )

        cmd = mock_run.call_args[0][0]
        log_mount = f"{log_path}:/network-sandbox.log:rw"
        assert log_mount in cmd

    def test_failure_raises_proxy_error(self, tmp_path: Path) -> None:
        """Raises ProxyError when container start fails."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        allowlist_path = tmp_path / "allowlist.json"
        allowlist_path.write_text("[]")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "run"], stderr="container start failed"
            )
            with pytest.raises(
                ProxyError, match="Failed to start proxy container"
            ):
                pm._run_proxy_container(
                    "airut-proxy-task1",
                    "airut-conv-task1",
                    "10.199.1.100",
                    allowlist_path,
                )


class TestWaitForProxyReady:
    """Tests for ProxyManager._wait_for_proxy_ready()."""

    def test_ready_immediately(self) -> None:
        """Proxy ready on first probe."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._wait_for_proxy_ready("airut-proxy-task1")

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "exec" in cmd
        assert "airut-proxy-task1" in cmd

    def test_ready_after_retries(self) -> None:
        """Proxy ready after several failed probes."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with (
            patch("airut.sandbox._proxy.subprocess.run") as mock_run,
            patch("airut.sandbox._proxy.time.sleep"),
        ):
            # Fail twice, then succeed
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, ["podman"]),
                subprocess.TimeoutExpired(["podman"], 3),
                MagicMock(returncode=0),
            ]
            pm._wait_for_proxy_ready("airut-proxy-task1")

        assert mock_run.call_count == 3

    def test_timeout_raises_proxy_error(self) -> None:
        """Raises ProxyError after timeout."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with (
            patch("airut.sandbox._proxy.subprocess.run") as mock_run,
            patch("airut.sandbox._proxy.time.sleep"),
            patch("airut.sandbox._proxy.time.monotonic") as mock_time,
        ):
            # Simulate time progressing past deadline
            mock_time.side_effect = [0.0, 0.1, 6.0]
            mock_run.side_effect = subprocess.CalledProcessError(1, ["podman"])

            with pytest.raises(ProxyError, match="not ready after"):
                pm._wait_for_proxy_ready("airut-proxy-task1", timeout=5.0)


class TestRemoveContainer:
    """Tests for ProxyManager._remove_container()."""

    def test_success(self) -> None:
        """Removes container successfully."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._remove_container("airut-proxy-task1")

        mock_run.assert_called_once_with(
            ["podman", "rm", "-f", "airut-proxy-task1"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_already_gone(self) -> None:
        """Handles already-removed container (idempotent)."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "rm"]
            )
            pm._remove_container("nonexistent")  # Should not raise


class TestCreateInternalNetwork:
    """Tests for ProxyManager._create_internal_network()."""

    def test_success(self) -> None:
        """Creates internal network with correct args."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._create_internal_network(
                "airut-conv-task1",
                subnet="10.199.1.0/24",
                proxy_ip="10.199.1.100",
            )

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "network" in cmd
        assert "create" in cmd
        assert "--internal" in cmd
        assert "--disable-dns" in cmd
        assert "--subnet" in cmd
        assert "10.199.1.0/24" in cmd
        assert "--route" in cmd
        assert "airut-conv-task1" in cmd

    def test_failure_raises_proxy_error(self) -> None:
        """Raises ProxyError when network creation fails."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "network", "create"], stderr="network exists"
            )
            with pytest.raises(
                ProxyError, match="Failed to create internal network"
            ):
                pm._create_internal_network(
                    "airut-conv-task1",
                    subnet="10.199.1.0/24",
                    proxy_ip="10.199.1.100",
                )


class TestCreateEgressNetwork:
    """Tests for ProxyManager._create_egress_network()."""

    def test_success(self) -> None:
        """Creates egress network with correct args."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._create_egress_network()

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "network" in cmd
        assert "create" in cmd
        assert "-o" in cmd
        assert "metric=5" in cmd
        assert EGRESS_NETWORK in cmd

    def test_failure_raises_proxy_error(self) -> None:
        """Raises ProxyError when egress network creation fails."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "network", "create"], stderr="create failed"
            )
            with pytest.raises(
                ProxyError, match="Failed to create egress network"
            ):
                pm._create_egress_network()


class TestRecreateEgressNetwork:
    """Tests for ProxyManager._recreate_egress_network()."""

    def test_removes_then_creates(self) -> None:
        """Removes existing egress network, then creates new one."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with (
            patch.object(pm, "_remove_network") as mock_rm,
            patch.object(pm, "_create_egress_network") as mock_create,
        ):
            pm._recreate_egress_network()

        mock_rm.assert_called_once_with(EGRESS_NETWORK)
        mock_create.assert_called_once()


class TestRemoveNetwork:
    """Tests for ProxyManager._remove_network()."""

    def test_success(self) -> None:
        """Removes network successfully."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._remove_network("test-net")

        mock_run.assert_called_once_with(
            ["podman", "network", "rm", "-f", "test-net"],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_already_gone(self) -> None:
        """Handles already-removed network (idempotent)."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "network", "rm"]
            )
            pm._remove_network("nonexistent")  # Should not raise


class TestCleanupOrphans:
    """Tests for ProxyManager._cleanup_orphans()."""

    def test_cleans_containers_and_networks(self) -> None:
        """Removes orphaned containers and networks."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            # First call: list containers (returns two names)
            # Second call: remove first container
            # Third call: remove second container
            # Fourth call: list networks (returns one name)
            # Fifth call: remove network
            container_result = MagicMock()
            container_result.stdout = "airut-proxy-old1\nairut-proxy-old2\n"
            network_result = MagicMock()
            network_result.stdout = "airut-conv-old1\n"

            # remove_container calls subprocess.run too
            mock_run.side_effect = [
                container_result,  # ps -a
                MagicMock(),  # rm container 1
                MagicMock(),  # rm container 2
                network_result,  # network ls
                MagicMock(),  # network rm
            ]

            pm._cleanup_orphans()

        assert mock_run.call_count == 5

    def test_handles_empty_output(self) -> None:
        """Handles empty container/network lists."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            empty_result = MagicMock()
            empty_result.stdout = ""

            mock_run.side_effect = [
                empty_result,  # ps -a (empty)
                empty_result,  # network ls (empty)
            ]

            pm._cleanup_orphans()

        assert mock_run.call_count == 2

    def test_handles_container_list_failure(self) -> None:
        """Continues to network cleanup when container list fails."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            network_result = MagicMock()
            network_result.stdout = ""

            mock_run.side_effect = [
                subprocess.CalledProcessError(1, ["podman", "ps"]),
                network_result,  # network ls (empty)
            ]

            pm._cleanup_orphans()  # Should not raise

        assert mock_run.call_count == 2

    def test_handles_network_list_failure(self) -> None:
        """Handles failure in network listing."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            container_result = MagicMock()
            container_result.stdout = ""

            mock_run.side_effect = [
                container_result,  # ps -a (empty)
                subprocess.CalledProcessError(1, ["podman", "network"]),
            ]

            pm._cleanup_orphans()  # Should not raise


class TestStartTaskProxy:
    """Tests for ProxyManager.start_proxy()."""

    def test_full_flow(self, tmp_path: Path) -> None:
        """Full start_proxy flow with all steps mocked."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with (
            patch.object(pm, "stop_proxy") as mock_stop,
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100"),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            proxy = pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )

        # Verify idempotent stop was called first
        mock_stop.assert_called_once_with("task-1")

        assert proxy.network_name == f"{CONTEXT_NETWORK_PREFIX}task-1"
        assert proxy.proxy_container_name == f"{CONTEXT_PROXY_PREFIX}task-1"
        assert proxy.proxy_ip == "10.199.1.100"
        assert "task-1" in pm._active_proxies

        # Cleanup temp files
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)

    def test_with_network_log_dir(self, tmp_path: Path) -> None:
        """Creates network log when network_log_dir is provided."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100"),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container") as mock_run_proxy,
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
                network_log_dir=log_dir,
            )

        # Verify network log was created
        assert "task-1" in pm._network_log_files

        # Verify _run_proxy_container was called with network_log_path
        call_kwargs = mock_run_proxy.call_args.kwargs
        assert call_kwargs["network_log_path"] is not None

        # Cleanup
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)

    def test_cleanup_on_failure(self, tmp_path: Path) -> None:
        """Cleans up on failure during start_proxy."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100"),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(
                pm,
                "_run_proxy_container",
                side_effect=ProxyError("container failed"),
            ),
            patch.object(pm, "_remove_container") as mock_rm_container,
            patch.object(pm, "_remove_network") as mock_rm_network,
        ):
            with pytest.raises(ProxyError, match="container failed"):
                pm.start_proxy(
                    "task-1",
                    allowlist_json=b"[]",
                    replacements_json=b"{}",
                )

        # Verify cleanup was called
        mock_rm_container.assert_called_once_with(
            f"{CONTEXT_PROXY_PREFIX}task-1"
        )
        mock_rm_network.assert_called_once_with(
            f"{CONTEXT_NETWORK_PREFIX}task-1"
        )
        # Temp files should have been cleaned up
        assert "task-1" not in pm._allowlist_tmpfiles
        assert "task-1" not in pm._replacement_tmpfiles

    def test_cleanup_on_failure_with_network_log(self, tmp_path: Path) -> None:
        """Cleans up network log tracking on failure."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        log_dir = tmp_path / "logs"
        log_dir.mkdir()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100"),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(
                pm,
                "_run_proxy_container",
                side_effect=ProxyError("container failed"),
            ),
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
        ):
            with pytest.raises(ProxyError, match="container failed"):
                pm.start_proxy(
                    "task-1",
                    allowlist_json=b"[]",
                    replacements_json=b"{}",
                    network_log_dir=log_dir,
                )

        # Network log tracking should be cleaned up
        assert "task-1" not in pm._network_log_files


class TestStopTaskProxy:
    """Tests for ProxyManager.stop_proxy()."""

    def test_stops_active_proxy(self) -> None:
        """Stops and cleans up an active proxy."""
        pm = ProxyManager(upstream_dns="1.1.1.1")
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="airut-conv-task-1",
            proxy_container_name="airut-proxy-task-1",
            proxy_ip="10.199.1.100",
        )
        # Track some temp files
        tmpfile = Path("/tmp/fake-allowlist.json")
        pm._allowlist_tmpfiles["task-1"] = tmpfile
        replacement_file = Path("/tmp/fake-replacements.json")
        pm._replacement_tmpfiles["task-1"] = replacement_file
        pm._network_log_files["task-1"] = Path("/tmp/fake-network.log")

        with (
            patch.object(pm, "_remove_container") as mock_rm_container,
            patch.object(pm, "_remove_network") as mock_rm_network,
            patch.object(Path, "unlink"),
        ):
            pm.stop_proxy("task-1")

        mock_rm_container.assert_called_once_with("airut-proxy-task-1")
        mock_rm_network.assert_called_once_with("airut-conv-task-1")
        assert "task-1" not in pm._active_proxies
        assert "task-1" not in pm._allowlist_tmpfiles
        assert "task-1" not in pm._replacement_tmpfiles
        assert "task-1" not in pm._network_log_files

    def test_noop_for_unknown_task(self) -> None:
        """Does nothing for unknown context_id."""
        pm = ProxyManager(upstream_dns="1.1.1.1")

        with patch.object(pm, "_remove_container") as mock_rm:
            pm.stop_proxy("nonexistent")

        mock_rm.assert_not_called()
