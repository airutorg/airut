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

from airut.sandbox._image_cache import ImageBuildSpec, ImageCache
from airut.sandbox._proxy import (
    CA_CERT_FILENAME,
    DEFAULT_RESOURCE_PREFIX,
    ProxyError,
    ProxyManager,
    _ContextProxy,
)


# Derived constants matching the default prefix for test assertions.
EGRESS_NETWORK = f"{DEFAULT_RESOURCE_PREFIX}-egress"
CONTEXT_NETWORK_PREFIX = f"{DEFAULT_RESOURCE_PREFIX}-conv-"
CONTEXT_PROXY_PREFIX = f"{DEFAULT_RESOURCE_PREFIX}-proxy-"


def _make_pm(
    *,
    upstream_dns: str = "1.1.1.1",
    container_command: str = "podman",
    proxy_dir: Path | None = None,
    egress_network: str | None = None,
    resource_prefix: str = DEFAULT_RESOURCE_PREFIX,
    image_cache: ImageCache | None = None,
    proxy_image_tag: str | None = "airut-proxy:test123",
) -> ProxyManager:
    """Create ProxyManager with a mock ImageCache (convenience helper).

    Sets ``_proxy_image_tag`` to a default test value so methods that
    reference the tag (``_ensure_ca_cert``, ``_run_proxy_container``)
    work without calling ``startup()`` first.
    """
    if image_cache is None:
        image_cache = MagicMock(spec=ImageCache)
    kwargs: dict = {
        "container_command": container_command,
        "upstream_dns": upstream_dns,
        "resource_prefix": resource_prefix,
        "image_cache": image_cache,
    }
    if proxy_dir is not None:
        kwargs["proxy_dir"] = proxy_dir
    if egress_network is not None:
        kwargs["egress_network"] = egress_network
    pm = ProxyManager(**kwargs)
    pm._proxy_image_tag = proxy_image_tag
    return pm


class TestContextProxy:
    """Tests for _ContextProxy dataclass."""

    def test_create(self) -> None:
        """Creates _ContextProxy with all fields."""
        proxy = _ContextProxy(
            network_name="airut-conv-abc123",
            proxy_container_name="airut-proxy-abc123",
            proxy_ip="10.199.1.100",
            subnet_octet=1,
        )
        assert proxy.network_name == "airut-conv-abc123"
        assert proxy.proxy_container_name == "airut-proxy-abc123"
        assert proxy.proxy_ip == "10.199.1.100"
        assert proxy.subnet_octet == 1

    def test_frozen(self) -> None:
        """_ContextProxy is immutable (frozen dataclass)."""
        proxy = _ContextProxy(
            network_name="net",
            proxy_container_name="container",
            proxy_ip="10.0.0.1",
            subnet_octet=1,
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
        pm = _make_pm(proxy_image_tag=None)
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
        assert pm._active_octets == set()
        assert pm._proxy_image_tag is None

    def test_custom_values(self) -> None:
        """ProxyManager accepts custom values."""
        pm = _make_pm(
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
        """startup() calls cleanup, ensure proxy image, ca cert, egress."""
        pm = _make_pm()
        with (
            patch.object(pm, "_cleanup_orphans") as mock_cleanup,
            patch.object(pm, "_ensure_proxy_image") as mock_ensure,
            patch.object(pm, "_ensure_ca_cert") as mock_cert,
            patch.object(pm, "_recreate_egress_network") as mock_egress,
        ):
            pm.startup()

        mock_cleanup.assert_called_once()
        mock_ensure.assert_called_once()
        mock_cert.assert_called_once()
        mock_egress.assert_called_once()


class TestProxyManagerShutdown:
    """Tests for ProxyManager.shutdown()."""

    def test_stops_active_proxies_and_removes_egress(self) -> None:
        """shutdown() stops remaining proxies and removes egress network."""
        pm = _make_pm()
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="net-1",
            proxy_container_name="proxy-1",
            proxy_ip="10.199.1.100",
            subnet_octet=1,
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
        pm = _make_pm()
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="net-1",
            proxy_container_name="proxy-1",
            proxy_ip="10.199.1.100",
            subnet_octet=1,
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
        pm = _make_pm()

        with patch.object(pm, "_remove_network") as mock_rm_net:
            pm.shutdown()

        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)


class TestAllocateSubnet:
    """Tests for ProxyManager._allocate_subnet()."""

    def test_first_allocation(self) -> None:
        """First allocation uses octet 1."""
        pm = _make_pm()
        subnet, proxy_ip, octet = pm._allocate_subnet()
        assert subnet == "10.199.1.0/24"
        assert proxy_ip == "10.199.1.100"
        assert octet == 1

    def test_increments_octet(self) -> None:
        """Subsequent allocations increment the octet."""
        pm = _make_pm()
        pm._allocate_subnet()
        subnet, proxy_ip, octet = pm._allocate_subnet()
        assert subnet == "10.199.2.0/24"
        assert proxy_ip == "10.199.2.100"
        assert octet == 2

    def test_wraps_at_254(self) -> None:
        """Octet wraps from 254 back to 1."""
        pm = _make_pm()
        pm._next_subnet_octet = 254
        subnet, proxy_ip, octet = pm._allocate_subnet()
        assert subnet == "10.199.254.0/24"
        assert proxy_ip == "10.199.254.100"
        assert octet == 254

        # Next allocation wraps to 1
        subnet2, proxy_ip2, octet2 = pm._allocate_subnet()
        assert subnet2 == "10.199.1.0/24"
        assert proxy_ip2 == "10.199.1.100"
        assert octet2 == 1

    def test_no_duplicate_subnets(self) -> None:
        """All 254 allocations produce unique subnets."""
        pm = _make_pm()
        allocated = []
        for _ in range(254):
            subnet, proxy_ip, octet = pm._allocate_subnet()
            allocated.append((subnet, proxy_ip, octet))

        # All octets are unique
        octets = [o for _, _, o in allocated]
        assert len(set(octets)) == 254
        assert set(octets) == set(range(1, 255))

        # All subnets and IPs are unique
        subnets = [s for s, _, _ in allocated]
        assert len(set(subnets)) == 254
        ips = [ip for _, ip, _ in allocated]
        assert len(set(ips)) == 254

    def test_exhaustion_raises_after_254(self) -> None:
        """255th allocation raises ProxyError when all are held."""
        pm = _make_pm()
        for _ in range(254):
            pm._allocate_subnet()

        with pytest.raises(ProxyError, match="All 254 subnets are in use"):
            pm._allocate_subnet()

    def test_release_allows_reuse(self) -> None:
        """Releasing a subnet makes it available for reallocation."""
        pm = _make_pm()
        _, _, first_octet = pm._allocate_subnet()
        pm._release_subnet(first_octet)

        # Next allocation can reuse the freed octet (or any free one)
        _, _, reused_octet = pm._allocate_subnet()
        # After releasing 1, the counter moved to 2, so octet 2 gets
        # allocated next.  The key invariant is: no error is raised.
        assert 1 <= reused_octet <= 254

    def test_release_after_exhaustion(self) -> None:
        """Releasing one subnet after full exhaustion allows one more."""
        pm = _make_pm()
        octets = []
        for _ in range(254):
            _, _, octet = pm._allocate_subnet()
            octets.append(octet)

        # Exhausted
        with pytest.raises(ProxyError):
            pm._allocate_subnet()

        # Free one and allocate again
        pm._release_subnet(octets[100])
        subnet, proxy_ip, octet = pm._allocate_subnet()
        assert octet == octets[100]
        assert subnet == f"10.199.{octet}.0/24"
        assert proxy_ip == f"10.199.{octet}.100"

    def test_wraparound_skips_held_subnets(self) -> None:
        """Allocator wraps around and skips subnets that are still held."""
        pm = _make_pm()
        # Allocate octets 1..253, then release all except 1 and 2
        held_octets = []
        for _ in range(253):
            _, _, octet = pm._allocate_subnet()
            held_octets.append(octet)

        for octet in held_octets[2:]:  # release 3..253
            pm._release_subnet(octet)

        # Counter is at 254. Allocate two more: should get 254, then 3
        # (skipping 1 and 2 which are still held)
        _, _, o1 = pm._allocate_subnet()
        assert o1 == 254
        pm._release_subnet(o1)

        _, _, o2 = pm._allocate_subnet()
        # Should skip 1 and 2, land on 3
        # (counter wrapped from 254->1, 1 held, 2 held, 3 free)
        assert o2 == 3

    def test_release_is_idempotent(self) -> None:
        """Releasing an already-released octet does not raise."""
        pm = _make_pm()
        _, _, octet = pm._allocate_subnet()
        pm._release_subnet(octet)
        pm._release_subnet(octet)  # no error


class TestEnsureProxyImage:
    """Tests for ProxyManager._ensure_proxy_image()."""

    def test_delegates_to_image_cache(self, tmp_path: Path) -> None:
        """_ensure_proxy_image() builds spec and delegates to ImageCache."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache.ensure.return_value = "airut-proxy:abc123"
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")

        pm = _make_pm(proxy_dir=tmp_path, image_cache=mock_cache)
        pm._ensure_proxy_image()

        mock_cache.ensure.assert_called_once()
        spec = mock_cache.ensure.call_args[0][0]
        assert isinstance(spec, ImageBuildSpec)
        assert spec.kind == "proxy"
        assert pm._proxy_image_tag == "airut-proxy:abc123"

    def test_sets_proxy_image_tag(self, tmp_path: Path) -> None:
        """_ensure_proxy_image() stores the tag for later use."""
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache.ensure.return_value = "airut-cli-proxy:def456"
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")

        pm = _make_pm(
            proxy_dir=tmp_path,
            image_cache=mock_cache,
            proxy_image_tag=None,
        )
        assert pm._proxy_image_tag is None

        pm._ensure_proxy_image()

        assert pm._proxy_image_tag == "airut-cli-proxy:def456"


class TestBuildProxySpec:
    """Tests for ProxyManager._build_proxy_spec()."""

    def test_includes_all_proxy_files(self, tmp_path: Path) -> None:
        """Spec includes Dockerfile and all other files as context."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")
        script = tmp_path / "proxy_filter.py"
        script.write_text("# filter\n")
        dns = tmp_path / "dns_responder.py"
        dns.write_text("# dns\n")

        pm = _make_pm(proxy_dir=tmp_path)
        spec = pm._build_proxy_spec()

        assert spec.kind == "proxy"
        assert spec.dockerfile == b"FROM python:3.13\n"
        assert "proxy_filter.py" in spec.context_files
        assert "dns_responder.py" in spec.context_files
        # Dockerfile itself should NOT be in context_files
        assert "proxy.dockerfile" not in spec.context_files

    def test_dockerfile_not_found(self, tmp_path: Path) -> None:
        """Raises ProxyError when Dockerfile is missing."""
        pm = _make_pm(proxy_dir=tmp_path)
        with pytest.raises(ProxyError, match="Proxy Dockerfile not found"):
            pm._build_proxy_spec()

    def test_context_files_sorted(self, tmp_path: Path) -> None:
        """Context files are collected from sorted directory listing."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")
        (tmp_path / "b_file.py").write_text("b")
        (tmp_path / "a_file.py").write_text("a")

        pm = _make_pm(proxy_dir=tmp_path)
        spec = pm._build_proxy_spec()

        assert list(spec.context_files.keys()) == ["a_file.py", "b_file.py"]

    def test_excludes_subdirectories(self, tmp_path: Path) -> None:
        """Subdirectories in proxy_dir are not included."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.py").write_text("nested")

        pm = _make_pm(proxy_dir=tmp_path)
        spec = pm._build_proxy_spec()

        assert "subdir" not in spec.context_files
        assert "nested.py" not in spec.context_files


class TestEnsureCaCert:
    """Tests for ProxyManager._ensure_ca_cert()."""

    def test_returns_early_when_cert_exists(self, tmp_path: Path) -> None:
        """Returns existing cert path without generating new one."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.write_text("existing-cert")

        pm = _make_pm()

        with patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path):
            result = pm._ensure_ca_cert()

        assert result == cert

    def test_generates_cert_when_missing(self, tmp_path: Path) -> None:
        """Generates CA cert via mitmdump when missing."""
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()
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
        pm = _make_pm()
        log_path = tmp_path / "network-sandbox.log"

        pm._create_network_log("task-1", log_path)

        assert log_path.exists()
        assert pm._network_log_files["task-1"] == log_path


class TestCleanupNetworkLog:
    """Tests for ProxyManager._cleanup_network_log()."""

    def test_removes_tracking(self, tmp_path: Path) -> None:
        """Removes tracking entry but keeps the file."""
        pm = _make_pm()
        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        pm._network_log_files["task-1"] = log_path

        pm._cleanup_network_log("task-1")

        assert "task-1" not in pm._network_log_files
        # File is intentionally kept
        assert log_path.exists()

    def test_noop_for_untracked_task(self) -> None:
        """Does nothing when context_id not tracked."""
        pm = _make_pm()
        pm._cleanup_network_log("nonexistent")  # Should not raise


class TestRunProxyContainer:
    """Tests for ProxyManager._run_proxy_container()."""

    def test_success_minimal(self, tmp_path: Path) -> None:
        """Starts proxy container with required args only."""
        pm = _make_pm()
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
        pm = _make_pm()
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
        pm = _make_pm()
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
        pm = _make_pm()
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
        pm = _make_pm()

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            pm._wait_for_proxy_ready("airut-proxy-task1")

        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert "exec" in cmd
        assert "airut-proxy-task1" in cmd

    def test_ready_after_retries(self) -> None:
        """Proxy ready after several failed probes."""
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "rm"]
            )
            pm._remove_container("nonexistent")  # Should not raise


class TestCreateInternalNetwork:
    """Tests for ProxyManager._create_internal_network()."""

    def test_success(self) -> None:
        """Creates internal network with correct args."""
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

        with patch("airut.sandbox._proxy.subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.CalledProcessError(
                1, ["podman", "network", "rm"]
            )
            pm._remove_network("nonexistent")  # Should not raise


class TestCleanupOrphans:
    """Tests for ProxyManager._cleanup_orphans()."""

    def test_cleans_containers_and_networks(self) -> None:
        """Removes orphaned containers and networks."""
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

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
        pm = _make_pm()

        with (
            patch.object(pm, "stop_proxy") as mock_stop,
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
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

    def test_with_network_log_path(self, tmp_path: Path) -> None:
        """Creates network log when network_log_path is provided."""
        pm = _make_pm()
        log_path = tmp_path / "logs" / "network-sandbox.log"
        log_path.parent.mkdir()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container") as mock_run_proxy,
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
                network_log_path=log_path,
            )

        # Verify network log was created
        assert "task-1" in pm._network_log_files
        assert pm._network_log_files["task-1"] == log_path

        # Verify _run_proxy_container was called with network_log_path
        call_kwargs = mock_run_proxy.call_args.kwargs
        assert call_kwargs["network_log_path"] == log_path

        # Cleanup
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)

    def test_cleanup_on_failure(self, tmp_path: Path) -> None:
        """Cleans up on failure during start_proxy."""
        pm = _make_pm()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
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
        pm = _make_pm()
        log_path = tmp_path / "logs" / "network-sandbox.log"
        log_path.parent.mkdir()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
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
                    network_log_path=log_path,
                )

        # Network log tracking should be cleaned up
        assert "task-1" not in pm._network_log_files

    def test_concurrent_proxies_get_unique_subnets(self) -> None:
        """Multiple concurrent start_proxy calls get distinct subnets."""
        pm = _make_pm()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            p1 = pm.start_proxy(
                "task-1", allowlist_json=b"[]", replacements_json=b"{}"
            )
            p2 = pm.start_proxy(
                "task-2", allowlist_json=b"[]", replacements_json=b"{}"
            )
            p3 = pm.start_proxy(
                "task-3", allowlist_json=b"[]", replacements_json=b"{}"
            )

        # Each proxy must have a distinct subnet
        ips = {p1.proxy_ip, p2.proxy_ip, p3.proxy_ip}
        assert len(ips) == 3

        # Cleanup
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)

    def test_stop_then_start_reuses_freed_subnet(self) -> None:
        """Stopping a proxy frees its subnet for reuse by a new proxy."""
        pm = _make_pm()

        with (
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
        ):
            # Fill all 254 subnets
            for i in range(254):
                pm.start_proxy(
                    f"task-{i}",
                    allowlist_json=b"[]",
                    replacements_json=b"{}",
                )

            # 255th should fail
            with pytest.raises(ProxyError, match="All 254 subnets"):
                pm.start_proxy(
                    "task-overflow",
                    allowlist_json=b"[]",
                    replacements_json=b"{}",
                )

            # Stop one proxy, then the same slot becomes available
            pm.stop_proxy("task-42")

            proxy = pm.start_proxy(
                "task-new",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )
            assert (
                proxy.subnet_octet
                == pm._active_proxies["task-new"].subnet_octet
            )

        # Cleanup
        for path in list(pm._allowlist_tmpfiles.values()):
            path.unlink(missing_ok=True)
        for path in list(pm._replacement_tmpfiles.values()):
            path.unlink(missing_ok=True)

    def test_failure_cleanup_releases_subnet(self) -> None:
        """Failed start_proxy releases its subnet so it won't be leaked."""
        pm = _make_pm()

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(pm, "_create_internal_network"),
            patch.object(
                pm,
                "_run_proxy_container",
                side_effect=ProxyError("container failed"),
            ),
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
        ):
            with pytest.raises(ProxyError):
                pm.start_proxy(
                    "task-1",
                    allowlist_json=b"[]",
                    replacements_json=b"{}",
                )

        # Octet 1 was allocated then released on failure. The counter
        # advanced to 2, so the next allocation gets 2. We can still
        # allocate all 254 without hitting exhaustion, proving octet 1
        # was properly freed.
        octets = []
        for _ in range(254):
            _, _, octet = pm._allocate_subnet()
            octets.append(octet)

        assert len(set(octets)) == 254


class TestStopTaskProxy:
    """Tests for ProxyManager.stop_proxy()."""

    def test_stops_active_proxy(self) -> None:
        """Stops and cleans up an active proxy."""
        pm = _make_pm()
        pm._active_proxies["task-1"] = _ContextProxy(
            network_name="airut-conv-task-1",
            proxy_container_name="airut-proxy-task-1",
            proxy_ip="10.199.1.100",
            subnet_octet=1,
        )
        pm._active_octets.add(1)
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
        # Subnet octet should be released
        assert 1 not in pm._active_octets

    def test_noop_for_unknown_task(self) -> None:
        """Does nothing for unknown context_id."""
        pm = _make_pm()

        with patch.object(pm, "_remove_container") as mock_rm:
            pm.stop_proxy("nonexistent")

        mock_rm.assert_not_called()
