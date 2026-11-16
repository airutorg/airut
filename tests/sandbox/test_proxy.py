# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_proxy.py -- per-context proxy lifecycle management."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from airut.sandbox._image_cache import ImageBuildSpec, ImageCache
from airut.sandbox._proxy import (
    DEFAULT_PROXY_READY_TIMEOUT,
    DEFAULT_RESOURCE_PREFIX,
    PROXY_BASE_IMAGE_ARG,
    ProxyError,
    ProxyManager,
    _ContextProxy,
)
from airut.sandbox._proxy_ca import CaCertError


# Derived constants matching the default prefix for test assertions.
EGRESS_NETWORK = f"{DEFAULT_RESOURCE_PREFIX}-egress"
CONTEXT_NETWORK_PREFIX = f"{DEFAULT_RESOURCE_PREFIX}-conv-"
CONTEXT_PROXY_PREFIX = f"{DEFAULT_RESOURCE_PREFIX}-proxy-"


def _make_pm(
    *,
    upstream_dns: str = "1.1.1.1",
    proxy_ready_timeout: float = DEFAULT_PROXY_READY_TIMEOUT,
    container_command: str = "podman",
    proxy_dir: Path | None = None,
    egress_network: str | None = None,
    resource_prefix: str = DEFAULT_RESOURCE_PREFIX,
    image_cache: ImageCache | None = None,
    proxy_image_tag: str | None = "airut-proxy:test123",
    base_image: str | None = None,
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
        "proxy_ready_timeout": proxy_ready_timeout,
        "resource_prefix": resource_prefix,
        "image_cache": image_cache,
    }
    if proxy_dir is not None:
        kwargs["proxy_dir"] = proxy_dir
    if egress_network is not None:
        kwargs["egress_network"] = egress_network
    if base_image is not None:
        kwargs["base_image"] = base_image
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
            proxy.proxy_ip = "10.0.0.2"  # ty:ignore[invalid-assignment]


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
        assert pm._proxy_ready_timeout == 30.0
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
            proxy_ready_timeout=90.0,
        )
        assert pm._cmd == "docker"
        assert pm._proxy_dir == Path("/custom/proxy")
        assert pm._egress_network == "custom-egress"
        assert pm._upstream_dns == "8.8.8.8"
        assert pm._proxy_ready_timeout == 90.0


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


class TestAllocateSubnetAndCreateNetwork:
    """Tests for ProxyManager._allocate_subnet_and_create_network()."""

    def test_success_first_try(self) -> None:
        """Creates network on first attempt when no conflict."""
        pm = _make_pm()
        with patch.object(pm, "_create_internal_network"):
            proxy_ip, octet = pm._allocate_subnet_and_create_network("net-1")
        assert proxy_ip == "10.199.1.100"
        assert octet == 1

    def test_retries_on_subnet_conflict(self) -> None:
        """Retries with next octet when subnet is already used externally."""
        pm = _make_pm()
        conflict_error = ProxyError(
            "Failed to create internal network net-1: "
            "Error: subnet 10.199.1.0/24 is already used on the host"
        )
        call_count = 0

        def create_side_effect(
            name: str, *, subnet: str, proxy_ip: str
        ) -> None:
            nonlocal call_count
            call_count += 1
            if "10.199.1." in subnet:
                raise conflict_error

        with (
            patch.object(
                pm,
                "_create_internal_network",
                side_effect=create_side_effect,
            ),
        ):
            proxy_ip, octet = pm._allocate_subnet_and_create_network("net-1")

        assert octet == 2
        assert proxy_ip == "10.199.2.100"
        assert call_count == 2
        # Octet 1 is released so future calls can retry it.
        assert 1 not in pm._active_octets

    def test_retries_multiple_conflicts(self) -> None:
        """Skips multiple externally-held subnets."""
        pm = _make_pm()
        conflict_octets = {1, 2, 3}

        def create_side_effect(
            name: str, *, subnet: str, proxy_ip: str
        ) -> None:
            for o in conflict_octets:
                if f"10.199.{o}." in subnet:
                    raise ProxyError(
                        f"Failed to create internal network {name}: "
                        f"Error: subnet {subnet} is already used"
                    )

        with patch.object(
            pm, "_create_internal_network", side_effect=create_side_effect
        ):
            proxy_ip, octet = pm._allocate_subnet_and_create_network("net-1")

        assert octet == 4
        assert proxy_ip == "10.199.4.100"
        # All conflict octets are released for future retries.
        for o in conflict_octets:
            assert o not in pm._active_octets

    def test_all_subnets_conflicting_raises(self) -> None:
        """Raises ProxyError when all 254 subnets are externally held."""
        pm = _make_pm()

        def always_conflict(name: str, *, subnet: str, proxy_ip: str) -> None:
            raise ProxyError(
                f"Failed to create internal network {name}: "
                f"Error: subnet {subnet} is already used"
            )

        with patch.object(
            pm, "_create_internal_network", side_effect=always_conflict
        ):
            with pytest.raises(
                ProxyError,
                match="All 254 subnets are in use or already claimed",
            ):
                pm._allocate_subnet_and_create_network("net-1")

    def test_non_conflict_error_propagates(self) -> None:
        """Non-subnet errors propagate immediately without retry."""
        pm = _make_pm()

        def permission_error(name: str, *, subnet: str, proxy_ip: str) -> None:
            raise ProxyError(
                f"Failed to create internal network {name}: permission denied"
            )

        with patch.object(
            pm, "_create_internal_network", side_effect=permission_error
        ):
            with pytest.raises(ProxyError, match="permission denied"):
                pm._allocate_subnet_and_create_network("net-1")

        # Octet should be released on non-conflict error.
        assert 1 not in pm._active_octets

    def test_non_conflict_error_releases_octet(self) -> None:
        """Non-conflict error releases the allocated octet."""
        pm = _make_pm()

        def generic_error(name: str, *, subnet: str, proxy_ip: str) -> None:
            raise ProxyError("some other failure")

        with patch.object(
            pm, "_create_internal_network", side_effect=generic_error
        ):
            with pytest.raises(ProxyError, match="some other failure"):
                pm._allocate_subnet_and_create_network("net-1")

        # Octet 1 should be freed; all 254 should be allocatable.
        octets = []
        for _ in range(254):
            _, _, octet = pm._allocate_subnet()
            octets.append(octet)
        assert len(set(octets)) == 254

    def test_conflict_then_non_conflict_error_propagates(self) -> None:
        """Conflict retry followed by a different error propagates."""
        pm = _make_pm()

        def mixed_errors(name: str, *, subnet: str, proxy_ip: str) -> None:
            if "10.199.1." in subnet:
                raise ProxyError(f"subnet {subnet} is already used")
            raise ProxyError("permission denied")

        with patch.object(
            pm, "_create_internal_network", side_effect=mixed_errors
        ):
            with pytest.raises(ProxyError, match="permission denied"):
                pm._allocate_subnet_and_create_network("net-1")

        # Both octets should be released.
        assert 1 not in pm._active_octets
        assert 2 not in pm._active_octets

    def test_wraparound_with_conflicts(self) -> None:
        """Retry wraps around octet space when conflicts span boundary."""
        pm = _make_pm()
        pm._next_subnet_octet = 253
        conflict_octets = {253, 254, 1}

        def create_side_effect(
            name: str, *, subnet: str, proxy_ip: str
        ) -> None:
            for o in conflict_octets:
                if f"10.199.{o}." in subnet:
                    raise ProxyError(f"subnet {subnet} is already used")

        with patch.object(
            pm, "_create_internal_network", side_effect=create_side_effect
        ):
            proxy_ip, octet = pm._allocate_subnet_and_create_network("net-1")

        assert octet == 2
        assert proxy_ip == "10.199.2.100"


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
        # The Dockerfile's default base image is used
        assert spec.build_args == {}

    def test_base_image_passed_as_build_arg(self, tmp_path: Path) -> None:
        """A configured base image becomes the BASE_IMAGE build argument."""
        (tmp_path / "proxy.dockerfile").write_text(
            "ARG BASE_IMAGE=docker.io/library/python:3.13\nFROM ${BASE_IMAGE}\n"
        )

        pm = _make_pm(proxy_dir=tmp_path, base_image="localhost/base:1")
        spec = pm._build_proxy_spec()

        assert spec.build_args == {PROXY_BASE_IMAGE_ARG: "localhost/base:1"}

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
    """Tests for ProxyManager._ensure_ca_cert().

    CA generation itself is covered in ``test_proxy_ca.py``.
    """

    def test_generates_ca_in_confdir_from_proxy_image(
        self, tmp_path: Path
    ) -> None:
        """Uses the shared confdir, proxy image and a prefixed name."""
        pm = _make_pm(container_command="docker", resource_prefix="airut-cli")
        cert = tmp_path / "mitmproxy-ca-cert.pem"

        with (
            patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path),
            patch(
                "airut.sandbox._proxy.ensure_ca_cert", return_value=cert
            ) as mock_ensure,
        ):
            result = pm._ensure_ca_cert()

        assert result == cert
        mock_ensure.assert_called_once_with(
            tmp_path,
            container_command="docker",
            image_tag="airut-proxy:test123",
            container_name="airut-cli-ca-init",
        )

    def test_generation_failure_raises_proxy_error(
        self, tmp_path: Path
    ) -> None:
        """A failed generation fails startup with a ProxyError."""
        pm = _make_pm()

        with (
            patch("airut.sandbox._proxy.MITMPROXY_CONFDIR", tmp_path),
            patch(
                "airut.sandbox._proxy.ensure_ca_cert",
                side_effect=CaCertError("generation did not finish"),
            ),
            pytest.raises(ProxyError, match="^generation did not finish$"),
        ):
            pm._ensure_ca_cert()


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


class _FakeClock:
    """Fake ``time.monotonic`` / ``time.sleep``: sleeping advances time."""

    def __init__(self) -> None:
        self.now = 1000.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


class _FakeProbe:
    """Fake ``podman exec`` readiness probe on a fake clock.

    Each probe takes *duration* seconds, or times out if its timeout is
    shorter.  A probe succeeds once the proxy is ready, *ready_at*
    seconds after the clock's start (never if None); before that it
    fails with a refused connection.

    Attributes:
        calls: (start time, command, keyword arguments) of each probe.
    """

    REFUSED = (
        "Traceback (most recent call last):\n"
        "ConnectionRefusedError: [Errno 111] Connection refused\n"
    )

    def __init__(
        self,
        clock: _FakeClock,
        *,
        ready_at: float | None,
        duration: float = 0.5,
    ) -> None:
        self._clock = clock
        self._start = clock.now
        self._ready_at = ready_at
        self._duration = duration
        self.calls: list[tuple[float, list[str], dict[str, object]]] = []

    def __call__(
        self, cmd: list[str], **kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((self._clock.now - self._start, cmd, kwargs))
        timeout = kwargs["timeout"]
        assert isinstance(timeout, float)
        if self._duration > timeout:
            self._clock.now += timeout
            raise subprocess.TimeoutExpired(cmd, timeout)
        self._clock.now += self._duration
        elapsed = self._clock.now - self._start
        if self._ready_at is not None and elapsed >= self._ready_at:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        raise subprocess.CalledProcessError(1, cmd, "", self.REFUSED)


def _wait(
    pm: ProxyManager,
    clock: _FakeClock,
    probe: Callable[..., subprocess.CompletedProcess[str]],
    container: str = "airut-proxy-task1",
) -> None:
    """Run _wait_for_proxy_ready() on *clock* with *probe* as exec."""
    with (
        patch("airut.sandbox._proxy.subprocess.run", probe),
        patch("airut.sandbox._proxy.time.monotonic", clock.monotonic),
        patch("airut.sandbox._proxy.time.sleep", clock.sleep),
    ):
        pm._wait_for_proxy_ready(container)


class TestWaitForProxyReady:
    """Tests for ProxyManager._wait_for_proxy_ready()."""

    def test_probes_ports_in_container(self) -> None:
        """Probes ports 80 and 443 inside the proxy container."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=0)

        _wait(_make_pm(), clock, probe)

        [(_, cmd, kwargs)] = probe.calls
        assert cmd[:5] == [
            "podman",
            "exec",
            "airut-proxy-task1",
            "python3",
            "-c",
        ]
        assert "('127.0.0.1', 80)" in cmd[5]
        assert "('127.0.0.1', 443)" in cmd[5]
        assert kwargs["check"] is True

    def test_returns_as_soon_as_ready(self) -> None:
        """Stops probing at the first successful probe."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=1.0)

        _wait(_make_pm(), clock, probe)

        # Probes at 0.0 (fails, 0.5) and 0.7 (succeeds, 1.2): no more
        # probes and no waiting for the timeout.
        assert [start for start, _, _ in probe.calls] == pytest.approx(
            [0.0, 0.7]
        )
        assert clock.now - 1000.0 == pytest.approx(1.2)

    def test_slow_start_within_default_timeout(self) -> None:
        """A proxy taking seconds to start on a slow host is waited for."""
        clock = _FakeClock()
        # Slow host: each exec takes 1.5 s, the proxy listens after 6 s.
        probe = _FakeProbe(clock, ready_at=6.0, duration=1.5)

        _wait(_make_pm(), clock, probe)

        assert len(probe.calls) == 4
        assert clock.now - 1000.0 < 10.0

    def test_honours_configured_timeout(self) -> None:
        """A longer configured timeout waits past the default."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=45.0)

        _wait(_make_pm(proxy_ready_timeout=60.0), clock, probe)

        assert clock.now - 1000.0 == pytest.approx(45.0, abs=0.7)

    def test_fails_when_configured_timeout_runs_out(self) -> None:
        """A shorter configured timeout fails once it has elapsed."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=None)

        with pytest.raises(ProxyError):
            _wait(_make_pm(proxy_ready_timeout=12.0), clock, probe)

        starts = [start for start, _, _ in probe.calls]
        # Probed until the deadline, and not past it.
        assert starts[-1] < 12.0 <= starts[-1] + 0.5 + 0.2
        assert clock.now - 1000.0 >= 12.0

    def test_probe_may_run_until_deadline(self) -> None:
        """A slow probe is not cut short before the overall deadline."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=None)

        with pytest.raises(ProxyError):
            _wait(_make_pm(proxy_ready_timeout=12.0), clock, probe)

        timeouts = [kwargs["timeout"] for _, _, kwargs in probe.calls]
        assert timeouts[0] == pytest.approx(12.0)
        assert timeouts[1] == pytest.approx(12.0 - 0.7)

    def test_timeout_message_names_proxy_and_last_failure(self) -> None:
        """The error says which proxy, how long, and why it was not ready."""
        clock = _FakeClock()
        probe = _FakeProbe(clock, ready_at=None)

        with pytest.raises(ProxyError) as exc_info:
            _wait(_make_pm(proxy_ready_timeout=12.0), clock, probe)

        assert str(exc_info.value) == (
            "Proxy airut-proxy-task1 did not accept connections on ports "
            "80 and 443 within 12s (last probe failure: "
            "ConnectionRefusedError: [Errno 111] Connection refused)"
        )

    def test_timeout_message_survives_cut_off_final_probe(self) -> None:
        """A probe cut off at the deadline does not hide the last failure."""
        clock = _FakeClock()
        # Probes start every 1.7 s; the one starting at 11.9 is cut off
        # at the deadline, 12.
        probe = _FakeProbe(clock, ready_at=None, duration=1.5)

        with pytest.raises(
            ProxyError,
            match=r"\(last probe failure: ConnectionRefusedError: .*\)$",
        ):
            _wait(_make_pm(proxy_ready_timeout=12.0), clock, probe)

        assert clock.now - 1000.0 == pytest.approx(12.0)

    def test_timeout_message_without_stderr(self) -> None:
        """A failed probe without stderr is reported by exit status."""
        clock = _FakeClock()

        def probe(
            cmd: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            clock.now += 1.0
            raise subprocess.CalledProcessError(125, cmd, "", "")

        with pytest.raises(
            ProxyError,
            match=r"within 5s \(last probe failure: exit status 125\)$",
        ):
            _wait(_make_pm(proxy_ready_timeout=5.0), clock, probe)

    def test_timeout_message_after_hung_probe(self) -> None:
        """A probe still running at the deadline is reported as such."""
        clock = _FakeClock()

        def probe(
            cmd: list[str], **kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            timeout = kwargs["timeout"]
            assert isinstance(timeout, float)
            clock.now += timeout
            raise subprocess.TimeoutExpired(cmd, timeout)

        with pytest.raises(
            ProxyError, match=r"within 30s \(no probe finished\)$"
        ):
            _wait(_make_pm(), clock, probe)


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
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
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
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
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

        # Verify cleanup was called: container/network removed both
        # for stale cleanup (before creation) and error cleanup (after
        # _run_proxy_container fails).
        container_name = f"{CONTEXT_PROXY_PREFIX}task-1"
        network_name = f"{CONTEXT_NETWORK_PREFIX}task-1"
        assert mock_rm_container.call_count == 2
        mock_rm_container.assert_any_call(container_name)
        assert mock_rm_network.call_count == 2
        mock_rm_network.assert_any_call(network_name)
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
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
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

    def test_force_cleans_stale_network_by_name(self) -> None:
        """start_proxy force-removes network by name before creating it.

        When a previous execution fails (e.g. ENOSPC) and stop_proxy
        can't remove the network (e.g. workload container still
        connected), the network is orphaned.  On retry, stop_proxy()
        finds nothing in _active_proxies, so the stale network blocks
        creation.  start_proxy must force-remove the network by name.
        """
        pm = _make_pm()

        with (
            patch.object(pm, "stop_proxy") as mock_stop,
            patch.object(pm, "_remove_container") as mock_rm_container,
            patch.object(pm, "_remove_network") as mock_rm_network,
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )

        # stop_proxy(context_id) called for tracked proxy cleanup
        mock_stop.assert_called_once_with("task-1")

        # Force-remove by name called BEFORE network creation
        mock_rm_container.assert_called_once_with(
            f"{CONTEXT_PROXY_PREFIX}task-1"
        )
        mock_rm_network.assert_called_once_with(
            f"{CONTEXT_NETWORK_PREFIX}task-1"
        )

        # Cleanup temp files
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)

    def test_retry_succeeds_after_stale_network(self) -> None:
        """Simulates the full failure-then-retry scenario.

        1. First start_proxy succeeds, network created
        2. Container execution fails, stop_proxy called
        3. stop_proxy pops from _active_proxies, removes container,
           but _remove_network silently fails (workload still connected)
        4. Network is now orphaned (not in _active_proxies, not removed)
        5. Second start_proxy: stop_proxy finds nothing in _active_proxies
        6. Force-remove by name removes the stale network
        7. Network creation succeeds
        """
        pm = _make_pm()

        network_name = f"{CONTEXT_NETWORK_PREFIX}task-1"
        create_network_calls: list[str] = []

        def track_create_network(
            name: str, *, subnet: str, proxy_ip: str
        ) -> None:
            create_network_calls.append(name)

        # Track which _remove_network calls succeed vs fail.
        # The network sticks around until the force-remove in
        # the second start_proxy call.
        stale_network_exists = False
        remove_network_log: list[tuple[str, bool]] = []

        def selective_remove_network(name: str) -> None:
            nonlocal stale_network_exists
            if name == network_name and stale_network_exists:
                # First removal attempt during stop_proxy fails
                # (container still connected).  Second attempt
                # during force-remove in start_proxy succeeds.
                stale_network_exists = False
                remove_network_log.append((name, True))
                return
            remove_network_log.append((name, True))

        with (
            patch.object(
                pm,
                "_create_internal_network",
                side_effect=track_create_network,
            ),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
            patch.object(pm, "_remove_container"),
            patch.object(
                pm,
                "_remove_network",
                side_effect=selective_remove_network,
            ),
        ):
            # Step 1: First start succeeds
            pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )
            assert "task-1" in pm._active_proxies

            # Step 2-3: stop_proxy runs but _remove_network is a
            # silent no-op for the stale network (simulating docker
            # failing because a workload container is still connected)
            stale_network_exists = True
            pm.stop_proxy("task-1")
            assert "task-1" not in pm._active_proxies

            # Step 5-7: Retry — force-remove by name cleans the
            # stale network, then _create_internal_network succeeds
            proxy2 = pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )

        assert proxy2.network_name == network_name
        assert "task-1" in pm._active_proxies
        assert len(create_network_calls) == 2

        # Cleanup
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
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

    def test_ensures_proxy_image_before_running_container(
        self, tmp_path: Path
    ) -> None:
        """start_proxy rebuilds proxy image if it was pruned after startup.

        Regression test: the proxy image was only built at gateway startup
        and cached in _proxy_image_tag.  If the GC thread pruned the image,
        start_proxy would fail with a 'short-name did not resolve' error
        because the image no longer existed locally.  start_proxy must call
        _ensure_proxy_image() so the image is rebuilt when missing.
        """
        mock_cache = MagicMock(spec=ImageCache)
        mock_cache.ensure.return_value = "airut-proxy:abc123"
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.write_text("FROM python:3.13\n")

        pm = _make_pm(
            proxy_dir=tmp_path,
            image_cache=mock_cache,
            proxy_image_tag=None,
        )
        # Simulate: image was built at startup, then pruned by GC.
        # _proxy_image_tag is still set (from startup) but image is gone.
        pm._proxy_image_tag = "airut-proxy:old-stale-tag"

        with (
            patch.object(pm, "stop_proxy"),
            patch.object(pm, "_remove_container"),
            patch.object(pm, "_remove_network"),
            patch.object(
                pm,
                "_allocate_subnet",
                return_value=("10.199.1.0/24", "10.199.1.100", 1),
            ),
            patch.object(pm, "_create_internal_network"),
            patch.object(pm, "_run_proxy_container"),
            patch.object(pm, "_wait_for_proxy_ready"),
        ):
            pm.start_proxy(
                "task-1",
                allowlist_json=b"[]",
                replacements_json=b"{}",
            )

        # _ensure_proxy_image must have been called (via ImageCache.ensure)
        mock_cache.ensure.assert_called_once()
        # The tag should be updated from the ensure call
        assert pm._proxy_image_tag == "airut-proxy:abc123"

        # Cleanup
        for path in pm._allowlist_tmpfiles.values():
            path.unlink(missing_ok=True)
        for path in pm._replacement_tmpfiles.values():
            path.unlink(missing_ok=True)


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
