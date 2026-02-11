# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for per-task proxy lifecycle management."""

import subprocess
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from lib.container.proxy import (
    CA_CERT_FILENAME,
    CONV_NETWORK_PREFIX,
    CONV_PROXY_PREFIX,
    EGRESS_NETWORK,
    NETWORK_LOG_FILENAME,
    PROXY_IMAGE_NAME,
    ProxyError,
    ProxyManager,
    TaskProxy,
    get_ca_cert_path,
)
from lib.git_mirror import GitMirrorCache


#: Upstream DNS value used across all ProxyManager tests.
_TEST_UPSTREAM_DNS = "9.9.9.9"


@pytest.fixture
def mock_mirror() -> MagicMock:
    """Create a mock GitMirrorCache for ProxyManager tests."""
    mirror = MagicMock(spec=GitMirrorCache)
    mirror.read_file.return_value = b"domains: []\nurl_prefixes: []\n"
    return mirror


def _make_pm(
    **kwargs: object,
) -> ProxyManager:
    """Create a ProxyManager with default args."""
    kwargs.setdefault("upstream_dns", _TEST_UPSTREAM_DNS)
    return ProxyManager(**kwargs)  # type: ignore[arg-type]


class TestTaskProxy:
    """Tests for TaskProxy dataclass."""

    def test_all_fields(self) -> None:
        """All fields set correctly."""
        tp = TaskProxy(
            network_name="airut-conv-x",
            proxy_container_name="airut-proxy-x",
            proxy_ip="10.199.1.100",
        )
        assert tp.network_name == "airut-conv-x"
        assert tp.proxy_container_name == "airut-proxy-x"
        assert tp.proxy_ip == "10.199.1.100"

    def test_frozen(self) -> None:
        """TaskProxy is immutable."""
        tp = TaskProxy(
            network_name="n",
            proxy_container_name="c",
            proxy_ip="10.199.1.100",
        )
        with pytest.raises(AttributeError):
            tp.network_name = "other"  # type: ignore[misc]


class TestProxyManagerInit:
    """Tests for ProxyManager initialization."""

    def test_defaults(self) -> None:
        """Default values set correctly."""
        pm = _make_pm()
        assert pm._cmd == "podman"
        assert pm._docker_dir == Path("docker")
        assert pm._upstream_dns == _TEST_UPSTREAM_DNS
        assert isinstance(pm._lock, type(threading.Lock()))

    def test_upstream_dns_required(self) -> None:
        """upstream_dns is a required keyword argument."""
        with pytest.raises(TypeError, match="upstream_dns"):
            ProxyManager()  # type: ignore[call-arg]

    def test_custom(self) -> None:
        """Custom values set correctly."""
        pm = _make_pm(
            container_command="docker",
            docker_dir=Path("/tmp/docker"),
            upstream_dns="8.8.8.8",
        )
        assert pm._cmd == "docker"
        assert pm._docker_dir == Path("/tmp/docker")
        assert pm._upstream_dns == "8.8.8.8"


class TestProxyManagerStartup:
    """Tests for ProxyManager.startup()."""

    @patch.object(ProxyManager, "_cleanup_orphans")
    @patch.object(ProxyManager, "_build_image")
    @patch.object(ProxyManager, "_ensure_ca_cert")
    @patch.object(ProxyManager, "_recreate_egress_network")
    def test_startup_sequence(
        self,
        mock_recreate: MagicMock,
        mock_ca: MagicMock,
        mock_build: MagicMock,
        mock_cleanup: MagicMock,
    ) -> None:
        """Startup calls steps in correct order."""
        pm = _make_pm()
        pm.startup()
        mock_cleanup.assert_called_once()
        mock_build.assert_called_once()
        mock_ca.assert_called_once()
        mock_recreate.assert_called_once()


class TestProxyManagerShutdown:
    """Tests for ProxyManager.shutdown()."""

    @patch.object(ProxyManager, "stop_task_proxy")
    @patch.object(ProxyManager, "_remove_network")
    def test_shutdown_stops_active_and_removes_egress(
        self,
        mock_rm_net: MagicMock,
        mock_stop: MagicMock,
    ) -> None:
        """Shutdown stops active proxies and removes egress network."""
        pm = _make_pm()
        # Simulate active proxies
        pm._active_proxies["task1"] = TaskProxy(
            network_name="n1",
            proxy_container_name="c1",
            proxy_ip="10.199.1.100",
        )
        pm._active_proxies["task2"] = TaskProxy(
            network_name="n2",
            proxy_container_name="c2",
            proxy_ip="10.199.2.100",
        )
        pm.shutdown()
        assert mock_stop.call_count == 2
        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)

    @patch.object(ProxyManager, "stop_task_proxy", side_effect=RuntimeError)
    @patch.object(ProxyManager, "_remove_network")
    def test_shutdown_continues_on_stop_error(
        self,
        mock_rm_net: MagicMock,
        mock_stop: MagicMock,
    ) -> None:
        """Shutdown continues even if individual stop fails."""
        pm = _make_pm()
        pm._active_proxies["task1"] = TaskProxy(
            network_name="n1",
            proxy_container_name="c1",
            proxy_ip="10.199.1.100",
        )
        pm.shutdown()
        mock_rm_net.assert_called_once_with(EGRESS_NETWORK)


class TestStartTaskProxy:
    """Tests for ProxyManager.start_task_proxy()."""

    @patch.object(ProxyManager, "_wait_for_proxy_ready")
    @patch.object(ProxyManager, "_run_proxy_container")
    @patch.object(ProxyManager, "_create_internal_network")
    @patch.object(ProxyManager, "stop_task_proxy")
    def test_creates_network_and_container(
        self,
        mock_stop: MagicMock,
        mock_create: MagicMock,
        mock_run: MagicMock,
        mock_health: MagicMock,
        mock_mirror: MagicMock,
    ) -> None:
        """Creates internal network, starts proxy, and checks health."""
        pm = _make_pm()
        result = pm.start_task_proxy("abc123", mirror=mock_mirror)
        assert result.network_name == f"{CONV_NETWORK_PREFIX}abc123"
        assert result.proxy_container_name == f"{CONV_PROXY_PREFIX}abc123"
        assert result.proxy_ip.startswith("10.199.")
        assert result.proxy_ip.endswith(".100")
        # Idempotent: stops any existing proxy first
        mock_stop.assert_called_once_with("abc123")
        mock_create.assert_called_once()
        # Verify internal network created with subnet and proxy_ip
        create_kwargs = mock_create.call_args.kwargs
        assert "subnet" in create_kwargs
        assert "proxy_ip" in create_kwargs
        # Allowlist extracted from mirror
        mock_mirror.read_file.assert_called_once_with(
            ".airut/network-allowlist.yaml"
        )
        mock_health.assert_called_once_with(f"{CONV_PROXY_PREFIX}abc123")
        assert "abc123" in pm._active_proxies

    @patch.object(ProxyManager, "_wait_for_proxy_ready")
    @patch.object(ProxyManager, "_run_proxy_container")
    @patch.object(ProxyManager, "_create_internal_network")
    @patch.object(ProxyManager, "stop_task_proxy")
    def test_creates_network_log_when_session_dir_provided(
        self,
        mock_stop: MagicMock,
        mock_create: MagicMock,
        mock_run: MagicMock,
        mock_health: MagicMock,
        mock_mirror: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Creates network log file when conversation_dir is provided."""
        pm = _make_pm()
        result = pm.start_task_proxy(
            "abc123", mirror=mock_mirror, conversation_dir=tmp_path
        )
        assert result.network_name == f"{CONV_NETWORK_PREFIX}abc123"
        # Network log file should be created
        log_path = tmp_path / NETWORK_LOG_FILENAME
        assert log_path.exists()
        assert "abc123" in pm._network_log_files
        assert pm._network_log_files["abc123"] == log_path
        # Run should be called with the log path
        mock_run.assert_called_once()
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs.get("network_log_path") == log_path

    @patch.object(ProxyManager, "_remove_network")
    @patch.object(ProxyManager, "_remove_container")
    @patch.object(
        ProxyManager, "_run_proxy_container", side_effect=ProxyError("fail")
    )
    @patch.object(ProxyManager, "_create_internal_network")
    @patch.object(ProxyManager, "stop_task_proxy")
    def test_cleans_up_on_container_failure(
        self,
        mock_stop: MagicMock,
        mock_create: MagicMock,
        mock_run: MagicMock,
        mock_rm_container: MagicMock,
        mock_rm_net: MagicMock,
        mock_mirror: MagicMock,
    ) -> None:
        """Cleans up container, network, and temp on failure."""
        pm = _make_pm()
        with pytest.raises(ProxyError, match="fail"):
            pm.start_task_proxy("xyz", mirror=mock_mirror)
        mock_rm_container.assert_called_once_with(f"{CONV_PROXY_PREFIX}xyz")
        mock_rm_net.assert_called_once_with(f"{CONV_NETWORK_PREFIX}xyz")
        assert "xyz" not in pm._active_proxies
        # Temp file should be cleaned up
        assert "xyz" not in pm._allowlist_tmpfiles

    @patch.object(ProxyManager, "_remove_network")
    @patch.object(ProxyManager, "_remove_container")
    @patch.object(
        ProxyManager,
        "_wait_for_proxy_ready",
        side_effect=ProxyError("not ready"),
    )
    @patch.object(ProxyManager, "_run_proxy_container")
    @patch.object(ProxyManager, "_create_internal_network")
    @patch.object(ProxyManager, "stop_task_proxy")
    def test_cleans_up_on_health_check_failure(
        self,
        mock_stop: MagicMock,
        mock_create: MagicMock,
        mock_run: MagicMock,
        mock_health: MagicMock,
        mock_rm_container: MagicMock,
        mock_rm_net: MagicMock,
        mock_mirror: MagicMock,
    ) -> None:
        """Removes container, network, and temp file if health check fails."""
        pm = _make_pm()
        with pytest.raises(ProxyError, match="not ready"):
            pm.start_task_proxy("hc", mirror=mock_mirror)
        mock_rm_container.assert_called_once_with(f"{CONV_PROXY_PREFIX}hc")
        mock_rm_net.assert_called_once_with(f"{CONV_NETWORK_PREFIX}hc")
        assert "hc" not in pm._active_proxies

    @patch.object(ProxyManager, "_wait_for_proxy_ready")
    @patch.object(ProxyManager, "_run_proxy_container")
    @patch.object(ProxyManager, "_create_internal_network")
    @patch.object(ProxyManager, "_remove_network")
    @patch.object(ProxyManager, "_remove_container")
    def test_idempotent_cleans_stale_proxy(
        self,
        mock_rm_container: MagicMock,
        mock_rm_net: MagicMock,
        mock_create: MagicMock,
        mock_run: MagicMock,
        mock_health: MagicMock,
        mock_mirror: MagicMock,
    ) -> None:
        """Tears down stale proxy before starting a new one."""
        pm = _make_pm()
        # Pre-populate a stale proxy for the same task_id
        pm._active_proxies["dup"] = TaskProxy(
            network_name="old-net",
            proxy_container_name="old-container",
            proxy_ip="10.199.99.100",
        )
        result = pm.start_task_proxy("dup", mirror=mock_mirror)
        # Old resources cleaned up
        mock_rm_container.assert_any_call("old-container")
        mock_rm_net.assert_any_call("old-net")
        # New proxy returned
        assert result.proxy_container_name == f"{CONV_PROXY_PREFIX}dup"


class TestStopTaskProxy:
    """Tests for ProxyManager.stop_task_proxy()."""

    @patch.object(ProxyManager, "_remove_network")
    @patch.object(ProxyManager, "_remove_container")
    def test_stops_and_removes(
        self,
        mock_rm_container: MagicMock,
        mock_rm_net: MagicMock,
    ) -> None:
        """Stops container, removes network, and cleans up temp file."""
        pm = _make_pm()
        pm._active_proxies["abc"] = TaskProxy(
            network_name="n-abc",
            proxy_container_name="c-abc",
            proxy_ip="10.199.1.100",
        )
        # Simulate a temp file
        tmp = Path("/tmp/fake-allowlist.yaml")
        pm._allowlist_tmpfiles["abc"] = tmp
        # Simulate a network log file (tracking only, file stays)
        pm._network_log_files["abc"] = Path("/tmp/fake-network.log")
        pm.stop_task_proxy("abc")
        mock_rm_container.assert_called_once_with("c-abc")
        mock_rm_net.assert_called_once_with("n-abc")
        assert "abc" not in pm._active_proxies
        assert "abc" not in pm._allowlist_tmpfiles
        # Network log tracking removed but file not deleted
        assert "abc" not in pm._network_log_files

    @patch.object(ProxyManager, "_remove_network")
    @patch.object(ProxyManager, "_remove_container")
    def test_noop_for_unknown_task(
        self,
        mock_rm_container: MagicMock,
        mock_rm_net: MagicMock,
    ) -> None:
        """Does nothing for unknown task ID."""
        pm = _make_pm()
        pm.stop_task_proxy("nonexistent")
        mock_rm_container.assert_not_called()
        mock_rm_net.assert_not_called()


class TestBuildImage:
    """Tests for ProxyManager._build_image()."""

    def test_missing_dockerfile(self, tmp_path: Path) -> None:
        """Raises ProxyError if Dockerfile missing."""
        pm = _make_pm(docker_dir=tmp_path)
        with pytest.raises(ProxyError, match="Proxy Dockerfile not found"):
            pm._build_image()

    @patch("lib.container.proxy.subprocess.run")
    def test_build_success(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Builds image with correct command."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.touch()
        pm = _make_pm(docker_dir=tmp_path)
        pm._build_image()
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "build"
        assert "-t" in cmd
        assert PROXY_IMAGE_NAME in cmd

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman", stderr="err"),
    )
    def test_build_failure(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Raises ProxyError on build failure."""
        dockerfile = tmp_path / "proxy.dockerfile"
        dockerfile.touch()
        pm = _make_pm(docker_dir=tmp_path)
        with pytest.raises(ProxyError, match="Proxy image build failed"):
            pm._build_image()


class TestEnsureCaCert:
    """Tests for ProxyManager._ensure_ca_cert()."""

    def test_cert_exists(self, tmp_path: Path) -> None:
        """Returns path when cert already exists."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.touch()
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            pm = _make_pm()
            result = pm._ensure_ca_cert()
            assert result == cert

    @patch("lib.container.proxy.subprocess.Popen")
    def test_generates_cert(
        self,
        mock_popen: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Generates cert by running mitmdump with entrypoint override."""
        cert_path = tmp_path / CA_CERT_FILENAME

        # Simulate cert appearing after Popen starts
        proc = MagicMock()
        mock_popen.return_value = proc

        def create_cert_on_sleep(duration: float) -> None:
            cert_path.touch()

        with (
            patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path),
            patch("lib.container.proxy.time.sleep", create_cert_on_sleep),
        ):
            pm = _make_pm()
            result = pm._ensure_ca_cert()

        assert result == cert_path
        proc.terminate.assert_called_once()
        proc.wait.assert_called_once()
        # Verify --entrypoint bash overrides proxy-entrypoint.sh
        cmd = mock_popen.call_args[0][0]
        assert "--entrypoint" in cmd
        assert "bash" in cmd

    @patch("lib.container.proxy.subprocess.Popen")
    @patch("lib.container.proxy.time.sleep")
    def test_fails_when_cert_not_generated(
        self,
        mock_sleep: MagicMock,
        mock_popen: MagicMock,
        tmp_path: Path,
    ) -> None:
        """Raises ProxyError when cert generation times out."""
        proc = MagicMock()
        mock_popen.return_value = proc

        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            pm = _make_pm()
            with pytest.raises(
                ProxyError, match="Failed to generate CA certificate"
            ):
                pm._ensure_ca_cert()


class TestRunProxyContainer:
    """Tests for ProxyManager._run_proxy_container()."""

    @patch("lib.container.proxy.subprocess.run")
    def test_correct_command(self, mock_run: MagicMock, tmp_path: Path) -> None:
        """Runs proxy with correct podman arguments."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("domains: []\n")

        pm = _make_pm(docker_dir=tmp_path)
        pm._run_proxy_container(
            "airut-proxy-abc",
            "airut-conv-abc",
            "10.199.1.100",
            allowlist,
        )
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert "run" in cmd
        assert "--rm" in cmd
        assert "-d" in cmd
        assert "--name" in cmd
        assert "airut-proxy-abc" in cmd
        # Check both networks with static IP on internal
        network_indices = [i for i, v in enumerate(cmd) if v == "--network"]
        networks = [cmd[i + 1] for i in network_indices]
        assert EGRESS_NETWORK in networks
        assert any("airut-conv-abc:ip=10.199.1.100" in n for n in networks)
        # Check environment variables
        env_indices = [i for i, v in enumerate(cmd) if v == "-e"]
        env_args = [cmd[i + 1] for i in env_indices]
        assert "PROXY_IP=10.199.1.100" in env_args
        assert f"UPSTREAM_DNS={_TEST_UPSTREAM_DNS}" in env_args
        # Check allowlist volume mount
        volume_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        volumes = [cmd[i + 1] for i in volume_indices]
        assert any(
            "allowlist.yaml:/network-allowlist.yaml:ro" in v for v in volumes
        )
        # proxy_filter.py is COPY'd into the image, not mounted
        assert not any("proxy_filter.py" in v for v in volumes)

    @patch("lib.container.proxy.subprocess.run")
    def test_mounts_network_log_when_provided(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Mounts network log file when path is provided."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("domains: []\n")

        log_path = tmp_path / "network-sandbox.log"
        log_path.touch()
        pm = _make_pm(docker_dir=tmp_path)
        pm._run_proxy_container(
            "airut-proxy-abc",
            "airut-conv-abc",
            "10.199.1.100",
            allowlist,
            network_log_path=log_path,
        )
        cmd = mock_run.call_args[0][0]
        # Check network log volume mount
        volume_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        volumes = [cmd[i + 1] for i in volume_indices]
        assert any(
            "network-sandbox.log:/network-sandbox.log:rw" in v for v in volumes
        )

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman", stderr="err"),
    )
    def test_failure_raises(self, mock_run: MagicMock) -> None:
        """Raises ProxyError on container start failure."""
        pm = _make_pm()
        with pytest.raises(ProxyError, match="Failed to start proxy"):
            pm._run_proxy_container(
                "c", "n", "10.199.1.100", Path("/tmp/fake.yaml")
            )


class TestExtractAllowlist:
    """Tests for ProxyManager._extract_allowlist()."""

    def test_extracts_to_tmpfile(self, mock_mirror: MagicMock) -> None:
        """Extracts allowlist from mirror to a temp file."""
        pm = _make_pm()
        path = pm._extract_allowlist("task1", mirror=mock_mirror)
        try:
            assert path.exists()
            assert path.read_bytes() == b"domains: []\nurl_prefixes: []\n"
            assert "task1" in pm._allowlist_tmpfiles
            assert pm._allowlist_tmpfiles["task1"] == path
        finally:
            path.unlink(missing_ok=True)

    def test_raises_on_mirror_error(self, mock_mirror: MagicMock) -> None:
        """Raises ProxyError if mirror read fails."""
        mock_mirror.read_file.side_effect = RuntimeError("mirror broken")
        pm = _make_pm()
        with pytest.raises(ProxyError, match="Failed to read allowlist"):
            pm._extract_allowlist("task1", mirror=mock_mirror)


class TestCleanupAllowlist:
    """Tests for ProxyManager._cleanup_allowlist()."""

    def test_removes_tmpfile(self, tmp_path: Path) -> None:
        """Removes the temp file and tracking entry."""
        tmpfile = tmp_path / "allowlist.yaml"
        tmpfile.write_text("test")
        pm = _make_pm()
        pm._allowlist_tmpfiles["task1"] = tmpfile
        pm._cleanup_allowlist("task1")
        assert not tmpfile.exists()
        assert "task1" not in pm._allowlist_tmpfiles

    def test_noop_for_unknown_task(self) -> None:
        """Does nothing for unknown task ID."""
        pm = _make_pm()
        pm._cleanup_allowlist("nonexistent")  # Should not raise


class TestNetworkLogOperations:
    """Tests for network log file operations."""

    def test_create_network_log(self, tmp_path: Path) -> None:
        """Creates empty log file in session directory."""
        pm = _make_pm()
        log_path = pm._create_network_log("task1", tmp_path)
        assert log_path == tmp_path / NETWORK_LOG_FILENAME
        assert log_path.exists()
        assert "task1" in pm._network_log_files
        assert pm._network_log_files["task1"] == log_path

    def test_create_network_log_idempotent(self, tmp_path: Path) -> None:
        """Creating log file multiple times is idempotent."""
        pm = _make_pm()
        # Pre-existing file with content
        log_path = tmp_path / NETWORK_LOG_FILENAME
        log_path.write_text("existing content")
        result = pm._create_network_log("task1", tmp_path)
        assert result == log_path
        # File should still exist with content preserved
        assert log_path.exists()
        assert log_path.read_text() == "existing content"

    def test_cleanup_network_log_removes_tracking(self) -> None:
        """Cleanup removes tracking but not the file itself."""
        pm = _make_pm()
        pm._network_log_files["task1"] = Path("/tmp/fake-log.log")
        pm._cleanup_network_log("task1")
        assert "task1" not in pm._network_log_files

    def test_cleanup_network_log_noop_for_unknown(self) -> None:
        """Cleanup is safe for unknown task IDs."""
        pm = _make_pm()
        pm._cleanup_network_log("nonexistent")  # Should not raise


class TestReplacementMapOperations:
    """Tests for replacement map file operations."""

    def test_write_replacement_map(self, tmp_path: Path) -> None:
        """Writes replacement map to temp file."""
        from lib.gateway.config import ReplacementEntry

        pm = _make_pm()
        replacement_map = {
            "ghp_surrogate123": ReplacementEntry(
                real_value="ghp_real456",
                scopes=("api.github.com",),
                headers=("Authorization",),
            )
        }
        path = pm._write_replacement_map("task1", replacement_map)
        try:
            assert path.exists()
            import json

            data = json.loads(path.read_text())
            assert "ghp_surrogate123" in data
            assert data["ghp_surrogate123"]["value"] == "ghp_real456"
            assert data["ghp_surrogate123"]["scopes"] == ["api.github.com"]
            assert data["ghp_surrogate123"]["headers"] == ["Authorization"]
            assert "task1" in pm._replacement_tmpfiles
            assert pm._replacement_tmpfiles["task1"] == path
        finally:
            path.unlink(missing_ok=True)

    def test_write_signing_credential_replacement_map(self) -> None:
        """Writes SigningCredentialEntry via replacement map."""
        from lib.gateway.config import (
            SIGNING_TYPE_AWS_SIGV4,
            SigningCredentialEntry,
        )

        pm = _make_pm()
        replacement_map = {
            "AKIA_SURROGATE1234567": SigningCredentialEntry(
                access_key_id="AKIAIOSFODNN7EXAMPLE",
                secret_access_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                session_token=None,
                surrogate_session_token=None,
                scopes=("s3.us-east-1.amazonaws.com",),
            )
        }
        path = pm._write_replacement_map("task2", replacement_map)
        try:
            import json

            data = json.loads(path.read_text())
            entry = data["AKIA_SURROGATE1234567"]
            assert entry["type"] == SIGNING_TYPE_AWS_SIGV4
            assert entry["access_key_id"] == "AKIAIOSFODNN7EXAMPLE"
            assert (
                entry["secret_access_key"]
                == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            )
            assert entry["session_token"] is None
            assert entry["surrogate_session_token"] is None
            assert entry["scopes"] == ["s3.us-east-1.amazonaws.com"]
        finally:
            path.unlink(missing_ok=True)

    def test_write_empty_replacement_map(self) -> None:
        """Empty replacement map creates empty JSON file."""
        pm = _make_pm()
        path = pm._write_replacement_map("task1", {})
        try:
            assert path.exists()
            import json

            data = json.loads(path.read_text())
            assert data == {}
        finally:
            path.unlink(missing_ok=True)

    def test_cleanup_replacement_map(self, tmp_path: Path) -> None:
        """Cleanup removes temp file and tracking."""
        tmpfile = tmp_path / "replacements.json"
        tmpfile.write_text("{}")
        pm = _make_pm()
        pm._replacement_tmpfiles["task1"] = tmpfile
        pm._cleanup_replacement_map("task1")
        assert not tmpfile.exists()
        assert "task1" not in pm._replacement_tmpfiles

    def test_cleanup_replacement_map_noop_for_unknown(self) -> None:
        """Cleanup is safe for unknown task IDs."""
        pm = _make_pm()
        pm._cleanup_replacement_map("nonexistent")  # Should not raise


class TestRunProxyContainerWithReplacement:
    """Tests for _run_proxy_container with replacement map."""

    @patch("lib.container.proxy.subprocess.run")
    def test_mounts_replacement_map_when_provided(
        self, mock_run: MagicMock, tmp_path: Path
    ) -> None:
        """Mounts replacement map file when path is provided."""
        allowlist = tmp_path / "allowlist.yaml"
        allowlist.write_text("domains: []\n")

        replacement_path = tmp_path / "replacements.json"
        replacement_path.write_text("{}")
        pm = _make_pm(docker_dir=tmp_path)
        pm._run_proxy_container(
            "airut-proxy-abc",
            "airut-conv-abc",
            "10.199.1.100",
            allowlist,
            replacement_path=replacement_path,
        )
        cmd = mock_run.call_args[0][0]
        # Check replacement map volume mount
        volume_indices = [i for i, v in enumerate(cmd) if v == "-v"]
        volumes = [cmd[i + 1] for i in volume_indices]
        assert any(
            "replacements.json:/replacements.json:ro" in v for v in volumes
        )


class TestRemoveContainer:
    """Tests for ProxyManager._remove_container()."""

    @patch("lib.container.proxy.subprocess.run")
    def test_removes_container(self, mock_run: MagicMock) -> None:
        """Runs podman rm -f."""
        pm = _make_pm()
        pm._remove_container("test-container")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd == ["podman", "rm", "-f", "test-container"]

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman"),
    )
    def test_ignores_already_gone(self, mock_run: MagicMock) -> None:
        """Does not raise if container already removed."""
        pm = _make_pm()
        pm._remove_container("gone")  # Should not raise


class TestNetworkOperations:
    """Tests for network create/remove operations."""

    @patch("lib.container.proxy.subprocess.run")
    def test_create_internal_network(self, mock_run: MagicMock) -> None:
        """Creates internal network with correct flags."""
        pm = _make_pm()
        pm._create_internal_network(
            "test-net",
            subnet="10.199.1.0/24",
            proxy_ip="10.199.1.100",
        )
        cmd = mock_run.call_args[0][0]
        assert "--internal" in cmd
        assert "--disable-dns" in cmd
        assert "--subnet" in cmd
        subnet_idx = cmd.index("--subnet")
        assert cmd[subnet_idx + 1] == "10.199.1.0/24"
        assert "--route" in cmd
        route_idx = cmd.index("--route")
        assert "0.0.0.0/0,10.199.1.100," in cmd[route_idx + 1]
        assert "test-net" in cmd

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman", stderr="err"),
    )
    def test_create_internal_network_failure(self, mock_run: MagicMock) -> None:
        """Raises ProxyError on internal network creation failure."""
        pm = _make_pm()
        with pytest.raises(ProxyError, match="Failed to create internal"):
            pm._create_internal_network(
                "bad-net",
                subnet="10.199.1.0/24",
                proxy_ip="10.199.1.100",
            )

    @patch("lib.container.proxy.subprocess.run")
    def test_create_egress_network(self, mock_run: MagicMock) -> None:
        """Creates egress network with metric option."""
        pm = _make_pm()
        pm._create_egress_network()
        cmd = mock_run.call_args[0][0]
        assert "-o" in cmd
        metric_idx = cmd.index("-o")
        assert "metric=" in cmd[metric_idx + 1]
        assert "--internal" not in cmd
        assert EGRESS_NETWORK in cmd

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman", stderr="err"),
    )
    def test_create_egress_failure(self, mock_run: MagicMock) -> None:
        """Raises ProxyError on egress network creation failure."""
        pm = _make_pm()
        with pytest.raises(ProxyError, match="Failed to create egress"):
            pm._create_egress_network()

    @patch("lib.container.proxy.subprocess.run")
    def test_remove_network(self, mock_run: MagicMock) -> None:
        """Removes network with force."""
        pm = _make_pm()
        pm._remove_network("test-net")
        cmd = mock_run.call_args[0][0]
        assert cmd == ["podman", "network", "rm", "-f", "test-net"]

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman"),
    )
    def test_remove_ignores_not_found(self, mock_run: MagicMock) -> None:
        """Does not raise if network doesn't exist."""
        pm = _make_pm()
        pm._remove_network("missing")  # Should not raise

    @patch.object(ProxyManager, "_create_egress_network")
    @patch.object(ProxyManager, "_remove_network")
    def test_recreate_egress(
        self,
        mock_rm: MagicMock,
        mock_create: MagicMock,
    ) -> None:
        """Recreate removes then creates egress network."""
        pm = _make_pm()
        pm._recreate_egress_network()
        mock_rm.assert_called_once_with(EGRESS_NETWORK)
        mock_create.assert_called_once()


class TestSubnetAllocation:
    """Tests for ProxyManager._allocate_subnet()."""

    def test_increments(self) -> None:
        """Allocates sequential subnets."""
        pm = _make_pm()
        subnet1, ip1 = pm._allocate_subnet()
        subnet2, ip2 = pm._allocate_subnet()
        assert subnet1 == "10.199.1.0/24"
        assert ip1 == "10.199.1.100"
        assert subnet2 == "10.199.2.0/24"
        assert ip2 == "10.199.2.100"

    def test_wraps_at_254(self) -> None:
        """Wraps around after reaching 254."""
        pm = _make_pm()
        pm._next_subnet_octet = 254
        subnet, ip = pm._allocate_subnet()
        assert subnet == "10.199.254.0/24"
        assert ip == "10.199.254.100"
        # Next allocation wraps to 1
        subnet, ip = pm._allocate_subnet()
        assert subnet == "10.199.1.0/24"
        assert ip == "10.199.1.100"


class TestCleanupOrphans:
    """Tests for ProxyManager._cleanup_orphans()."""

    @patch("lib.container.proxy.subprocess.run")
    def test_cleans_containers_and_networks(self, mock_run: MagicMock) -> None:
        """Removes orphaned containers and networks."""
        # First call: ps for containers
        ps_result = MagicMock()
        ps_result.stdout = "airut-proxy-old1\nairut-proxy-old2\n"
        # Second call: rm container 1
        # Third call: rm container 2
        # Fourth call: network ls
        net_result = MagicMock()
        net_result.stdout = "airut-conv-old1\n"
        # Fifth call: network rm

        mock_run.side_effect = [
            ps_result,
            MagicMock(),  # rm -f old1
            MagicMock(),  # rm -f old2
            net_result,
            MagicMock(),  # network rm -f old1
        ]

        pm = _make_pm()
        pm._cleanup_orphans()
        assert mock_run.call_count == 5

    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman"),
    )
    def test_handles_list_failure(self, mock_run: MagicMock) -> None:
        """Does not raise if listing fails."""
        pm = _make_pm()
        pm._cleanup_orphans()  # Should not raise


class TestWaitForProxyReady:
    """Tests for ProxyManager._wait_for_proxy_ready()."""

    @patch("lib.container.proxy.subprocess.run")
    def test_succeeds_immediately(self, mock_run: MagicMock) -> None:
        """Returns when probe succeeds on first attempt."""
        pm = _make_pm()
        pm._wait_for_proxy_ready("proxy-abc")
        mock_run.assert_called_once()
        cmd = mock_run.call_args[0][0]
        assert cmd[0] == "podman"
        assert cmd[1] == "exec"
        assert cmd[2] == "proxy-abc"
        assert cmd[3] == "python3"
        # Probe should check ports 80 and 443 (not 8080)
        probe_script = cmd[5]
        assert "80" in probe_script
        assert "443" in probe_script

    @patch("lib.container.proxy.time.sleep")
    @patch("lib.container.proxy.subprocess.run")
    def test_retries_then_succeeds(
        self,
        mock_run: MagicMock,
        mock_sleep: MagicMock,
    ) -> None:
        """Retries on failure then succeeds."""
        mock_run.side_effect = [
            subprocess.CalledProcessError(1, "podman"),
            subprocess.CalledProcessError(1, "podman"),
            MagicMock(),  # Success
        ]
        pm = _make_pm()
        pm._wait_for_proxy_ready("proxy-abc")
        assert mock_run.call_count == 3
        assert mock_sleep.call_count == 2

    @patch("lib.container.proxy.time.monotonic")
    @patch("lib.container.proxy.time.sleep")
    @patch(
        "lib.container.proxy.subprocess.run",
        side_effect=subprocess.CalledProcessError(1, "podman"),
    )
    def test_raises_on_timeout(
        self,
        mock_run: MagicMock,
        mock_sleep: MagicMock,
        mock_monotonic: MagicMock,
    ) -> None:
        """Raises ProxyError after timeout expires."""
        # Simulate time passing beyond deadline
        mock_monotonic.side_effect = [0.0, 0.0, 6.0]
        pm = _make_pm()
        with pytest.raises(ProxyError, match="not ready after"):
            pm._wait_for_proxy_ready("proxy-abc", timeout=5.0)

    @patch("lib.container.proxy.time.sleep")
    @patch("lib.container.proxy.subprocess.run")
    def test_handles_timeout_expired(
        self,
        mock_run: MagicMock,
        mock_sleep: MagicMock,
    ) -> None:
        """Handles subprocess.TimeoutExpired as a retry case."""
        mock_run.side_effect = [
            subprocess.TimeoutExpired("podman", 3),
            MagicMock(),  # Success
        ]
        pm = _make_pm()
        pm._wait_for_proxy_ready("proxy-abc")
        assert mock_run.call_count == 2


class TestGetCaCertPath:
    """Tests for get_ca_cert_path() module-level function."""

    def test_returns_path(self, tmp_path: Path) -> None:
        """Returns cert path when it exists."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.touch()
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            assert get_ca_cert_path() == cert

    def test_missing_raises(self, tmp_path: Path) -> None:
        """Raises RuntimeError when cert missing."""
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            with pytest.raises(RuntimeError, match="CA certificate not found"):
                get_ca_cert_path()
