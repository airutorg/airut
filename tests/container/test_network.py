# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for network sandbox module."""

from pathlib import Path
from unittest.mock import patch

import pytest

from lib.container.network import (
    CA_CONTAINER_PATH,
    get_network_args,
)
from lib.container.proxy import TaskProxy


class TestGetNetworkArgs:
    """Tests for get_network_args."""

    def test_disabled_returns_empty(self) -> None:
        """Returns empty list when sandbox is disabled (None proxy)."""
        assert get_network_args(None) == []

    def test_enabled_returns_args(self, tmp_path: Path) -> None:
        """Returns correct Podman args when sandbox is enabled."""
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.touch()
        tp = TaskProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.1.100",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args(tp)

        assert "--network" in args
        assert "test-net" in args

        # DNS pointing to proxy IP
        dns_idx = args.index("--dns")
        assert args[dns_idx + 1] == "10.199.1.100"

        # CA cert mount
        mount_args = [
            a for i, a in enumerate(args) if i > 0 and args[i - 1] == "-v"
        ]
        assert len(mount_args) == 1
        assert str(cert) in mount_args[0]
        assert CA_CONTAINER_PATH in mount_args[0]

        # CA trust env vars
        env_args = [
            a for i, a in enumerate(args) if i > 0 and args[i - 1] == "-e"
        ]
        ca_env_vars = [
            a
            for a in env_args
            if any(
                k in a
                for k in [
                    "NODE_EXTRA_CA_CERTS",
                    "REQUESTS_CA_BUNDLE",
                    "SSL_CERT_FILE",
                    "CURL_CA_BUNDLE",
                ]
            )
        ]
        assert len(ca_env_vars) == 4

        # No cooperative proxy env vars (transparent proxy architecture)
        assert not any("HTTP_PROXY=" in a for a in env_args)
        assert not any("HTTPS_PROXY=" in a for a in env_args)
        assert not any("GLOBAL_AGENT" in a for a in env_args)
        assert not any("NODE_OPTIONS" in a for a in env_args)
        assert not any("ELECTRON_GET_USE_PROXY" in a for a in env_args)

    def test_custom_proxy_ip(self, tmp_path: Path) -> None:
        """Respects custom proxy IP address."""
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.touch()
        tp = TaskProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.42.100",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args(tp)

        dns_idx = args.index("--dns")
        assert args[dns_idx + 1] == "10.199.42.100"

    def test_infra_not_ready_raises(self, tmp_path: Path) -> None:
        """Raises RuntimeError when CA cert is missing (fail-secure)."""
        tp = TaskProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_ip="10.199.1.100",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            with pytest.raises(RuntimeError, match="CA certificate not found"):
                get_network_args(tp)
