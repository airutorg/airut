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
            proxy_host="test-proxy",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args(tp)

        assert "--network" in args
        assert "test-net" in args

        # Proxy env vars
        env_args = [
            a for i, a in enumerate(args) if i > 0 and args[i - 1] == "-e"
        ]
        proxy_urls = [a for a in env_args if "PROXY=" in a]
        assert len(proxy_urls) == 2
        assert any("HTTP_PROXY=http://test-proxy:8080" in a for a in proxy_urls)
        assert any(
            "HTTPS_PROXY=http://test-proxy:8080" in a for a in proxy_urls
        )

        # CA cert mount
        mount_args = [
            a for i, a in enumerate(args) if i > 0 and args[i - 1] == "-v"
        ]
        assert len(mount_args) == 1
        assert str(cert) in mount_args[0]
        assert CA_CONTAINER_PATH in mount_args[0]

        # CA trust env vars
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

    def test_custom_host_and_port(self, tmp_path: Path) -> None:
        """Respects custom proxy host and port."""
        cert = tmp_path / "mitmproxy-ca-cert.pem"
        cert.touch()
        tp = TaskProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_host="10.89.0.1",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args(tp)

        env_args = [
            a for i, a in enumerate(args) if i > 0 and args[i - 1] == "-e"
        ]
        assert any("HTTP_PROXY=http://10.89.0.1:8080" in a for a in env_args)

    def test_infra_not_ready_raises(self, tmp_path: Path) -> None:
        """Raises RuntimeError when CA cert is missing (fail-secure)."""
        tp = TaskProxy(
            network_name="test-net",
            proxy_container_name="test-proxy",
            proxy_host="test-proxy",
        )
        with patch("lib.container.proxy.MITMPROXY_CONFDIR", tmp_path):
            with pytest.raises(RuntimeError, match="CA certificate not found"):
                get_network_args(tp)
