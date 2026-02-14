# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Tests for lib/sandbox/_network.py -- network sandbox configuration."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from lib.sandbox._network import (
    CA_CONTAINER_PATH,
    get_ca_cert_path,
    get_network_args,
)
from lib.sandbox._proxy import CA_CERT_FILENAME


class TestGetCaCertPath:
    """Tests for get_ca_cert_path function."""

    def test_returns_path_when_cert_exists(self, tmp_path: Path) -> None:
        """Returns CA cert path when file exists."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.write_text("fake-cert")

        with patch("lib.sandbox._network.MITMPROXY_CONFDIR", tmp_path):
            result = get_ca_cert_path()

        assert result == cert

    def test_raises_when_cert_missing(self, tmp_path: Path) -> None:
        """Raises RuntimeError when CA cert does not exist."""
        with patch("lib.sandbox._network.MITMPROXY_CONFDIR", tmp_path):
            with pytest.raises(RuntimeError, match="CA certificate not found"):
                get_ca_cert_path()


class TestGetNetworkArgs:
    """Tests for get_network_args function."""

    def test_returns_correct_args(self, tmp_path: Path) -> None:
        """Returns correct podman args for network sandbox."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.write_text("fake-cert")

        with patch("lib.sandbox._network.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args("task-net-123", "10.199.1.100")

        # --network
        assert "--network" in args
        idx = args.index("--network")
        assert args[idx + 1] == "task-net-123"

        # --dns
        assert "--dns" in args
        dns_idx = args.index("--dns")
        assert args[dns_idx + 1] == "10.199.1.100"

        # Volume mount for CA cert
        assert "-v" in args
        v_idx = args.index("-v")
        expected_mount = f"{cert}:{CA_CONTAINER_PATH}:ro"
        assert args[v_idx + 1] == expected_mount

        # CA env vars for all common TLS stacks
        assert "-e" in args
        env_args = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
        assert f"NODE_EXTRA_CA_CERTS={CA_CONTAINER_PATH}" in env_args
        assert f"REQUESTS_CA_BUNDLE={CA_CONTAINER_PATH}" in env_args
        assert f"SSL_CERT_FILE={CA_CONTAINER_PATH}" in env_args
        assert f"CURL_CA_BUNDLE={CA_CONTAINER_PATH}" in env_args

    def test_no_http_proxy_env_vars(self, tmp_path: Path) -> None:
        """Transparent proxy: no HTTP_PROXY or HTTPS_PROXY env vars."""
        cert = tmp_path / CA_CERT_FILENAME
        cert.write_text("fake-cert")

        with patch("lib.sandbox._network.MITMPROXY_CONFDIR", tmp_path):
            args = get_network_args("task-net-123", "10.199.1.100")

        # Collect all env vars set via -e
        env_args = [args[i + 1] for i, a in enumerate(args) if a == "-e"]
        for env_arg in env_args:
            key = env_arg.split("=")[0]
            assert key not in (
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "http_proxy",
                "https_proxy",
            )

    def test_raises_when_ca_cert_missing(self, tmp_path: Path) -> None:
        """Raises RuntimeError when CA cert is missing."""
        with patch("lib.sandbox._network.MITMPROXY_CONFDIR", tmp_path):
            with pytest.raises(RuntimeError, match="CA certificate not found"):
                get_network_args("task-net-123", "10.199.1.100")
