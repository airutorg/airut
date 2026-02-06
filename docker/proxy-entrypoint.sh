#!/bin/sh
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

# Proxy entrypoint: starts DNS responder + mitmproxy in regular mode.
#
# No iptables, no ip_forward, no CAP_NET_ADMIN needed. All client traffic
# arrives at the proxy IP because:
#   1. DNS returns the proxy IP for all allowed domains
#   2. The client's default route points to the proxy IP (via --route)
#
# mitmproxy in regular mode uses SNI (HTTPS) and Host header (HTTP)
# to determine the real upstream destination.
#
# Environment:
#   PROXY_IP       - this container's IP on the internal network
#   UPSTREAM_DNS   - upstream DNS server for proxy's own resolution (default: 1.1.1.1)

set -eu

PROXY_IP="${PROXY_IP:-}"
UPSTREAM_DNS="${UPSTREAM_DNS:-1.1.1.1}"

# -- Fix DNS for upstream resolution -----------------------------------------
#
# The proxy container may inherit aardvark-dns from the egress network.
# Replace resolv.conf with the configured upstream resolver so mitmproxy
# can resolve real hostnames when connecting upstream.
echo "nameserver $UPSTREAM_DNS" > /etc/resolv.conf

# -- Start DNS responder ------------------------------------------------------

python3 /dns_responder.py "$PROXY_IP" &
DNS_PID=$!

sleep 1
if ! kill -0 "$DNS_PID" 2>/dev/null; then
    echo "ERROR: DNS responder failed to start" >&2
    wait "$DNS_PID" 2>/dev/null || true
    exit 1
fi

# -- Start mitmproxy ----------------------------------------------------------
#
# Regular mode on ports 80 and 443. Since mitmproxy 7, regular mode
# uses Host header (HTTP) and SNI (HTTPS) to determine upstream when
# the client connects directly (DNS spoofing pattern).
#
# connection_strategy=lazy: don't connect upstream until the request
# is fully received. This lets proxy-filter.py check the allowlist
# before any upstream connection is made.

exec mitmdump \
    --mode regular@80 \
    --mode regular@443 \
    --set connection_strategy=lazy \
    --set confdir=/mitmproxy-confdir \
    --set flow_detail=0 \
    --showhost \
    -s /proxy-filter.py
