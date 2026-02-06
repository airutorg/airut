#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""Allowlist-enforcing DNS responder for the network sandbox.

Listens on UDP port 53. For every A query:
  - If the domain matches the allowlist -> respond with PROXY_IP
  - Otherwise -> respond with NXDOMAIN

No upstream DNS forwarding ever occurs. The proxy container resolves
real IPs itself when mitmproxy connects upstream.

Only A queries are supported (returns NOTIMP for AAAA, MX, etc.).
This is intentional: the client only needs to reach the proxy IP.
"""

from __future__ import annotations

import fnmatch
import socket
import struct
import sys
from pathlib import Path

import yaml


LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53
ALLOWLIST_PATH = Path("/network-allowlist.yaml")

# DNS constants
QTYPE_A = 1
QCLASS_IN = 1
TTL = 60


def _match_pattern(pattern: str, value: str) -> bool:
    """Match a domain against a pattern (exact or fnmatch wildcard)."""
    if "*" in pattern or "?" in pattern:
        return fnmatch.fnmatch(value, pattern)
    return pattern == value


def load_allowed_domains(path: Path) -> list[str]:
    """Load all domain patterns from allowlist YAML.

    Extracts domains from both the ``domains`` list and ``url_prefixes``
    host fields, deduplicating across both sources.
    """
    if not path.exists():
        print(
            f"[dns] WARNING: {path} not found, blocking all queries", flush=True
        )
        return []
    with open(path) as f:
        config = yaml.safe_load(f) or {}

    patterns: list[str] = list(config.get("domains", []))
    for entry in config.get("url_prefixes", []):
        host = entry.get("host", "")
        if host and host not in patterns:
            patterns.append(host)
    return patterns


def is_allowed(name: str, patterns: list[str]) -> bool:
    """Check if a domain name matches any allowlist pattern."""
    for pattern in patterns:
        if _match_pattern(pattern, name):
            return True
    return False


# -- Minimal DNS packet parsing/construction ---------------------------------


def parse_query(data: bytes) -> tuple[str, int, int, int]:
    """Parse a DNS query packet.

    Returns (qname, qtype, qclass, question_end_offset).

    Raises:
        ValueError: If the packet is malformed or truncated.
    """
    if len(data) < 12:
        raise ValueError("packet too short")

    pos = 12  # skip header
    labels: list[str] = []
    while pos < len(data):
        length = data[pos]
        if length == 0:
            pos += 1
            break
        pos += 1
        labels.append(
            data[pos : pos + length].decode("ascii", errors="replace")
        )
        pos += length

    qname = ".".join(labels)
    if pos + 4 > len(data):
        raise ValueError("truncated question")
    qtype, qclass = struct.unpack("!HH", data[pos : pos + 4])
    return qname, qtype, qclass, pos + 4


def build_a_response(query: bytes, ip: str, qname_end: int) -> bytes:
    """Build a DNS response with a single A record."""
    txn_id = query[:2]
    # QR=1, RD=1, RA=1, RCODE=0
    flags = struct.pack("!H", 0x8180)
    counts = struct.pack("!HHHH", 1, 1, 0, 0)  # QD=1, AN=1
    question = query[12:qname_end]

    # Answer: pointer to qname in question (offset 12), type A, class IN
    answer = struct.pack("!H", 0xC00C)  # name pointer to offset 12
    answer += struct.pack("!HH", QTYPE_A, QCLASS_IN)
    answer += struct.pack("!I", TTL)
    ip_bytes = socket.inet_aton(ip)
    answer += struct.pack("!H", len(ip_bytes))
    answer += ip_bytes

    return txn_id + flags + counts + question + answer


def build_nxdomain(query: bytes, qname_end: int) -> bytes:
    """Build an NXDOMAIN response."""
    txn_id = query[:2]
    # QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
    flags = struct.pack("!H", 0x8183)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question = query[12:qname_end]
    return txn_id + flags + counts + question


def build_not_implemented(query: bytes, qname_end: int) -> bytes:
    """Build a NOTIMP response for unsupported query types."""
    txn_id = query[:2]
    # QR=1, RD=1, RA=1, RCODE=4 (NOTIMP)
    flags = struct.pack("!H", 0x8184)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question = query[12:qname_end]
    return txn_id + flags + counts + question


# -- Main --------------------------------------------------------------------


def run_dns_server(proxy_ip: str, patterns: list[str]) -> None:
    """Run the DNS responder loop (blocks forever)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((LISTEN_ADDR, LISTEN_PORT))
    print(f"[dns] listening on {LISTEN_ADDR}:{LISTEN_PORT}", flush=True)

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            qname, qtype, _qclass, qend = parse_query(data)
            name = qname.rstrip(".")

            if qtype != QTYPE_A:
                # Only A queries supported; AAAA, MX, etc. get NOTIMP
                print(
                    f"[dns] NOTIMP  {qname} type={qtype} from {addr[0]}",
                    flush=True,
                )
                sock.sendto(build_not_implemented(data, qend), addr)
                continue

            if is_allowed(name, patterns):
                print(
                    f"[dns] ALLOW   {name} -> {proxy_ip} (from {addr[0]})",
                    flush=True,
                )
                sock.sendto(build_a_response(data, proxy_ip, qend), addr)
            else:
                print(f"[dns] BLOCKED {name} (from {addr[0]})", flush=True)
                sock.sendto(build_nxdomain(data, qend), addr)

        except Exception as e:
            print(f"[dns] error: {e}", flush=True)


def main() -> None:
    proxy_ip = sys.argv[1] if len(sys.argv) > 1 else ""
    if not proxy_ip:
        proxy_ip = socket.gethostbyname(socket.gethostname())
        print(f"[dns] auto-detected proxy IP: {proxy_ip}", flush=True)

    patterns = load_allowed_domains(ALLOWLIST_PATH)
    print(
        f"[dns] loaded {len(patterns)} domain patterns, "
        f"responding with {proxy_ip} for allowed queries",
        flush=True,
    )
    for p in patterns:
        print(f"[dns]   {p}", flush=True)

    run_dns_server(proxy_ip, patterns)


if __name__ == "__main__":
    main()
