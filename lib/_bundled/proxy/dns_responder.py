#!/usr/bin/env python3
# Copyright (c) 2026 Pyry Haulos
#
# This software is released under the MIT License.
# https://opensource.org/licenses/MIT

"""DNS responder for the network sandbox.

Listens on UDP port 53. For every A query, responds with PROXY_IP
unconditionally. The proxy (mitmproxy) is responsible for allowlist
enforcement — blocked requests receive an HTTP 403 with an actionable
error message.

This design avoids leaking domain existence information: no upstream DNS
resolution is ever performed. All domains appear to resolve from within
the container.

Only A queries are supported (returns NOTIMP for AAAA, MX, etc.).
This is intentional: the client only needs to reach the proxy IP.

All DNS decisions are logged to the network sandbox log file
(``/network-sandbox.log``) when it exists, using the same file as
the mitmproxy addon. Log format::

    DNS AAAA example.com -> NOTIMP
    DNS A api.github.com -> 10.199.1.100
    DNS A evil.com -> 10.199.1.100
"""

from __future__ import annotations

import socket
import struct
import sys
from pathlib import Path
from typing import TextIO


LISTEN_ADDR = "0.0.0.0"
LISTEN_PORT = 53
NETWORK_LOG_PATH = Path("/network-sandbox.log")

# DNS constants
QTYPE_A = 1
QCLASS_IN = 1
TTL = 60

# Common DNS query type names (for logging).
_QTYPE_NAMES: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


def qtype_name(qtype: int) -> str:
    """Return a human-readable name for a DNS query type."""
    return _QTYPE_NAMES.get(qtype, f"TYPE{qtype}")


def _open_network_log(path: Path) -> TextIO | None:
    """Open the network log file for appending, if it exists.

    Returns None if the file doesn't exist or can't be opened.
    """
    if not path.exists():
        return None
    try:
        return open(path, "a")
    except OSError as e:
        print(f"[dns] WARNING: could not open log file {path}: {e}", flush=True)
        return None


def _log_to_file(log_file: TextIO | None, message: str) -> None:
    """Append a line to the network log file (best-effort)."""
    if log_file is None:
        return
    try:
        log_file.write(message + "\n")
        log_file.flush()
    except OSError:
        pass


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


def build_not_implemented(query: bytes, qname_end: int) -> bytes:
    """Build a NOTIMP response for unsupported query types."""
    txn_id = query[:2]
    # QR=1, RD=1, RA=1, RCODE=4 (NOTIMP)
    flags = struct.pack("!H", 0x8184)
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question = query[12:qname_end]
    return txn_id + flags + counts + question


# -- Main --------------------------------------------------------------------


def run_dns_server(
    proxy_ip: str,
    log_file: TextIO | None = None,
) -> None:
    """Run the DNS responder loop (blocks forever).

    All A queries resolve to proxy_ip. No allowlist checking is
    performed — the proxy handles allowlist enforcement.

    Args:
        proxy_ip: IP address to return for all A queries.
        log_file: Optional file handle for the shared network log.
    """
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
                type_label = qtype_name(qtype)
                print(
                    f"[dns] NOTIMP  {qname} type={qtype} from {addr[0]}",
                    flush=True,
                )
                _log_to_file(
                    log_file,
                    f"DNS {type_label} {name} -> NOTIMP",
                )
                sock.sendto(build_not_implemented(data, qend), addr)
                continue

            # All A queries resolve to proxy IP — proxy enforces allowlist
            print(
                f"[dns] RESOLVE {name} -> {proxy_ip} (from {addr[0]})",
                flush=True,
            )
            _log_to_file(
                log_file,
                f"DNS A {name} -> {proxy_ip}",
            )
            sock.sendto(build_a_response(data, proxy_ip, qend), addr)

        except Exception as e:
            print(f"[dns] error: {e}", flush=True)


def main() -> None:
    proxy_ip = sys.argv[1] if len(sys.argv) > 1 else ""
    if not proxy_ip:
        proxy_ip = socket.gethostbyname(socket.gethostname())
        print(f"[dns] auto-detected proxy IP: {proxy_ip}", flush=True)

    print(
        f"[dns] responding with {proxy_ip} for all A queries "
        f"(proxy enforces allowlist)",
        flush=True,
    )

    log_file = _open_network_log(NETWORK_LOG_PATH)
    if log_file is not None:
        print(f"[dns] logging to {NETWORK_LOG_PATH}", flush=True)

    run_dns_server(proxy_ip, log_file=log_file)


if __name__ == "__main__":  # pragma: no cover
    main()
