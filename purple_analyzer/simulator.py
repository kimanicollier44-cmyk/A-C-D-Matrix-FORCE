"""Deterministic simulated packet feed.

The HTML original generated random packets in the browser with Math.random()
(simulateNetworkTraffic / generateRandomPacket). This is the same idea,
seeded — so tests, demos and the dashboard export are reproducible.
"""
from __future__ import annotations

import random
from .packets import Packet

_PROFILES = [
    # (dst_port, transport, flags, payload template)
    (80, "TCP", "PSH,ACK", b"GET /index.html HTTP/1.1\r\nHost: example.local\r\n\r\n"),
    (443, "TCP", "PSH,ACK", b"\x16\x03\x01\x00\x2e\x01\x00\x00\x2a\x03\x03"),
    (53, "UDP", "", b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00"),
    (22, "TCP", "SYN", b""),
    (25, "TCP", "PSH,ACK", b"EHLO mail.local\r\n"),
    (0, "ICMP", "", b"\x08\x00\xf7\xff\x00\x00\x00\x00"),
    (21, "TCP", "SYN", b""),
    (3306, "TCP", "PSH,ACK", b"\x4a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x00"),
]


def simulated_packets(count: int = 20, seed: int = 42, host: str = "192.168.1.50") -> list[Packet]:
    rng = random.Random(seed)
    out: list[Packet] = []
    peers = ["192.168.1.1", "192.168.1.61", "192.168.1.156", "203.0.113.10", "198.51.100.7"]
    for i in range(count):
        port, transport, flags, payload = rng.choice(_PROFILES)
        src = rng.choice(peers)
        out.append(Packet(
            src_ip=src, dst_ip=host,
            src_port=rng.randint(1024, 65535) if transport in ("TCP", "UDP") else 0,
            dst_port=port, transport=transport, payload=payload,
            ttl=rng.choice([64, 128, 255]), timestamp=float(i), flags=flags,
        ))
    return out
