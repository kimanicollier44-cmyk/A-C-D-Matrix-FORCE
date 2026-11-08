"""Traffic simulation — the bot's `generate traffic` command, made safe.

UPSTREAM DIFFERENCE, stated plainly: the original simulate_* functions sent
real socket connects / HTTP requests at the target. The merged version
generates the same shapes as in-memory packets and feeds them to the
detector — it proves the detection fires, generates a reportable alert,
and sends zero packets on any wire. Use your own lab tooling if you need
real load; this module will not do it.
"""
from __future__ import annotations

from .packets import Packet

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]


def portscan_packets(src: str, dst: str, start_time: float = 0.0, count: int = 40) -> list[Packet]:
    ports = (COMMON_PORTS * 3)[:count]
    return [Packet(src_ip=src, dst_ip=dst, src_port=40000 + i, dst_port=p,
                   transport="TCP", flags="SYN", timestamp=start_time + i * 0.5)
            for i, p in enumerate(ports)]


def dos_packets(src: str, dst: str, start_time: float = 0.0, count: int = 130) -> list[Packet]:
    return [Packet(src_ip=src, dst_ip=dst, src_port=30000, dst_port=80,
                   transport="TCP", flags="SYN", timestamp=start_time + i * 0.2)
            for i in range(count)]


def http_flood_packets(src: str, dst: str, start_time: float = 0.0,
                       count: int = 70, https: bool = False) -> list[Packet]:
    port = 443 if https else 80
    payload = b"GET / HTTP/1.1\r\nHost: target.local\r\n\r\n" if not https else b"\x16\x03\x01\x00\x2e"
    return [Packet(src_ip=src, dst_ip=dst, src_port=31000 + i, dst_port=port,
                   transport="TCP", flags="PSH,ACK", payload=payload,
                   timestamp=start_time + i * 0.3)
            for i in range(count)]


def generate(kind: str, src: str, dst: str, start_time: float = 0.0) -> list[Packet]:
    kind = kind.lower()
    if kind == "portscan":
        return portscan_packets(src, dst, start_time)
    if kind == "dos":
        return dos_packets(src, dst, start_time)
    if kind == "httpflood":
        return http_flood_packets(src, dst, start_time, https=False)
    if kind == "httpsflood":
        return http_flood_packets(src, dst, start_time, https=True)
    raise ValueError(f"unknown traffic type: {kind} (portscan|dos|httpflood|httpsflood)")
