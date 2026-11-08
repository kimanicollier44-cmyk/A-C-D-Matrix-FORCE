"""Packet model + dissection — the Network Analyzer half, in Python.

Ports the browser original's three views to real, testable code:
  * details     — protocol-specific header fields
  * hex viewer  — classic offset / hex / ASCII dump of the payload
  * disassembly — a readable pseudo-disassembly of header + payload

Protocols covered (same list the upstream README advertises):
TCP, UDP, ICMP, HTTP, HTTPS (TLS on 443), FTP, DNS, SMTP, ARP, other IP.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field, asdict

WELL_KNOWN = {
    21: ("FTP", "TCP"), 22: ("SSH", "TCP"), 23: ("TELNET", "TCP"),
    25: ("SMTP", "TCP"), 53: ("DNS", "UDP"), 80: ("HTTP", "TCP"),
    110: ("POP3", "TCP"), 143: ("IMAP", "TCP"), 443: ("HTTPS", "TCP"),
    465: ("SMTPS", "TCP"), 587: ("SMTP", "TCP"), 993: ("IMAPS", "TCP"),
    995: ("POP3S", "TCP"), 3306: ("MySQL", "TCP"), 3389: ("RDP", "TCP"),
}


def protocol_for(src_port: int, dst_port: int, transport: str = "TCP") -> str:
    """Name the application protocol from the ports, like the dashboard did."""
    for port in (dst_port, src_port):
        if port in WELL_KNOWN:
            name, _ = WELL_KNOWN[port]
            # DNS rides UDP in the common case; keep the name either way.
            return name
    return transport


@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int = 0
    dst_port: int = 0
    transport: str = "TCP"          # TCP | UDP | ICMP | ARP
    payload: bytes = b""
    ttl: int = 64
    timestamp: float = 0.0
    flags: str = ""                 # TCP flags e.g. "SYN", "SYN,ACK", "PSH,ACK"

    @property
    def protocol(self) -> str:
        if self.transport in ("ICMP", "ARP"):
            return self.transport
        return protocol_for(self.src_port, self.dst_port, self.transport)

    @property
    def size(self) -> int:
        header = 20 + (20 if self.transport == "TCP" else 8 if self.transport == "UDP" else 8)
        return header + len(self.payload)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["payload"] = self.payload.hex()
        d["protocol"] = self.protocol
        d["size"] = self.size
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Packet":
        d = dict(d)
        payload = bytes.fromhex(d.pop("payload", "") or "")
        d.pop("protocol", None); d.pop("size", None)
        return cls(payload=payload, **d)


def hex_dump(data: bytes, width: int = 16) -> str:
    """Offset / hex / ASCII dump — the dashboard's Hex tab, byte-exact."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hex_part:<{width * 3}}  |{ascii_part}|")
    return "\n".join(lines) if lines else "(empty payload)"


def dissect(pkt: Packet) -> dict:
    """Protocol-specific detail view — the dashboard's Details tab."""
    details = {
        "src": f"{pkt.src_ip}:{pkt.src_port}" if pkt.transport in ("TCP", "UDP") else pkt.src_ip,
        "dst": f"{pkt.dst_ip}:{pkt.dst_port}" if pkt.transport in ("TCP", "UDP") else pkt.dst_ip,
        "transport": pkt.transport,
        "protocol": pkt.protocol,
        "size_bytes": pkt.size,
        "payload_bytes": len(pkt.payload),
        "ttl": pkt.ttl,
    }
    if pkt.transport == "TCP":
        details["tcp_flags"] = pkt.flags or "ACK"
        details["window"] = 65535
    if pkt.protocol == "HTTP" and pkt.payload:
        text = pkt.payload.decode("latin-1", "replace")
        first = text.split("\r\n", 1)[0]
        details["http_first_line"] = first
        if " " in first:
            details["http_method"] = first.split(" ", 1)[0]
    if pkt.protocol == "DNS":
        details["dns_note"] = "query/response on port 53 — see disassembly for qname bytes"
    if pkt.protocol in ("HTTPS",) and pkt.payload:
        details["tls_note"] = "payload is TLS records; plaintext is not visible — metadata only"
        if pkt.payload[:1] == b"\x16":
            details["tls_record_type"] = "handshake (0x16)"
    return details


def disassemble(pkt: Packet) -> str:
    """Readable pseudo-disassembly — the dashboard's Disassembly tab."""
    out = [
        f"; packet {pkt.src_ip}:{pkt.src_port} -> {pkt.dst_ip}:{pkt.dst_port}",
        f"; transport={pkt.transport} protocol={pkt.protocol} ttl={pkt.ttl} size={pkt.size}",
        "IP .version  = 4",
        f"IP  .src      = {pkt.src_ip}",
        f"IP  .dst      = {pkt.dst_ip}",
        f"IP  .ttl      = {pkt.ttl}",
    ]
    if pkt.transport == "TCP":
        out += [f"TCP .sport    = {pkt.src_port}", f"TCP .dport    = {pkt.dst_port}",
                f"TCP .flags    = {pkt.flags or 'ACK'}"]
    elif pkt.transport == "UDP":
        out += [f"UDP .sport    = {pkt.src_port}", f"UDP .dport    = {pkt.dst_port}",
                f"UDP .length   = {8 + len(pkt.payload)}"]
    elif pkt.transport == "ICMP":
        out += ["ICMP.type     = 8 (echo request) / 0 (echo reply)"]
    for i in range(0, min(len(pkt.payload), 64), 8):
        chunk = pkt.payload[i:i + 8]
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"DATA+{i:<4} " + " ".join(f"{b:02x}" for b in chunk) + f"  |{ascii_part}|")
    if len(pkt.payload) > 64:
        out.append(f"; ... {len(pkt.payload) - 64} more payload bytes (see hex view)")
    return "\n".join(out)


def protocol_stats(packets) -> dict:
    """Counts per protocol — the data behind the dashboard's protocol chart."""
    stats: dict[str, int] = {}
    for p in packets:
        stats[p.protocol] = stats.get(p.protocol, 0) + 1
    return stats
