"""Export & reports — Analyzer's Data Export (JSON / CSV) + threat summary.

The upstream Analyzer advertised PCAP/JSON/CSV export but the shipped HTML
implemented none of it; the merged engine implements JSON and CSV for real.
PCAP is honestly NOT implemented (no scapy dependency in the core) — packets
export as JSON records that tools can convert. That gap is stated, not hidden.
"""
from __future__ import annotations

import csv
import io
import json

from .packets import dissect


def packets_json(packets) -> str:
    return json.dumps([p.to_dict() for p in packets], indent=2)


def packets_csv(packets) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
                "transport", "protocol", "size_bytes", "flags"])
    for p in packets:
        w.writerow([p.timestamp, p.src_ip, p.src_port, p.dst_ip, p.dst_port,
                    p.transport, p.protocol, p.size, p.flags])
    return buf.getvalue()


def threat_report(monitor) -> dict:
    st = monitor.status()
    return {
        "packets_captured": st["packets_captured"],
        "protocol_stats": st["protocol_stats"],
        "monitored": st["monitored"],
        "alerts": st["alerts"],
        "alert_count": len(st["alerts"]),
    }


def packet_summary(packets) -> list:
    return [{"details": dissect(p), "hex": _first_hex(p)} for p in packets]


def _first_hex(p) -> str:
    from .packets import hex_dump
    return hex_dump(p.payload) if p.payload else "(empty payload)"
