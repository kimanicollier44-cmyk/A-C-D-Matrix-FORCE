"""Monitor engine — Analyzer capture + Purple Hat detection, one pipeline.

Replaces the bot's scapy sniff thread + the dashboard's simulated socket
feed with one feed-agnostic engine: packets come from the simulator, from
caller-supplied lists / JSON, or from the traffic simulator, and every
packet is both dissected (Analyzer) and scored (Purple Hat detector).
"""
from __future__ import annotations

from . import packets as pk
from .config import validate_ip
from .detector import Detector


class Monitor:
    def __init__(self, thresholds: dict | None = None, cooldown: float = 300.0):
        self.monitored_ips: set[str] = set()
        self.detector = Detector(thresholds=thresholds or Detector().thresholds,
                                 cooldown=cooldown)
        self.packets: list[pk.Packet] = []
        self.running = False

    # -- monitored IP management (bot commands: add ip / remove ip / view) --
    def add_ip(self, ip: str) -> bool:
        if not validate_ip(ip):
            return False
        self.monitored_ips.add(ip)
        return True

    def remove_ip(self, ip: str) -> bool:
        if ip in self.monitored_ips:
            self.monitored_ips.remove(ip)
            return True
        return False

    # -- pipeline -----------------------------------------------------------
    def feed(self, packet: pk.Packet) -> list:
        """One packet in: stored for analysis, scored for threats."""
        if self.monitored_ips and packet.src_ip not in self.monitored_ips \
                and packet.dst_ip not in self.monitored_ips:
            return []  # bot semantics: only traffic touching monitored IPs
        self.packets.append(packet)
        return self.detector.process(packet)

    def feed_many(self, packets) -> list:
        out = []
        for p in packets:
            out.extend(self.feed(p))
        return out

    # -- views (Analyzer) ---------------------------------------------------
    def stats(self) -> dict:
        return pk.protocol_stats(self.packets)

    def status(self) -> dict:
        per_ip = {}
        for ip in sorted(self.monitored_ips):
            per_ip[ip] = {
                "status": "Active" if self.running else "Inactive",
                "threats_detected": sum(1 for a in self.detector.alerts if a.ip == ip),
            }
        return {"monitoring": self.running, "monitored": per_ip,
                "packets_captured": len(self.packets),
                "alerts": [a.to_dict() for a in self.detector.alerts],
                "protocol_stats": self.stats()}
