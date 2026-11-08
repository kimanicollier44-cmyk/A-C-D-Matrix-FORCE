"""Purple Hat threat detector — the Purple Hat Bot half.

Threshold logic preserved from Accurate-Cyber-Defense-Purple-Hat-Bot.py v19.1:
  port_scan : >10 distinct/probed ports per minute per source
  dos       : >100 packets per minute to a monitored IP
  http_flood: >50 HTTP/HTTPS requests per minute per source
  cooldown  : 300 s between repeat alerts for the same (ip, type)
Windows are 60 s sliding, keyed on packet timestamps so simulated and
caller-supplied streams test deterministically.
"""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field

from .packets import Packet

DEFAULT_THRESHOLDS = {"port_scan": 10, "dos_attack": 100, "http_flood": 50}


@dataclass
class Alert:
    timestamp: float
    ip: str
    type: str            # "Port Scan" | "DoS Attack" | "HTTP Flood"
    description: str

    def to_dict(self) -> dict:
        return {"timestamp": self.timestamp, "ip": self.ip,
                "type": self.type, "description": self.description}


@dataclass
class Detector:
    thresholds: dict = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    cooldown: float = 300.0
    window: float = 60.0
    alerts: list = field(default_factory=list)
    _packets: dict = field(default_factory=lambda: defaultdict(deque))        # dst_ip -> times
    _ports: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(deque)))  # src -> minute-ish
    _port_sets: dict = field(default_factory=lambda: defaultdict(deque))      # src -> (time, dport)
    _http: dict = field(default_factory=lambda: defaultdict(deque))           # src -> times
    _last_alert: dict = field(default_factory=dict)

    def _fire(self, now: float, ip: str, kind: str, desc: str):
        key = f"{kind}_{ip}"
        if now - self._last_alert.get(key, -1e18) < self.cooldown:
            return None
        self._last_alert[key] = now
        alert = Alert(timestamp=now, ip=ip, type=kind, description=desc)
        self.alerts.append(alert)
        return alert

    def process(self, pkt: Packet) -> list:
        """Feed one packet; returns any alerts it triggered."""
        now = pkt.timestamp
        fired = []
        # DoS: packet rate toward the destination
        dq = self._packets[pkt.dst_ip]; dq.append(now)
        while dq and now - dq[0] > self.window:
            dq.popleft()
        if len(dq) > self.thresholds["dos_attack"]:
            a = self._fire(now, pkt.dst_ip, "DoS Attack",
                           f"High incoming packet rate: {len(dq)} packets/minute")
            if a: fired.append(a)
        # Port scan: distinct destination ports probed by one source in window
        pq = self._port_sets[pkt.src_ip]; pq.append((now, pkt.dst_port))
        while pq and now - pq[0][0] > self.window:
            pq.popleft()
        distinct = {p for _, p in pq}
        if pkt.transport == "TCP" and len(distinct) > self.thresholds["port_scan"]:
            a = self._fire(now, pkt.src_ip, "Port Scan",
                           f"High port scan activity: {len(distinct)} ports scanned/minute")
            if a: fired.append(a)
        # HTTP flood: requests to 80/443 per source in window
        if pkt.transport == "TCP" and pkt.dst_port in (80, 443):
            hq = self._http[pkt.src_ip]; hq.append(now)
            while hq and now - hq[0] > self.window:
                hq.popleft()
            if len(hq) > self.thresholds["http_flood"]:
                a = self._fire(now, pkt.src_ip, "HTTP Flood",
                               f"High HTTP request rate: {len(hq)} requests/minute")
                if a: fired.append(a)
        return fired

    def process_many(self, packets) -> list:
        out = []
        for p in packets:
            out.extend(self.process(p))
        return out
