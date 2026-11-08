"""Diagnostics — Purple Hat Bot commands that NetLab does NOT have,
plus the bot's scan profile.

DEDUPE (v1.2.0, docs/DEDUPE_MAP.md): this module used to carry its own
ping / port-scan / traceroute engines. LLM-X-NetLab's live.py carries the
same three features in stronger form (labelled ICMP/TCP ping, concurrent
scan, TTL traceroute feeding the START/MIDDLE/END tracker), so the Purple
Hat copies were REMOVED — one canonical engine per feature, in
llmx_netlab.live. What remains here is genuinely different:
  * interfaces / netstat (the bot's local-machine views; NetLab has none)
  * BOT15_PORTS — the bot's exact 15-port list, kept as DATA (a scan
    profile for the canonical scanner). It differs from NetLab's list:
    it is the only one carrying 465/587 (SMTPS / submission).
"""
from __future__ import annotations

import platform
import subprocess

BOT15_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389]


def _run(cmd: list[str]) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        return (r.stdout or r.stderr).strip()
    except Exception as e:
        return f"unavailable: {e}"


def interfaces() -> str:
    return _run(["ip", "a"] if platform.system().lower() == "linux" else ["ifconfig"])


def netstat() -> str:
    return _run(["netstat", "-ano"] if platform.system().lower() == "windows"
                else ["netstat", "-tulnp"])
