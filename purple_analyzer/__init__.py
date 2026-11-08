"""Purple-Hat Network Analyzer — merged Accurate Cyber Defense tools.

Sources merged (preserved verbatim under upstream/):
  1. Accurate-Cyber-Defense-Network-Analyzer (single-file HTML dashboard:
     packet list, details, hex viewer, disassembly, protocol chart, terminal)
  2. Accurate-Cyber-Defense-Purple-Hat-Bot v19.1 (Python CLI: scapy monitor,
     port-scan / DoS / HTTP-flood detection, Telegram alerts, diagnostics)

Merged core is pure Python stdlib. Live capture with scapy is an optional
extra in the upstream original; the merged engine works on simulated and
caller-supplied packets so it runs and tests anywhere.
"""
__version__ = "1.4.0"
__all__ = ["packets", "simulator", "detector", "monitor", "diagnostics",
           "telegram_alert", "traffic_sim", "report", "config", "swarm"]
