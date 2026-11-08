# Merge map — where every upstream piece went

Org: https://github.com/Accurate-Cyber-Defense (Malawian cybersecurity startup,
56 public repos at audit time 2026-11-08). This merge takes the two repos named
in the order — not the whole org.

## 1. Accurate-Cyber-Defense-Network-Analyzer
Upstream: README + LICENSE (CC0) + one 958-line HTML file. All packet data in
the shipped page was browser-simulated (`generateRandomPacket()`).

| Upstream piece | Merged home |
|---|---|
| HTML dashboard (panels: Network Traffic, Packet Analysis, Traffic Statistics, Terminal, status bar) | `dashboard/network-analyzer.html` (verbatim) + `upstream/network-analyzer-original.html` |
| Packet list / details view | `purple_analyzer/packets.py` `dissect()` + `main.py analyze / packet` |
| Hex viewer | `packets.py` `hex_dump()` |
| Disassembly viewer | `packets.py` `disassemble()` |
| Protocol chart data | `packets.py` `protocol_stats()` |
| Simulated traffic feed | `purple_analyzer/simulator.py` (same idea, seeded/deterministic) |
| Advertised protocols HTTP/HTTPS/FTP/DNS/SMTP/ARP + TCP/UDP/ICMP | `packets.py` `WELL_KNOWN` + `protocol_for()` |
| Advertised export PCAP/JSON/CSV | JSON + CSV implemented in `report.py`; **PCAP not implemented** (stated in README) |
| Terminal commands in page (help/packets/clear…) | Unified `main.py` CLI + bot `shell` |

## 2. Accurate-Cyber-Defense-Purple-Hat-Bot (v19.1, 741 lines, Python)
Upstream deps: scapy, requests, prettytable, colorama. Merged core: stdlib only
(urllib replaces requests; tables are plain output; capture is feed-based —
the original file is preserved for anyone who wants the scapy live sniffer).

| Upstream piece | Merged home |
|---|---|
| Threat thresholds port_scan 10 / dos 100 / http_flood 50, cooldown 300 s | `detector.py` `DEFAULT_THRESHOLDS`, exact values, tested |
| Packet counting / port-scan / HTTP-flood analysis loop | `detector.py` `Detector.process()` (60 s sliding windows) |
| Monitored-IP add/remove/view, start monitoring | `monitor.py` + shell commands |
| Telegram config / test / export | `telegram_alert.py` + `config.py` (same file name + keys; README's `user_id` accepted as alias) |
| ping / scan / tracert / ip a / netstat | `diagnostics.py` (scan = same 15 common ports) |
| `generate traffic` (portscan/dos/httpflood/httpsflood) | `traffic_sim.py` — **in-memory only** (see safety note in that file + README) |
| Config file `accuratecyberbot_config.json` | `config.py`, load/save compatible |
| Original .py + both READMEs + NA LICENSE | `upstream/` verbatim, sha256 in tests |

## Provenance hashes (sha256, verified in tests)
- network-analyzer-original.html: 8f44319395bfbb315cc02e2ca094f681bfd3f4aa69c4e7f3ca1cecf461ccafc9
- purple-hat-bot-original.py: 73a6a5a4b217c970b1db5841ffd87c707ea06f39542193fbf54fd878610d71e8
