# Decompress + dedupe map

Darion's order (2026-11-08): decompress each named repo into this project,
**remove duplicate features, keep everything that is different**.

"Decompress" = expand each project from its repo form into its full package
tree inside this project, verbatim (sha256-checked against the source repos),
wired into the ONE unified `main.py`. Each source project's own `main.py`
CLI is NOT copied — one interface only; each lab's report/checks are
replicated from its package APIs in `purple_analyzer/labs.py` (NetLab's in
`main.py: netlab_dispatch / netlab_checks`).

Sources, in order received:
1. credkellar/LLM-X-NetLab → v1.2.0
2. credkellar/MATH-THE-MATRIX, credkellar/CVE-RE, credkellar/sysadmin-footprint-mask → v1.3.0

## Duplicates REMOVED (same feature, same job — one canonical kept)

| Duplicate feature | Copies that existed | Canonical kept | What was removed |
|---|---|---|---|
| Live ping | Purple Hat `diagnostics.ping_host` (subprocess ping, no fallback/label) vs NetLab `live.ping_host` (ICMP where permitted + labelled TCP-timing fallback) | NetLab `live.ping_host` — `main.py ping`, bot shell `ping` | Purple Hat `ping_host` deleted from `diagnostics.py`; absence asserted in checks + tests |
| Live port scan | Purple Hat `diagnostics.scan_host` (sequential, 15 ports) vs NetLab `live.port_scan` (concurrent, configurable) | NetLab `live.port_scan` — `main.py scan`, shell `scan` | Purple Hat `scan_host` engine deleted. Its 15-port LIST was different data (only list with 465/587) → kept as the `bot15` profile: `scan <host> --profile bot15` |
| Traceroute | Purple Hat `diagnostics.trace_host` (subprocess) vs NetLab `live.traceroute` / `trace_and_track` (TTL probes feeding START/MIDDLE/END tracker) | NetLab live trace — `main.py trace`, shell `tracert` | Purple Hat `trace_host` deleted |
| Per-lab CLI surfaces | Every source shipped its own main.py (demo/checks/hold-demo with different flags) | The one unified `main.py`; bare run = demo + unified checks (the labs' own convention) | Source CLIs not copied; their checks are replicated once each (`netlab checks`, `matrix report`, `cve report`, `mask checks`) |
| Council commands at top level | Carbon 4 / Muse seat surface in NetLab + MATH + CVE + sysadmin | ONE top-level surface: `main.py council` (status of all 4 seats) | No per-lab council commands at top level. The ENGINES stay inside their labs — see "kept" below |

## Kept because DIFFERENT (everything else)

| Feature | Why it is not a duplicate |
|---|---|
| NetLab RAG/KB (21 entries), orchestrator, gateway/tokenizer, TF-IDF embeddings, backbone + bigram SLM, session/episodic memory, domain X modules, guardrails, MLOps benchmark | No counterpart anywhere else in the project |
| NetLab subnet / topology-SPOF / layer / device engines, simulated topology ping | Different from Purple Hat's packet simulator (topology graphs vs packet streams) — both kept, names disambiguated |
| NetLab IP tracker (START/MIDDLE/END), Earth KML, Flow video plans, DNS/connect/HTTP/geo, endpoint walker (`beyond_end.py`) | Unique to NetLab |
| NetLab council ENGINE (`llmx_netlab/brains/`) | Decides NetLab ask() requests; tier map differs (extended=8192) from sysadmin's (deep=8192); its v1.1.0 removed HOLD gates — behaviour no other lab shares |
| MATH catalog (56 formulas / 24 domains), candidate labs (46 candidates / 22 kinds), 2048+ test battery, sandbox deploy registry | Unique domain: formula/candidate testing lab |
| MATH brains (council over candidate scores, default tier 32768) + its 12 HOLD gates | Different code, different subjects (candidates), different gate list (clinical use, patent filing…) |
| MATH flows (merged plan per candidate) | Different code + subject |
| CVE catalog (44 unauthenticated RCE / memory-disclosure records), analyzer (filter/group/priority), pipeline | Unique domain: records inventory — data + triage, not packets, not formulas |
| CVE carbon4 (verdicts on CVE records) + its 12 HOLD gates (live_exploitation…) | Different code, different subjects, different gate list |
| CVE flows (plans per CVE record) | Different code + subject |
| sysadmin sanitizer / isolation / profile / sandbox / blackbox / freeai registry | Unique domain: own-machine footprint masking; nothing else touches env/history |
| sysadmin brains Gate engine + carbon4 (verdicts on session reports) | Different code, different subjects (session reports), different HOLD triggers (wipe_system_logs…) |
| sysadmin bin/ scripts, configs/, examples/, Dockerfile.sandbox | Shell artifacts at project root, exactly where its checks and tooling expect them |
| sysadmin flows (runbook storyboards, workspace triggers) | Different code + subject |
| Purple Hat packet dissection / detector / Telegram / swarm, NetLab-vs-Purple-Hat everything in docs/MERGE_MAP.md | Original merge, unchanged |

Rule applied throughout: same *concept* (Carbon 4 seat, Google Flows, HOLD
gates) with different code, different data, and different subjects is
**different** and kept; the same *feature doing the same job on the same
inputs* (ping/scan/trace a host, a top-level CLI, a top-level council
command) is a **duplicate** and exists exactly once.
