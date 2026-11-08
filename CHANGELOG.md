# Changelog

## 1.4.0 — 2026-11-08
- RENAMED: Purple-Hat Network Analyzer -> **A-C-D-Matrix-FORCE** (Darion's name).
- Merged from Docker Hub images (verified live under credkellar/):
  sandbox-api (8,467 pulls; :main 2026-09-30 newer than :latest 2026-08-25)
  -> Sandbox-API chamber, and honeyroot-x (325 pulls) -> honeypot log
  analysis. The ~487 MB image blobs could not be pulled through this
  machine's proxy, so both features were merged from Darion's own in-repo
  implementations of them in PHP-Vuln-RE (php_re/ subset: analyzer, samples,
  sandbox, honeypot — verbatim, sha256-verified; the rest of that lab stays
  in its own repo). Chamber: 15 triaged / 11 allowed / 4 held, never
  executes. Honeypot: 12 attempts, top threat 100, no listener exists.
- README rewritten to Darion's full template: updated workflow + tech-stack
  badges (all 12 URLs verified HTTP 200; workflow badges are static shields
  linked to Actions until the workflow paste + first run), all template
  sections in order, mermaid flowchart per script (78 blocks), emojis
  throughout. Verified at this version: pytest 111 passed, unified CHECKS
  44/44, netlab 23/23, matrix 12/12, cve 14/14, mask 36/36, hold-demo exit 2.


## 1.3.0 — 2026-11-08
- Decompressed 3 more of Darion's repos (verbatim packages, sha256-verified):
  MATH-THE-MATRIX (math_matrix/), CVE-RE (cve_re/), sysadmin-footprint-mask
  (footprintmask/ + bin/, configs/, examples/, Dockerfile.sandbox at root).
- All different features kept and wired: `matrix`, `cve`, `mask` namespaces
  replicate each lab's own report/checks; their test suites vendored flat in
  tests/ (original depth, so their ROOT math works unchanged).
- Dedupe (docs/DEDUPE_MAP.md): ONE top-level council surface (`council`)
  reporting all 4 labs' Carbon 4 / Muse seats; engines stay per-lab
  (different code/data/subjects). ONE bare-run convention (demo + checks)
  and ONE `--hold-demo` for all labs' gates.
- Unified CHECKS grow with matrix formulas / CVE catalog / mask sanitizer /
  council-surface checks.

## 1.2.0 — 2026-11-08
- Decompressed LLM-X-NetLab (llmx_netlab/ + beyond_end.py, verbatim,
  sha256-verified; its 36 tests vendored in tests/netlab/).
- Kept everything different: RAG/orchestrator/SLM/council, subnet/topology/
  layer/device engines, IP tracker, Earth KML, Flow plans, live DNS/connect/
  HTTP/geo, endpoint walker (`walk`), `netlab checks` full set.
- Duplicates REMOVED: Purple Hat ping/scan/traceroute engines deleted —
  NetLab live engines are the single canonical `ping` / `scan` / `trace`;
  the bot's 15-port list kept as data (`--profile bot15`, only list with
  465/587). Purple Hat interfaces/netstat kept (NetLab has none).

## 1.1.0 — 2026-11-08
- 250k Agent Swarm added from Darion's Gemini video spec (docs/SWARM.md):
  C2 human-in-the-loop gate, 250x1,000 virtual fleet (labelled, 0 processes),
  telemetry pipeline over the merged engine, invariant registry + invariant
  fuzzing, replay-verified Synthesis & Audit with escalation to human
  analysts, all 5 human roles mapped. eBPF/XDP and Rust/Go/C++ sandbox items
  are descriptor specs only, stated as such.

## 1.0.0 — 2026-11-08
- Merge of Accurate-Cyber-Defense-Network-Analyzer + Accurate-Cyber-Defense-Purple-Hat-Bot v19.1.
- Analyzer dissection/hex/disassembly/stats in tested stdlib Python; dashboard preserved verbatim.
- Purple Hat detector with upstream thresholds/cooldown; Telegram alerting config-compatible.
- Traffic simulation moved in-memory (upstream sent real traffic); PCAP export gap stated honestly.
