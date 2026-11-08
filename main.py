#!/usr/bin/env python3
"""Purple-Hat Network Analyzer — ONE interface for the merged tools.

Merged from Accurate Cyber Defense (github.com/Accurate-Cyber-Defense):
  Network Analyzer (HTML dashboard) + Purple Hat Bot v19.1 (Python CLI)

  python main.py demo                     analyzer + detector end-to-end demo
  python main.py analyze                  simulated capture: list, dissect, hex, stats
  python main.py analyze --seed 7 --count 30
  python main.py packet <index>           details + hex + disassembly for one demo packet
  python main.py simulate <kind> <src> <dst>   in-memory traffic sim -> detector
                                               kind: portscan|dos|httpflood|httpsflood
  python main.py scan <host>              live common-port scan of ONE named host
  python main.py ping <host>              live ping
  python main.py trace <host>             live traceroute
  python main.py shell                    Purple Hat Bot interactive shell (its commands)
  python main.py swarm plan               250k agent swarm: C2 plan (needs human approval)
  python main.py swarm run                shows the plan — does NOT execute unapproved
  python main.py swarm run --approve      human-approved fleet cycle: telemetry ->
                                          detection -> replay-verified findings -> escalation
  python main.py swarm fuzz               invariant fuzzing of the dissector
  python main.py ask "<question>"         NetLab orchestrator (RAG + council) [decompressed]
  python main.py subnet <cidr>            NetLab subnet calculator
  python main.py topology <kind> <n>      NetLab topology sim + SPOF analysis
  python main.py layer <thing>            NetLab OSI / TCP-IP layer mapper
  python main.py device "<need>"          NetLab device advisor
  python main.py quiz                     NetLab tutor study cards
  python main.py track <ip,ip,...>        NetLab IP hopper/tracker/mapper (start/middle/end)
  python main.py track-topo <kind> <n> <src> <dst>
  python main.py earth <ip,ip,...>        NetLab Google Earth KML export
  python main.py flow "<topic>"           NetLab Google Flow video plan
  python main.py bench                    NetLab MLOps benchmark
  python main.py stages                   NetLab backbone stage contract
  python main.py connect <host> <port>    LIVE TCP connect + latency (NetLab live)
  python main.py dns <host>               LIVE DNS lookup (NetLab live)
  python main.py http <url>               LIVE HTTP probe (NetLab live)
  python main.py geo <ip>                 LIVE IP geo lookup (NetLab live, approximate)
  python main.py walk [--selftest]        NetLab beyond-the-END endpoint walker
  python main.py netlab checks            the decompressed NetLab self-checks, full set
  python main.py matrix report            MATH-THE-MATRIX lab (56 formulas, battery, council, gates)
  python main.py matrix battery <n>       MATH test battery at n tests
  python main.py cve report               CVE-RE inventory report (44 records) + its checks
  python main.py cve catalog              CVE-RE: every record
  python main.py mask checks              sysadmin-footprint-mask: its full 36-check suite
  python main.py mask sanitize            sysadmin: sanitize the sample env (demo)
  python main.py council                  ONE council status for all labs (deduped surface)
  python main.py brain status             Purple Hat core council seats (Carbon 4 + Muse + Flows)
  python main.py brain review             council review of a demo DoS alert set (strictest wins)
  python main.py chamber demo             Sandbox-API chamber (from the Docker image): static triage, never executes
  python main.py chamber triage <id>      triage one synthetic sample in the chamber
  python main.py honeypot report          honeypot log analysis (from honeyroot-x): no listener, bait never grants
  python main.py --hold-demo              every lab's HOLD gates, one demo (exit 2)
  (bare `python main.py` = demo + full unified checks, matching the labs' own convention)
  (ping / scan / trace are SINGLE canonical commands since v1.2.0 — they run
   the NetLab live engines; the Purple Hat duplicates were removed, and
   `scan <host> --profile bot15` keeps the bot's exact 15-port list)
  python main.py dashboard                path of the merged HTML dashboard
  python main.py export                   demo capture exported as JSON + CSV counts
  python main.py checks                   self-checks (CHECKS n/n, RESULT, VERDICT)

Stdlib only. Telegram sends happen only in the shell / via config you set;
no token is stored in this repo.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from purple_analyzer import config as cfgmod
from purple_analyzer import diagnostics, labs, swarm, telegram_alert, traffic_sim
from llmx_netlab import iphop, live
from llmx_netlab import netlab as netlab_mod
from llmx_netlab.backbone import STAGES
from llmx_netlab.earth import build_kml
from llmx_netlab.flowvideo import plan_video
from llmx_netlab.mlops import run_benchmark
from llmx_netlab.orchestrator import Orchestrator
from llmx_netlab.rag import RagSystem
from purple_analyzer.monitor import Monitor
from purple_analyzer.packets import dissect, disassemble, hex_dump
from purple_analyzer.report import packets_csv, packets_json, threat_report
from purple_analyzer.simulator import simulated_packets


def _print(obj):
    print(json.dumps(obj, indent=2) if isinstance(obj, (dict, list)) else obj)


def demo():
    mon = Monitor()
    mon.add_ip("192.168.1.50")
    mon.running = True
    pkts = simulated_packets(20, seed=42)
    mon.feed_many(pkts)
    print("== ANALYZER: first packet ==")
    _print(dissect(pkts[0]))
    print(hex_dump(pkts[0].payload))
    print(disassemble(pkts[0]))
    print("== PROTOCOL STATS ==")
    _print(mon.stats())
    print("== PURPLE HAT: simulated port scan against the monitored host ==")
    scan = traffic_sim.generate("portscan", "203.0.113.99", "192.168.1.50", start_time=1000.0)
    alerts = mon.feed_many(scan)
    _print([a.to_dict() for a in alerts])
    print("== REPORT ==")
    _print(threat_report(mon))
    return 0


def analyze(argv):
    seed, count = 42, 20
    while argv:
        if argv[0] == "--seed":
            seed = int(argv[1]); argv = argv[2:]
        elif argv[0] == "--count":
            count = int(argv[1]); argv = argv[2:]
        else:
            argv = argv[1:]
    pkts = simulated_packets(count, seed=seed)
    for i, p in enumerate(pkts):
        print(f"{i:>3}  {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}  "
              f"{p.protocol:<6} {p.size:>4}B  {p.flags}")
    from purple_analyzer.packets import protocol_stats
    _print(protocol_stats(pkts))
    return 0


def packet_cmd(argv):
    idx = int(argv[0]) if argv else 0
    pkts = simulated_packets(20, seed=42)
    p = pkts[idx]
    _print(dissect(p))
    print(hex_dump(p.payload))
    print(disassemble(p))
    return 0


def simulate(argv):
    kind, src, dst = argv[0], argv[1], argv[2]
    mon = Monitor()
    mon.add_ip(dst)
    pkts = traffic_sim.generate(kind, src, dst, start_time=0.0)
    alerts = mon.feed_many(pkts)
    _print({"kind": kind, "packets_generated": len(pkts), "in_memory_only": True,
            "alerts": [a.to_dict() for a in alerts]})
    return 0


def swarm_cmd(argv):
    sub = argv[0] if argv else "plan"
    if sub == "plan":
        _print(swarm.plan_fleet())
        return 0
    if sub == "fuzz":
        _print(swarm.fuzz_invariants())
        return 0
    if sub == "run":
        approved = "--approve" in argv
        result = swarm.run_fleet(approved=approved)
        _print(result)
        return 0
    print("swarm subcommands: plan | run [--approve] | fuzz")
    return 2


def netlab_checks():
    """The decompressed LLM-X-NetLab self-checks, run in full (netlab checks)."""
    rag = RagSystem()
    orch = Orchestrator()
    rows = []

    def check(name, fn):
        try:
            ok = bool(fn())
        except Exception:
            ok = False
        rows.append((name, ok))

    check("kb_loaded", lambda: len(rag.entries) >= 20)
    check("rag_finds_router", lambda: rag.search("What does a router do?")[0]["id"] == "router")
    check("subnet_math", lambda: netlab_mod.subnet_info("192.168.1.0/24")["usable_hosts"] == 254)
    check("subnet_private", lambda: netlab_mod.subnet_info("192.168.1.0/24")["is_private"] is True)
    check("subnet_public", lambda: netlab_mod.subnet_info("8.8.8.0/24")["is_private"] is False)
    check("ip_class_c", lambda: netlab_mod.subnet_info("192.168.1.0/24")["class"]["class"] == "C")
    check("star_spof_is_center", lambda: netlab_mod.analyse_topology("star", 6)["single_points_of_failure"] == [0])
    check("mesh_no_spof", lambda: netlab_mod.analyse_topology("mesh", 5)["single_points_of_failure"] == [])
    check("ring_hops", lambda: netlab_mod.analyse_topology("ring", 6)["worst_case_hops"] == 3)
    check("layer_router", lambda: netlab_mod.layer_of("router")["osi_layer"] == 3)
    check("ping_simulated", lambda: netlab_mod.simulate_ping("star", 5, 1, 3)["simulated"] is True)
    check("ask_proceeds", lambda: orch.ask("What does a switch do?")["verdict"] == "PROCEED")
    check("ask_live_proceeds", lambda: orch.ask("ping localhost")["verdict"] == "PROCEED")
    import socket as _s
    _srv = _s.socket(); _srv.bind(("127.0.0.1", 0)); _srv.listen(1)
    _port = _srv.getsockname()[1]
    check("live_tcp_connect_loopback", lambda: live.tcp_connect("127.0.0.1", _port)["open"] is True)
    check("live_dns_localhost", lambda: "127.0.0.1" in live.dns_lookup("localhost")["addresses"])
    _srv.close()
    check("benchmark", lambda: run_benchmark(rag)["accuracy"] >= 0.8)
    _trk = iphop.track_path(["192.168.1.1", "10.0.0.1", "172.16.0.1", "203.0.113.10"])
    check("track_start", lambda: _trk["start"]["ip"] == "192.168.1.1" and "START" in _trk["start"]["role"])
    check("track_middle", lambda: _trk["middle_count"] == 2 and all("MIDDLE" in h["role"] for h in _trk["middle"]))
    check("track_end", lambda: _trk["end"]["ip"] == "203.0.113.10" and "ENDING" in _trk["end"]["role"])
    check("track_map_renders", lambda: "IP PATH MAP" in iphop.render_map(_trk))
    check("earth_kml", lambda: "<kml" in build_kml(_trk, {"192.168.1.1": (34.05, -118.24), "203.0.113.10": (40.71, -74.0)}))
    check("flow_plan", lambda: plan_video("star topology")["render"].startswith("HOLD"))
    check("carbon4_tiers", lambda: orch.council.decider.thinking_budget == 8192)
    passed = sum(1 for _, ok in rows if ok)
    for name, ok in rows:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"CHECKS {passed}/{len(rows)}")
    print("RESULT:", "PASS" if passed == len(rows) else "FAIL")
    print("VERDICT:", "PROCEED" if passed == len(rows) else "FAIL")
    return 0 if passed == len(rows) else 1


def netlab_dispatch(cmd, rest):
    """Single implementation for every decompressed NetLab feature.
    Top-level commands and the `netlab` namespace both route here."""
    if cmd == "checks":
        return netlab_checks()
    if cmd == "demo":
        orch = Orchestrator()
        _print(orch.ask("What does a router do?"))
        _print(netlab_mod.subnet_info("192.168.1.0/24"))
        _print(netlab_mod.analyse_topology("star", 6))
        return 0
    if cmd == "ask":
        _print(Orchestrator().ask(" ".join(rest)))
        return 0
    if cmd == "subnet":
        _print(netlab_mod.subnet_info(rest[0])); return 0
    if cmd == "topology":
        _print(netlab_mod.analyse_topology(rest[0], int(rest[1]))); return 0
    if cmd == "layer":
        _print(netlab_mod.layer_of(rest[0])); return 0
    if cmd == "device":
        _print(netlab_mod.advise_device(" ".join(rest))); return 0
    if cmd == "track":
        trk = iphop.track_path(rest[0].split(","))
        _print(trk); print(iphop.render_map(trk)); return 0
    if cmd == "track-topo":
        trk = iphop.track_topology(rest[0], int(rest[1]), int(rest[2]), int(rest[3]))
        _print(trk)
        if trk.get("path"):
            print(iphop.render_map(trk))
        return 0
    if cmd == "earth":
        trk = iphop.track_path(rest[0].split(","))
        print(build_kml(trk)); return 0
    if cmd == "flow":
        _print(plan_video(" ".join(rest))); return 0
    if cmd == "quiz":
        _print(Orchestrator().quiz()); return 0
    if cmd == "bench":
        _print(run_benchmark(RagSystem())); return 0
    if cmd == "stages":
        _print(STAGES); return 0
    if cmd == "connect":
        _print(live.tcp_connect(rest[0], int(rest[1]))); return 0
    if cmd == "dns":
        _print(live.dns_lookup(rest[0])); return 0
    if cmd == "http":
        _print(live.http_probe(rest[0])); return 0
    if cmd == "geo":
        _print(live.geo_lookup(rest[0])); return 0
    if cmd == "walk":
        import beyond_end
        old_argv = sys.argv
        sys.argv = ["beyond_end.py"] + list(rest)
        try:
            return beyond_end.main()
        finally:
            sys.argv = old_argv
    print(f"unknown netlab command: {cmd}")
    return 2


def shell():
    cfg = cfgmod.load_config()
    mon = Monitor(thresholds=cfg["thresholds"], cooldown=float(cfg["alert_cooldown"]))
    for ip in cfg.get("monitored_ips", []):
        mon.add_ip(ip)
    print("Purple-Hat Network Analyzer shell — type 'help', 'exit'")
    while True:
        try:
            command = input("AccurateBot> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not command:
            continue
        parts = command.split()
        cmd = parts[0].lower()
        if cmd in ("exit", "stop"):
            break
        elif cmd == "help":
            print("help | clear | ping <IP> | scan <IP> | tracert <IP> | ip a | netstat\n"
                  "add ip <IP> | remove ip <IP> | view | start monitoring <IP>\n"
                  "generate traffic <src> <kind> <dst> | test telegram | export to telegram\n"
                  "config_telegram token <VALUE> | config_telegram chat_id <VALUE>")
        elif cmd == "clear":
            os.system("cls" if os.name == "nt" else "clear")
        elif cmd == "ping" and len(parts) > 1:
            _print(live.ping_host(parts[1]))
        elif cmd == "scan" and len(parts) > 1:
            _print(live.port_scan(parts[1], ports=diagnostics.BOT15_PORTS))
        elif cmd == "tracert" and len(parts) > 1:
            _print(live.traceroute(parts[1]))
        elif cmd == "ip":
            print(diagnostics.interfaces())
        elif cmd == "netstat":
            print(diagnostics.netstat())
        elif cmd == "add" and len(parts) > 2:
            print("added" if mon.add_ip(parts[2]) else "invalid IP")
        elif cmd == "remove" and len(parts) > 2:
            print("removed" if mon.remove_ip(parts[2]) else "not monitored")
        elif cmd == "view":
            _print(mon.status())
        elif cmd == "start" and len(parts) > 2:
            mon.add_ip(parts[2]); mon.running = True
            mon.feed_many(simulated_packets(20, seed=1, host=parts[2]))
            print(f"monitoring {parts[2]} — simulated feed scored, alerts: "
                  f"{len(mon.detector.alerts)}")
        elif cmd == "generate" and len(parts) > 4:
            pkts = traffic_sim.generate(parts[3], parts[2], parts[4])
            alerts = mon.feed_many(pkts)
            _print([a.to_dict() for a in alerts])
        elif cmd == "test":
            _print(telegram_alert.test_alert(cfg))
        elif cmd == "export":
            _print(telegram_alert.export_report(cfg, mon.status()["alerts"]))
        elif cmd == "config_telegram" and len(parts) > 2:
            key = "telegram_token" if parts[1] == "token" else "telegram_chat_id"
            cfg[key] = parts[2]
            cfgmod.save_config(cfg)
            print(f"{key} configured (value not shown)")
        else:
            print(f"Unknown command: {command} — type 'help'")
    return 0


def checks():
    rows = []

    def check(name, fn):
        try:
            ok = bool(fn())
        except Exception:
            ok = False
        rows.append((name, ok))

    from purple_analyzer.detector import Detector
    from purple_analyzer.packets import Packet
    pkts = simulated_packets(20, seed=42)
    check("sim_deterministic", lambda: [p.to_dict() for p in simulated_packets(5, seed=3)]
          == [p.to_dict() for p in simulated_packets(5, seed=3)])
    check("sim_count", lambda: len(pkts) == 20)
    check("protocol_http", lambda: any(p.protocol == "HTTP" for p in simulated_packets(200, seed=9)))
    check("protocol_dns", lambda: Packet("1.1.1.1", "8.8.8.8", 1234, 53, "UDP").protocol == "DNS")
    check("protocol_https_tls_note", lambda: "tls_note" in dissect(
        Packet("1.1.1.1", "8.8.8.8", 1234, 443, "TCP", b"\x16\x03\x01")))
    check("hex_dump_offset", lambda: hex_dump(b"AB").startswith("00000000  41 42"))
    check("hex_dump_ascii", lambda: "|AB|" in hex_dump(b"AB"))
    check("disassembly_fields", lambda: "IP  .src" in disassemble(pkts[0]))
    check("size_includes_header", lambda: pkts[0].size > len(pkts[0].payload))
    # detector: upstream thresholds
    check("detector_defaults_upstream", lambda: Detector().thresholds
          == {"port_scan": 10, "dos_attack": 100, "http_flood": 50})
    check("detector_cooldown_default", lambda: Detector().cooldown == 300.0)
    mon = Monitor(); mon.add_ip("192.168.1.50")
    check("portscan_alert", lambda: any(a.type == "Port Scan" for a in
          mon.feed_many(traffic_sim.generate("portscan", "203.0.113.9", "192.168.1.50"))))
    mon2 = Monitor(); mon2.add_ip("192.168.1.50")
    check("dos_alert", lambda: any(a.type == "DoS Attack" for a in
          mon2.feed_many(traffic_sim.generate("dos", "203.0.113.9", "192.168.1.50"))))
    mon3 = Monitor(); mon3.add_ip("192.168.1.50")
    check("http_flood_alert", lambda: any(a.type == "HTTP Flood" for a in
          mon3.feed_many(traffic_sim.generate("httpflood", "203.0.113.9", "192.168.1.50"))))
    mon4 = Monitor(); mon4.add_ip("10.0.0.1")
    check("monitor_filters_unmonitored", lambda: mon4.feed(
        Packet("9.9.9.9", "8.8.8.8", 1, 80, "TCP")) == [] and mon4.packets == [])
    check("validate_ip", lambda: cfgmod.validate_ip("192.168.1.1") and not cfgmod.validate_ip("999.1.1.1"))
    check("config_user_id_alias", lambda: _alias_check())
    check("telegram_unconfigured_no_send", lambda: telegram_alert.send_alert(
        {"telegram_token": "", "telegram_chat_id": ""}, {"ip": "1.1.1.1"})["sent"] is False)
    check("export_json", lambda: len(json.loads(packets_json(pkts))) == 20)
    check("export_csv_header", lambda: packets_csv(pkts).splitlines()[0].startswith("timestamp,src_ip"))
    check("traffic_sim_in_memory", lambda: all(isinstance(p, Packet) for p in
          traffic_sim.generate("portscan", "1.1.1.1", "2.2.2.2")))
    check("dashboard_preserved", lambda: os.path.exists(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dashboard", "network-analyzer.html")))
    check("upstream_preserved", lambda: os.path.exists(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "upstream", "purple-hat-bot-original.py")))
    # --- 250k swarm (Gemini video spec) ---
    _plan = swarm.plan_fleet()
    check("swarm_fleet_250k", lambda: _plan["fleet_size"] == 250_000
          and _plan["shards"] * _plan["bots_per_shard"] == 250_000)
    check("swarm_virtual_labelled", lambda: _plan["virtual"] is True
          and _plan["processes_spawned"] == 0)
    check("swarm_layers_4", lambda: len(_plan["layers"]) == 4
          and _plan["layers"][0]["layer"].startswith("Command & Control"))
    check("swarm_roles_5", lambda: set(_plan["human_roles"])
          == {"professors", "students", "scientists", "software developers", "engineers"})
    check("swarm_c2_blocks_unapproved", lambda: swarm.run_fleet(approved=False)["executed"] is False)
    _run = swarm.run_fleet(approved=True)
    check("swarm_verified_findings", lambda: _run["synthesis_audit"]["verified_count"] >= 3
          and _run["synthesis_audit"]["escalated_to_human"] == _run["synthesis_audit"]["verified_count"])
    check("swarm_fuzz_invariants_hold", lambda: _run["invariant_fuzzing"]["invariants_held"] is True)

    # --- decompressed NetLab + dedupe (v1.2.0) ---
    check("netlab_kb_loaded", lambda: len(RagSystem().entries) >= 20)
    check("netlab_subnet_math", lambda: netlab_mod.subnet_info("192.168.1.0/24")["usable_hosts"] == 254)
    check("netlab_track_start", lambda: iphop.track_path(["192.168.1.1", "203.0.113.10"])["start"]["ip"] == "192.168.1.1")
    check("dedupe_no_ph_ping", lambda: not hasattr(diagnostics, "ping_host"))
    check("dedupe_no_ph_scan", lambda: not hasattr(diagnostics, "scan_host"))
    check("dedupe_no_ph_trace", lambda: not hasattr(diagnostics, "trace_host"))
    check("bot15_profile_kept", lambda: 465 in diagnostics.BOT15_PORTS and 587 in diagnostics.BOT15_PORTS
          and len(diagnostics.BOT15_PORTS) == 15)
    # --- decompressed labs (v1.3.0) ---
    from math_matrix import catalog as _mm_catalog
    from cve_re.catalog import CATALOG as _cve_catalog
    from footprintmask import sanitizer as _mask_sanitizer
    check("matrix_formulas_verified", lambda: _mm_catalog.verify_all()[0] == _mm_catalog.verify_all()[1])
    check("matrix_domains_24", lambda: len({f.domain for f in _mm_catalog.FORMULAS}) >= 20)
    check("cve_catalog_44", lambda: len(_cve_catalog) == 44)
    check("mask_sanitizer_works", lambda: _mask_sanitizer.is_sanitized(
        _mask_sanitizer.sanitize(dict(labs.MASK_SAMPLE_ENV))["clean_env"]))
    check("council_single_surface", lambda: len(labs.council_status()["seats"]) == 6)
    from purple_analyzer import brains as _core_brains
    check("core_carbon_decides", lambda: _core_brains.carbon_decide(
        [{"type": "dos", "src": "198.51.100.9", "dst": "x", "count": 1500}])["decision"] == "ESCALATE"
        and _core_brains.carbon_decide([])["decision"] == "PROCEED")
    check("core_muse_advises", lambda: len(_core_brains.muse_advise([])["advice"]) == 4
          and _core_brains.council_review([])["strictest_wins"] is True)
    from php_re.brains import HOLD_GATES as _php_gates
    from php_re import carbon4 as _php_c4
    check("php_brains_full_seats", lambda: len(_php_gates) == 14
          and _php_c4.seat_status()["model_id"] == "google/gemini-carbon-4-extended-pro-thinking")
    from php_re.sandbox import sandbox_demo as _chamber_demo
    from php_re.honeypot import honeypot_summary as _hp_summary
    check("chamber_never_executes", lambda: _chamber_demo()["any_executed"] is False
          and _chamber_demo()["network_access"] is False and _chamber_demo()["total"] == 15)
    check("honeypot_no_listener", lambda: _hp_summary()["listener_open"] is False
          and _hp_summary()["access_granted"] is False and _hp_summary()["attempts"] == 12)
    passed = sum(1 for _, ok in rows if ok)
    for name, ok in rows:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"CHECKS {passed}/{len(rows)}")
    print(f"RESULT {'PASS' if passed == len(rows) else 'FAIL'}")
    print(f"VERDICT {'PROCEED' if passed == len(rows) else 'HOLD — failing checks above'}")
    return 0 if passed == len(rows) else 1


def _alias_check():
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"telegram_token": "x", "user_id": "123"}, f)
        path = f.name
    try:
        return cfgmod.load_config(path)["telegram_chat_id"] == "123"
    finally:
        os.unlink(path)


def main(argv):
    if not argv:
        demo()
        return checks()
    if argv[0] == "--hold-demo":
        return labs.combined_hold_demo()
    cmd, rest = argv[0], argv[1:]
    if cmd == "demo":
        return demo()
    if cmd == "analyze":
        return analyze(rest)
    if cmd == "packet":
        return packet_cmd(rest)
    if cmd == "simulate":
        return simulate(rest)
    if cmd == "scan":
        if "--profile" in rest and "bot15" in rest:
            _print(live.port_scan(rest[0], ports=diagnostics.BOT15_PORTS))
        else:
            _print(live.port_scan(rest[0]))
        return 0
    if cmd == "ping":
        _print(live.ping_host(rest[0])); return 0
    if cmd == "trace":
        out = live.trace_and_track(rest[0])
        _print(out)
        if out.get("track"):
            print(iphop.render_map(out["track"]))
        return 0
    if cmd == "netlab":
        return netlab_dispatch(rest[0] if rest else "checks", rest[1:])
    if cmd == "matrix":
        return labs.matrix_dispatch(rest)
    if cmd == "cve":
        return labs.cve_dispatch(rest)
    if cmd == "mask":
        return labs.mask_dispatch(rest)
    if cmd == "council":
        _print(labs.council_status()); return 0
    if cmd == "brain":
        from purple_analyzer import brains as _brains
        sub = rest[0] if rest else "status"
        if sub == "status":
            _print(_brains.seat_status()); return 0
        if sub == "review":
            demo_alerts = [{"type": "dos", "src": "198.51.100.9",
                            "dst": "192.168.1.50", "count": 1500},
                           {"type": "http_flood", "src": "198.51.100.9",
                            "dst": "192.168.1.50", "count": 900}]
            _print(_brains.council_review(demo_alerts)); return 0
        print("brain subcommands: status | review"); return 2
    if cmd == "chamber":
        return labs.chamber_dispatch(rest)
    if cmd == "honeypot":
        return labs.honeypot_dispatch(rest)
    if cmd in ("ask", "subnet", "topology", "layer", "device", "quiz", "track",
               "track-topo", "earth", "flow", "bench", "stages", "connect",
               "dns", "http", "geo", "walk"):
        return netlab_dispatch(cmd, rest)
    if cmd == "shell":
        return shell()
    if cmd == "swarm":
        return swarm_cmd(rest)
    if cmd == "dashboard":
        print(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "dashboard", "network-analyzer.html")); return 0
    if cmd == "export":
        pkts = simulated_packets(20, seed=42)
        print(packets_json(pkts)[:200] + " ...")
        print(f"json_packets=20 csv_lines={len(packets_csv(pkts).splitlines())}")
        return 0
    if cmd == "checks":
        return checks()
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
