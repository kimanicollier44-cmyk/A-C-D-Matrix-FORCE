import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from purple_analyzer import config as cfgmod, telegram_alert, traffic_sim
from purple_analyzer.detector import Detector
from purple_analyzer.monitor import Monitor
from purple_analyzer.packets import Packet, dissect, disassemble, hex_dump, protocol_stats
from purple_analyzer.report import packets_csv, packets_json
from purple_analyzer.simulator import simulated_packets

ROOT = os.path.join(os.path.dirname(__file__), "..")


def test_sim_deterministic():
    a = [p.to_dict() for p in simulated_packets(10, seed=5)]
    b = [p.to_dict() for p in simulated_packets(10, seed=5)]
    assert a == b


def test_protocols():
    assert Packet("1.1.1.1", "8.8.8.8", 1, 53, "UDP").protocol == "DNS"
    assert Packet("1.1.1.1", "8.8.8.8", 1, 80, "TCP").protocol == "HTTP"
    assert Packet("1.1.1.1", "8.8.8.8", 1, 443, "TCP").protocol == "HTTPS"
    assert Packet("1.1.1.1", "8.8.8.8", 0, 0, "ICMP").protocol == "ICMP"


def test_hex_and_disassembly():
    p = Packet("10.0.0.1", "10.0.0.2", 1234, 80, "TCP", b"GET / HTTP/1.1\r\n\r\n", flags="PSH,ACK")
    assert hex_dump(p.payload).startswith("00000000")
    assert "GET" in disassemble(p)
    d = dissect(p)
    assert d["http_method"] == "GET" and d["protocol"] == "HTTP"


def test_detector_thresholds_are_upstream():
    d = Detector()
    assert d.thresholds == {"port_scan": 10, "dos_attack": 100, "http_flood": 50}
    assert d.cooldown == 300.0


def _mon():
    m = Monitor(); m.add_ip("192.168.1.50"); return m


def test_portscan_alert():
    alerts = _mon().feed_many(traffic_sim.generate("portscan", "203.0.113.9", "192.168.1.50"))
    assert any(a.type == "Port Scan" for a in alerts)


def test_dos_alert():
    alerts = _mon().feed_many(traffic_sim.generate("dos", "203.0.113.9", "192.168.1.50"))
    assert any(a.type == "DoS Attack" for a in alerts)


def test_http_flood_alert():
    alerts = _mon().feed_many(traffic_sim.generate("httpflood", "203.0.113.9", "192.168.1.50"))
    assert any(a.type == "HTTP Flood" for a in alerts)


def test_cooldown_suppresses_repeat():
    m = _mon()
    first = m.feed_many(traffic_sim.generate("portscan", "203.0.113.9", "192.168.1.50", start_time=0.0))
    second = m.feed_many(traffic_sim.generate("portscan", "203.0.113.9", "192.168.1.50", start_time=30.0))
    assert len([a for a in first if a.type == "Port Scan"]) == 1
    assert len([a for a in second if a.type == "Port Scan"]) == 0


def test_monitor_filter_and_status():
    m = Monitor(); m.add_ip("10.0.0.1")
    assert m.feed(Packet("9.9.9.9", "8.8.8.8", 1, 80, "TCP")) == []
    assert m.status()["packets_captured"] == 0
    assert m.remove_ip("10.0.0.1") is True


def test_config_alias_and_roundtrip(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"telegram_token": "x", "user_id": "42"}))
    assert cfgmod.load_config(str(p))["telegram_chat_id"] == "42"
    cfg = cfgmod.load_config(str(p))
    assert cfgmod.save_config(cfg, str(p)) is True


def test_telegram_fake_opener():
    class Resp:
        status = 200
        def __enter__(self): return self
        def __exit__(self, *a): return False
    seen = {}
    def opener(req, timeout=10):
        seen["url"] = req.full_url; return Resp()
    out = telegram_alert.send_alert({"telegram_token": "TESTTOKEN", "telegram_chat_id": "7"},
                                    {"timestamp": "t", "ip": "1.1.1.1", "type": "Port Scan",
                                     "description": "d"}, opener=opener)
    assert out["sent"] is True
    assert "TESTTOKEN" in seen["url"]  # used for the API call only
    assert "TESTTOKEN" not in json.dumps(out)  # never in results/reports


def test_telegram_unconfigured():
    out = telegram_alert.send_alert({"telegram_token": "", "telegram_chat_id": ""},
                                    {"ip": "1.1.1.1"})
    assert out == {"sent": False, "reason": "not configured"}


def test_exports():
    pkts = simulated_packets(5, seed=1)
    assert len(json.loads(packets_json(pkts))) == 5
    assert packets_csv(pkts).count("\n") >= 6
    assert protocol_stats(pkts)


def test_upstream_preserved_hashes():
    def sha(path):
        return hashlib.sha256(open(path, "rb").read()).hexdigest()
    assert sha(os.path.join(ROOT, "upstream", "network-analyzer-original.html")) == \
        "8f44319395bfbb315cc02e2ca094f681bfd3f4aa69c4e7f3ca1cecf461ccafc9"
    assert sha(os.path.join(ROOT, "upstream", "purple-hat-bot-original.py")) == \
        "73a6a5a4b217c970b1db5841ffd87c707ea06f39542193fbf54fd878610d71e8"


from purple_analyzer import swarm


def test_swarm_plan_is_250k_virtual():
    plan = swarm.plan_fleet()
    assert plan["fleet_size"] == 250_000
    assert plan["shards"] * plan["bots_per_shard"] == 250_000
    assert plan["virtual"] is True and plan["processes_spawned"] == 0
    assert plan["status"] == "AWAITING_HUMAN_APPROVAL"


def test_swarm_layers_and_roles_match_video():
    plan = swarm.plan_fleet()
    layers = [row["layer"] for row in plan["layers"]]
    assert layers[0].startswith("Command & Control")
    assert any("Agent Fleet" in x for x in layers)
    assert any("Telemetry" in x for x in layers)
    assert any("Synthesis" in x for x in layers)
    assert set(plan["human_roles"]) == {"professors", "students", "scientists",
                                         "software developers", "engineers"}


def test_swarm_c2_gate():
    assert swarm.run_fleet(approved=False)["executed"] is False


def test_swarm_run_verifies_and_escalates():
    run = swarm.run_fleet(approved=True)
    sa = run["synthesis_audit"]
    assert run["telemetry"]["packets_ingested"] == len(swarm.telemetry_stream())
    assert sa["verified_count"] >= 3  # port scan + DoS + HTTP flood all reproduce
    assert sa["escalated_to_human"] == sa["verified_count"]
    types = {f["type"] for f in sa["verified_findings"]}
    assert {"Port Scan", "DoS Attack", "HTTP Flood"} <= types


def test_swarm_fuzz_invariants():
    out = swarm.fuzz_invariants(iterations=300)
    assert out["violations"] == 0 and out["invariants_held"] is True


def test_dashboard_panels_present():
    html = open(os.path.join(ROOT, "dashboard", "network-analyzer.html")).read()
    for marker in ["Network Traffic", "Packet Analysis", "Traffic Statistics",
                   "Terminal", "hexViewer", "protocolChart"]:
        assert marker in html
