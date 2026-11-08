import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from purple_analyzer import brains

DOS = [{"type": "dos", "src": "198.51.100.9", "dst": "192.168.1.50", "count": 1500}]
SCAN = [{"type": "port_scan", "src": "198.51.100.9", "dst": "192.168.1.50", "count": 30}]


def test_carbon_identity_and_tiers():
    s = brains.seat_status()
    assert s["model_id"] == "google/gemini-carbon-4-extended-pro-thinking"
    assert s["thinking_tiers"] == {"standard": 2048, "extended": 8192, "deep": 32768}
    assert s["can_override_hold"] is False and s["live_calls_made"] is False
    assert s["advisor_decision_authority"] == "none"


def test_carbon_dos_escalates_empty_proceeds():
    assert brains.carbon_decide(DOS)["decision"] == "ESCALATE"
    assert brains.carbon_decide([])["decision"] == "PROCEED"


def test_carbon_stress_single_scan_not_escalated():
    d = brains.carbon_decide(SCAN)
    assert d["decision"] == "WATCH"
    assert all(d["stress_controls"].values())


def test_muse_four_advice_authority_none():
    m = brains.muse_advise(DOS)
    assert len(m["advice"]) == 4 and m["decision_authority"] == "none"
    assert m["live_call_made"] is False


def test_council_strictest_wins():
    r = brains.council_review(DOS)
    assert r["final"] == "ESCALATE" and r["strictest_wins"] is True
    assert r["muse_advice_items"] == 4


def test_flows_all_four_nothing_rendered():
    f = brains.flow_plan(DOS)
    assert f["all_flows_used"] is True and len(f["flows"]) == 4
    assert f["rendered"] is False
