import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from php_re.brains import HOLD_GATES, is_held
from php_re.carbon4 import (DEFAULT_TIER, ENGINE, MODEL_ID, PHASES,
                            carbon_decide, seat_status, stress_controls)
from php_re.flows import (brain_flow_plan, build_timeline, carbon_flow_plan,
                          flow_engine, flowx_plan, merged_plan, muse_flow_plan,
                          script_to_storyboard, workspace_studio_plan)
from php_re.muse_seat import DECISION_AUTHORITY, advise, council
from php_re.muse_seat import seat_status as muse_status
from php_re.samples import get_sample
from php_re.sandbox import SANITIZED_SNIPPET

def test_carbon4_identity():
    s = seat_status()
    assert MODEL_ID == "google/gemini-carbon-4-extended-pro-thinking"
    assert ENGINE == "gemini-2.5-pro" and s["engine"] == ENGINE
    assert list(PHASES) == ["MAP", "MODEL", "STRESS", "DECIDE"]
    assert DEFAULT_TIER == 32768 and s["thinking_tiers"] == [2048, 8192, 32768]
    assert s["key_env_name"] == "GEMINI_API_KEY" and s["can_override_hold"] is False

def test_carbon4_stress_controls_all_pass():
    controls = stress_controls()
    assert len(controls) == 4 and all(c["passed"] for c in controls)

def test_carbon4_sanitized_not_escalated():
    code = ("<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');"
            " $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');")
    d = carbon_decide("static_analysis", code)
    assert d["level"] in ("low", "medium") and d["verdict"] == "ALLOW"

def test_carbon4_benign_proceeds_and_critical_holds():
    assert carbon_decide("static_analysis", "<?php echo 'hi';")["verdict"] == "ALLOW"
    crit = get_sample("code-injection-09")
    d = carbon_decide("execute_php_sample", crit["code"], base_risk=crit["base_risk"])
    assert d["verdict"] == "HOLD" and d["level"] in ("high", "critical")

def test_carbon4_can_only_tighten():
    assert carbon_decide("static_analysis", base_verdict="HOLD")["verdict"] == "HOLD"
    assert carbon_decide("upload_web_shell")["verdict"] == "HOLD"

def test_muse_full_seat():
    s = muse_status()
    assert s["decision_authority"] == "none" and DECISION_AUTHORITY == "none"
    assert s["must_plug"] is True and s["key_env_name"] == "MODEL_API_KEY"
    a = advise("static_analysis", "ALLOW")
    assert len(a["advice_items"]) == 4 and a["advice_count"] == 4
    assert a["decision_authority"] == "none" and a["can_override_hold"] is False

def test_council_strictest_wins_friendly_muse():
    # Friendly Muse ALLOW + a HOLD trigger still returns HOLD.
    c = council("execute_php_sample", advisor_verdict="ALLOW")
    assert c["verdict"] == "HOLD" and c["advisor_verdict"] == "ALLOW"
    assert c["decider_verdict"] == "HOLD" and len(c["advice_items"]) == 4

def test_council_muse_hold_tightens_and_clean_allows():
    assert council("static_analysis", advisor_verdict="HOLD")["verdict"] == "HOLD"
    assert council("static_analysis", advisor_verdict="ALLOW")["verdict"] == "ALLOW"

def test_flowx_graph():
    fx = flowx_plan()
    assert fx["subtask_count"] >= 10 and fx["queue_wait"] == 0
    ids = {t["id"] for t in fx["subtasks"]}
    assert {"intake", "taint", "obfuscation", "framework", "sandbox_triage",
            "honeypot_correlation", "hardening", "council_verdict"} <= ids
    assert fx["widest_level_size"] >= 2

def test_merged_plan_all_flows_and_engine():
    mp = merged_plan()
    assert mp["all_flows_used"] is True and len(mp["flows"]) == 4
    assert flow_engine()["engine_id"] == "google_flow"
    assert flow_engine()["primary_capability"] == "workflow"

def test_flows_applied_to_both_brains():
    for fn, brain in ((carbon_flow_plan, "carbon4"), (muse_flow_plan, "muse")):
        plan = fn()
        assert plan["brain"] == brain and plan["rendered"] is False
        assert plan["flowx"]["subtask_count"] >= 10
        assert set(plan["routed_through"]) == {"Gemini-FlowX", "Google Flow Filmmaking"}
    assert brain_flow_plan("carbon4")["role"] == "decider"
    assert brain_flow_plan("muse")["role"] == "advisor"
    assert is_held("live_video_generation")

def test_hold_gate_total():
    assert len(HOLD_GATES) == 14
