import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from cve_re.analyzer import (filter_catalog, group_by_type, group_by_vendor,
                             priority_score, rank, remediation_plan, search)
from cve_re.carbon4 import carbon_decide, seat_status, stress_controls
from cve_re.catalog import CATALOG, get_record
from cve_re.flows import carbon_flow_plan, flowx_plan, merged_plan
from cve_re.gates import HOLD_GATES, gate_check, is_held
from cve_re.pipeline import run_checks

REQUIRED = ("cve_id", "name", "vendor", "product", "vuln_type", "cvss",
            "kev", "exploited", "year", "vuln_class", "remediation")


def test_catalog_at_least_40_unique():
    ids = [r["cve_id"] for r in CATALOG]
    assert len(CATALOG) >= 40 and len(ids) == len(set(ids))


def test_catalog_required_fields_and_types():
    for r in CATALOG:
        for k in REQUIRED:
            assert k in r, (r["cve_id"], k)
        assert r["vuln_type"] in ("rce", "memory_disclosure", "auth_bypass_chain")
        assert r["cvss"] is None or isinstance(r["cvss"], float)
    types = {r["vuln_type"] for r in CATALOG}
    assert "rce" in types and "memory_disclosure" in types


def test_mandatory_records_present():
    for cid in ("CVE-2026-88771", "CVE-2025-5777", "CVE-2023-4966",
                "CVE-2026-3055", "CVE-2025-55182", "CVE-2025-53770",
                "CVE-2025-31324", "CVE-2021-44228", "CVE-2014-0160"):
        assert get_record(cid) is not None, cid


def test_ranking_deterministic_and_grouping():
    a = [r["cve_id"] for r in rank()]
    assert a == [r["cve_id"] for r in rank()]
    assert priority_score(get_record("CVE-2025-55182")) >= 90
    assert "Citrix" in group_by_vendor()
    assert set(group_by_type()) >= {"rce", "memory_disclosure"}


def test_filter_and_search():
    assert filter_catalog(vendor="Citrix")
    assert all(r["vendor"] == "Citrix" for r in filter_catalog(vendor="Citrix"))
    assert all(r["vuln_type"] == "rce" for r in filter_catalog(vuln_type="rce"))
    assert search("citrixbleed")


def test_citrixbleed_patch_alone_not_closed():
    bleed = get_record("CVE-2025-5777")
    assert bleed["requires_session_rotation"] is True
    assert remediation_plan(bleed, patched=True)["status"] == "patched_not_closed"
    closed = remediation_plan(bleed, patched=True, sessions_rotated=True)
    assert closed["status"] == "closed" and closed["patch_alone_closes"] is False


def test_toolshell_needs_session_and_key_rotation():
    ts = get_record("CVE-2025-53770")
    assert ts["requires_session_rotation"] and ts["requires_key_rotation"]
    plan = remediation_plan(ts, patched=True, sessions_rotated=True)
    assert plan["status"] == "patched_not_closed" and "rotate_keys" in plan["missing"]
    assert remediation_plan(ts, patched=True, sessions_rotated=True,
                            keys_rotated=True)["status"] == "closed"


def test_carbon4_seat_and_tighten_only():
    s = seat_status()
    assert s["engine"] == "gemini-2.5-pro"
    assert s["model_id"] == "google/gemini-carbon-4-extended-pro-thinking"
    assert s["thinking_tiers"] == [2048, 8192, 32768] and s["default_tier"] == 32768
    assert s["can_override_hold"] is False
    held = carbon_decide(get_record("CVE-2025-55182"), base_verdict="HOLD")
    assert held["verdict"] == "HOLD"


def test_carbon4_stress_controls_4_of_4():
    controls = stress_controls()
    assert len(controls) == 4 and all(c["passed"] for c in controls)


def test_flows_all_used():
    plan = merged_plan()
    assert plan["all_flows_used"] is True and plan["subtask_count"] >= 13
    assert flowx_plan()["subtask_count"] >= 13
    assert carbon_flow_plan()["rendered"] is False


def test_gates_hold():
    assert len(HOLD_GATES) >= 10
    for a in ("live_exploitation", "live_scanning_public_target",
              "exploit_payload_generation", "use_disclosed_credentials_or_sessions",
              "persistence_or_webshell_install", "live_target_fingerprinting",
              "live_video_generation", "live_gemini_api_call"):
        assert is_held(a) and gate_check(a)["verdict"] == "HOLD"


def test_pipeline_checks_all_pass():
    checks = run_checks()
    assert all(ok for _, ok in checks), checks


def test_hold_demo_exit_code_2():
    proc = subprocess.run([sys.executable, str(ROOT / "main.py"), "--hold-demo"],
                          capture_output=True, text=True)
    assert proc.returncode == 2 and "HOLD" in proc.stdout


def test_main_default_exit_0():
    proc = subprocess.run([sys.executable, str(ROOT / "main.py")],
                          capture_output=True, text=True)
    assert proc.returncode == 0 and "CHECKS" in proc.stdout and "PROCEED" in proc.stdout
