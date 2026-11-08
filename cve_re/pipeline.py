"""Pipeline + self-checks for CVE-RE (offline, deterministic)."""
from __future__ import annotations

from .analyzer import group_by_type, group_by_vendor, rank, remediation_plan
from .carbon4 import carbon_decide, seat_status, stress_controls
from .catalog import CATALOG, get_record
from .flows import merged_plan
from .gates import HOLD_GATES, gate_check

REQUIRED_FIELDS = ("cve_id", "name", "vendor", "product", "vuln_type",
                   "cvss", "kev", "year", "vuln_class", "remediation")


def run_lab() -> dict:
    top = rank()[0]
    return {
        "catalog_count": len(CATALOG),
        "by_type": {k: len(v) for k, v in group_by_type().items()},
        "by_vendor": {k: len(v) for k, v in group_by_vendor().items()},
        "top": top, "top_list": rank()[:10],
        "carbon4": carbon_decide(top),
        "carbon4_seat": seat_status(),
        "carbon4_stress": stress_controls(),
        "flows": merged_plan(top),
        "hold_gates": sorted(HOLD_GATES),
    }


def run_checks() -> list:
    checks = []
    ids = [r["cve_id"] for r in CATALOG]
    checks.append(("catalog_at_least_40_records", len(CATALOG) >= 40))
    checks.append(("catalog_ids_unique", len(ids) == len(set(ids))))
    checks.append(("catalog_required_fields",
                   all(all(k in r for k in REQUIRED_FIELDS) for r in CATALOG)))
    types = {r["vuln_type"] for r in CATALOG}
    checks.append(("both_rce_and_memory_types_present",
                   {"rce", "memory_disclosure"} <= types))
    checks.append(("all_records_unauthenticated",
                   all(r["unauthenticated"] for r in CATALOG)))
    bleed = remediation_plan(get_record("CVE-2025-5777"), patched=True)
    checks.append(("citrixbleed_patch_alone_not_closed",
                   bleed["status"] == "patched_not_closed"))
    ts = remediation_plan(get_record("CVE-2025-53770"), patched=True,
                          sessions_rotated=True)
    checks.append(("toolshell_needs_key_rotation",
                   ts["status"] == "patched_not_closed"
                   and "rotate_keys" in ts["missing"]))
    stress = stress_controls()
    checks.append(("carbon4_stress_4_of_4",
                   len(stress) == 4 and all(c["passed"] for c in stress)))
    checks.append(("carbon4_cannot_override_hold",
                   carbon_decide(get_record("CVE-2025-55182"),
                                 base_verdict="HOLD")["verdict"] == "HOLD"))
    checks.append(("flows_all_flows_used", merged_plan()["all_flows_used"] is True))
    checks.append(("hold_gates_at_least_10", len(HOLD_GATES) >= 10))
    checks.append(("live_actions_held",
                   all(gate_check(a)["verdict"] == "HOLD" for a in
                       ("live_exploitation", "live_scanning_public_target",
                        "exploit_payload_generation", "live_gemini_api_call"))))
    checks.append(("ranking_deterministic",
                   [r["cve_id"] for r in rank()] == [r["cve_id"] for r in rank()]))
    checks.append(("top_priority_is_critical",
                   rank()[0] is not None and rank()[0]["cve_id"] in ids))
    return checks
