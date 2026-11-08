"""Decompressed lab namespaces — MATH-THE-MATRIX, CVE-RE, sysadmin-footprint-mask.

Each lab's package is vendored verbatim at the project root (math_matrix/,
cve_re/, footprintmask/ + its bin/, configs/, examples/, Dockerfile.sandbox).
This module is the single unified-CLI wiring for them, replicating each
lab's own report/checks from its package APIs (their main.py CLIs are not
copied — one interface, per docs/DEDUPE_MAP.md).
"""
from __future__ import annotations

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _print(obj):
    print(json.dumps(obj, indent=2) if isinstance(obj, (dict, list)) else obj)


# ---------------------------------------------------------------- MATH ----
def matrix_checks(battery: int = 2048) -> int:
    from math_matrix import brains, catalog, flows, gates
    from math_matrix.labs import generate_candidates
    from math_matrix.test_runner import run_thousands
    results = []
    passed, total, failed = catalog.verify_all()
    results.append((f"formulas {passed}/{total}", passed == total and not failed))
    domains = sorted({f.domain for f in catalog.FORMULAS})
    results.append(("domains>=20", len(domains) >= 20))
    cands = generate_candidates()
    results.append(("candidates>=46", len(cands) >= 46))
    results.append(("all candidate bases are real formulas",
                    all(c.basis in catalog.BY_ID for c in cands)))
    results.append(("carbon4 stress controls", brains.stress_controls()))
    results.append(("muse advisor cannot lift HOLD", brains.MUSE["can_lift_hold"] is False))
    council = brains.council_evaluate("probe-candidate", 0.9, False)
    results.append(("council: carbon4 decides + muse gives 4 advice items",
                    council["final"] == "PROCEED" and len(council["muse_advice"]) == 4
                    and council["carbon4"]["tier"] == 32768
                    and council["carbon4"]["live_call_made"] is False))
    results.append(("all 4 Google Flows plan-only", flows.all_flows_used()))
    results.append(("12 HOLD gates present", len(gates.HOLD_GATES) == 12))
    results.append(("real deployment is HOLD", gates.check("real_deployment") == "HOLD"))
    results.append(("clinical use is HOLD", gates.check("clinical_use") == "HOLD"))
    run = run_thousands(battery)
    results.append((f"test battery {battery}+ all pass", run.ok and run.total >= battery))
    print(f"MATH-THE-MATRIX — domains ({len(domains)}): {', '.join(domains)}")
    print(f"Test battery: {run.passed}/{run.total} passed, {run.failed} failed")
    ok_count = 0
    for name, ok in results:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
        ok_count += int(ok)
    print(f"CHECKS {ok_count}/{len(results)} {'PROCEED' if ok_count == len(results) else 'HOLD'}")
    return 0 if ok_count == len(results) else 1


def matrix_dispatch(argv) -> int:
    from math_matrix import catalog, gates
    from math_matrix.labs import generate_candidates
    sub = argv[0] if argv else "report"
    if sub in ("report", "checks"):
        return matrix_checks(int(argv[1]) if len(argv) > 1 else 2048)
    if sub == "battery":
        from math_matrix.test_runner import run_thousands
        run = run_thousands(int(argv[1]) if len(argv) > 1 else 2048)
        _print({"passed": run.passed, "total": run.total, "failed": run.failed, "ok": run.ok})
        return 0 if run.ok else 1
    if sub == "domains":
        _print(sorted({f.domain for f in catalog.FORMULAS}))
        return 0
    if sub == "candidates":
        _print([{"id": c.id, "kind": c.kind, "basis": c.basis} for c in generate_candidates()])
        return 0
    if sub == "hold-demo":
        return gates.hold_demo()
    print("matrix subcommands: report [battery] | battery <n> | domains | candidates | hold-demo")
    return 2


# ----------------------------------------------------------------- CVE ----
def cve_report() -> int:
    from cve_re.analyzer import priority_score
    from cve_re.pipeline import run_checks, run_lab
    lab = run_lab()
    print("CVE-RE — static / synthetic / defensive lab (records are data, never exploit code)")
    print(f"catalog: {lab['catalog_count']} records | HOLD gates: {len(lab['hold_gates'])}")
    print("by type: " + ", ".join(f"{k}={v}" for k, v in sorted(lab["by_type"].items())))
    print("by vendor: " + ", ".join(f"{k}={v}" for k, v in sorted(lab["by_vendor"].items())))
    print("Top priority:")
    for r in lab["top_list"]:
        print(f"  {r['cve_id']:18} {priority_score(r):6}  {r['vendor']} — {r['product']} "
              f"({r['vuln_type']}, remediation {r['remediation']})")
    checks = run_checks()
    passed = sum(1 for _, ok in checks if ok)
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"CHECKS {passed}/{len(checks)} {'PROCEED' if passed == len(checks) else 'FAIL'}")
    return 0 if passed == len(checks) else 1


def cve_dispatch(argv) -> int:
    from cve_re.analyzer import filter_catalog, priority_score, rank
    from cve_re.carbon4 import carbon_decide, stress_controls
    from cve_re.catalog import CATALOG
    from cve_re.flows import merged_plan
    from cve_re.gates import gate_check
    from cve_re.pipeline import run_checks
    sub = argv[0] if argv else "report"
    if sub == "report":
        return cve_report()
    if sub == "checks":
        checks = run_checks()
        passed = sum(1 for _, ok in checks if ok)
        for name, ok in checks:
            print(f"{'PASS' if ok else 'FAIL'}  {name}")
        print(f"CHECKS {passed}/{len(checks)}")
        return 0 if passed == len(checks) else 1
    if sub == "catalog":
        for r in CATALOG:
            print(f"{r['cve_id']:18} {r['vendor']:20} {r['vuln_type']:19} score={priority_score(r)}")
        return 0
    if sub == "vendor":
        _print(filter_catalog(vendor=argv[1])); return 0
    if sub == "type":
        _print(filter_catalog(vuln_type=argv[1])); return 0
    if sub == "carbon":
        _print(carbon_decide(rank()[0])); return 0
    if sub == "carbon-stress":
        _print(stress_controls()); return 0
    if sub == "flows":
        _print(merged_plan(rank()[0])); return 0
    if sub == "hold-demo":
        d = gate_check("live_exploitation")
        print(f"HOLD: {d['action']} — {d['reason']} (Carbon 4 cannot override a HOLD)")
        return 2
    print("cve subcommands: report | checks | catalog | vendor <x> | type <x> | carbon | flows | hold-demo")
    return 2


# ---------------------------------------------------------------- MASK ----
MASK_SAMPLE_ENV = {
    "HISTFILE": "/home/operator/.bash_history",
    "SSH_CLIENT": "203.0.113.9 51234 22",
    "SSH_CONNECTION": "203.0.113.9 51234 192.0.2.10 22",
    "SUDO_USER": "operator",
    "USER": "operator",
    "LOGNAME": "operator",
    "HOME": "/home/operator",
    "PATH": "/custom/bin:/usr/bin",
    "EDITOR": "vim",
}


def _mask_read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def mask_session_report() -> dict:
    from footprintmask.brains import evaluate
    gates = evaluate({"own_system": True})
    return {"env": dict(MASK_SAMPLE_ENV), "available": ["unshare", "podman"],
            "profile_text": _mask_read("configs/profile.d/footprint-mask.sh"),
            "brain_verdict": "PASS" if not gates else "HOLD"}


def mask_checks() -> int:
    """The lab's own 36-check suite, replicated from its main.py (assets at root)."""
    from footprintmask import carbon4, flows, isolation, profile, sandbox, sanitizer
    from footprintmask.blackbox import BlackBox
    from footprintmask.brains import evaluate
    from footprintmask.freeai import MUSE_MODELS, SEATS, detected
    box = BlackBox()
    results = []

    def check(name, cond):
        results.append((name, bool(cond)))

    original = dict(MASK_SAMPLE_ENV)
    cleaned = sanitizer.sanitize(MASK_SAMPLE_ENV)
    check("sanitizer purges every present tracking var",
          set(cleaned["purged"]) >= {"HISTFILE", "SSH_CLIENT", "SSH_CONNECTION",
                                     "SUDO_USER", "USER", "LOGNAME"})
    check("sanitized env matches the baseline", sanitizer.is_sanitized(cleaned["clean_env"]))
    check("sanitizer never mutates its input", MASK_SAMPLE_ENV == original)
    check("workspace is the volatile /tmp/secure-workspace (0700)",
          cleaned["workspace"] == "/tmp/secure-workspace" and cleaned["workspace_mode"] == "0700")
    leaky = dict(cleaned["clean_env"]); leaky["SSH_CLIENT"] = "203.0.113.9 51234 22"
    check("a leaked SSH_CLIENT is caught", "SSH_CLIENT" in sanitizer.leaks(leaky))
    check("the clean env has no leaks", sanitizer.leaks(cleaned["clean_env"]) == [])
    check("isolation prefers unshare over podman",
          isolation.choose(["podman", "unshare"])["backend"] == "unshare")
    pod = isolation.choose(["podman"])
    check("podman fallback is rootless with network none",
          pod["backend"] == "podman" and pod["network"] == "none")
    check("no isolation backend is an honest hold", isolation.choose([])["held"] is True)
    profile_text = _mask_read("configs/profile.d/footprint-mask.sh")
    check("shipped profile passes every rule", profile.check_profile(profile_text)["ok"])
    check("a history-on profile fails the check",
          not profile.check_profile(profile_text.replace("HISTSIZE=0", "HISTSIZE=500"))["ok"])
    sandbox_text = _mask_read("Dockerfile.sandbox")
    val = sandbox.validate_sandbox(sandbox_text)
    check("shipped Dockerfile.sandbox validates", val["ok"])
    check("sandbox is alpine:3.20, 7 packages, operator user",
          val["parsed"]["base_image"] == "alpine:3.20"
          and len(val["parsed"]["packages"]) == 7 and val["parsed"]["runs_as_operator"])
    sanitize_sh = _mask_read("bin/sanitize-env")
    check("bin/sanitize-env unsets every purge var on disk",
          all(f"unset {name}" in sanitize_sh for name in sanitizer.PURGE_VARS))
    exec_sh = _mask_read("bin/secure-exec")
    check("bin/secure-exec offers unshare, then podman, then errors",
          "unshare" in exec_sh and "podman" in exec_sh and "exit 1" in exec_sh)
    check("all four Google flows are registered",
          flows.FLOW_IDS == ("gemini_flowx", "google_workspace_studio_flows",
                             "google_flow_filmmaking", "google_flow_engine"))
    plan = flows.flowx_plan()
    check("FlowX recommends the widest level (3 agents, queue wait 0)",
          plan["recommended_agents"] == 3 and plan["widest_level"] == 3
          and plan["queue_wait_ms_at_recommended"] == 0)
    check("FlowX critical path beats sequential", plan["critical_path_ms"] < plan["sequential_ms"])
    trig = flows.workspace_trigger("gmail")
    check("Workspace starter maps Gmail to email_trigger + chat step",
          trig["ok"] and trig["starter"] == "email_trigger" and "send_chat_message" in trig["steps"])
    check("an unknown starter kind is honestly not ok", flows.workspace_trigger("smoke_signal")["ok"] is False)
    board = flows.script_to_storyboard(["a", "b", "c", "d"])
    tl = flows.timeline()
    check("Filmmaking timeline is ordered setup/sanitize/exec/teardown",
          tl["ordered"] and board["frame_count"] == 4)
    route = flows.route_engine("workflow")
    check("Google Flow engine routes workflow as its primary capability",
          route["routable"] and route["primary"])
    check("the merged plan uses ALL four Google flows", flows.merged_plan()["all_flows_used"])
    check("wiping system logs is a HOLD",
          any(g.trigger == "wipe_system_logs" for g in evaluate({"action": "wipe_system_logs"})))
    check("disabling the system audit daemon is a HOLD",
          any(g.trigger == "disable_system_audit" for g in evaluate({"action": "disable_system_audit"})))
    check("running on a system you do not own is a HOLD",
          any(g.trigger == "not_own_system" for g in evaluate({"own_system": False})))
    check("hiding malware is a HOLD",
          any(g.trigger == "hide_malware" for g in evaluate({"purpose": "malware"})))
    check("mounting the host root / docker socket is a HOLD",
          any(g.trigger == "host_root_mount" for g in evaluate({"mount_docker_socket": True})))
    check("a clean own-system session passes the brains", evaluate({"own_system": True}) == [])
    carbon = carbon4.run(mask_session_report())
    check("Carbon 4 runs MAP/MODEL/STRESS/DECIDE in order",
          [p["phase"] for p in carbon["phases"]] == ["MAP", "MODEL", "STRESS", "DECIDE"])
    check("Carbon 4 PROCEEDs a clean masked session",
          carbon["decision"] == "PROCEED" and carbon["stress_ok"])
    held = carbon4.run({**mask_session_report(), "brain_verdict": "HOLD"})
    check("Carbon 4 can never override a brains HOLD", held["decision"] == "HOLD")
    bad = carbon4.run({**mask_session_report(),
                       "profile_text": profile_text.replace("umask 077", "umask 022")})
    check("Carbon 4 HOLDs when a stress control fails",
          bad["decision"] == "HOLD" and not bad["stress_ok"])
    check("Muse seat is registered names-only (MODEL_API_KEY)",
          SEATS.get("muse") == "MODEL_API_KEY" and len(MUSE_MODELS) == 2)
    check("freeai detection returns seat names, never values",
          all(s in SEATS for s in detected()))
    for ev in ("session", "flows", "carbon"):
        box.log(ev, {"ok": True})
    check("blackbox hash chain verifies", box.verify())
    passed = sum(1 for _, ok in results if ok)
    for name, ok in results:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    print(f"CHECKS {passed}/{len(results)} {'PASS' if passed == len(results) else 'FAIL'}")
    print(f"VERDICT: {'PROCEED' if passed == len(results) else 'HOLD'}")
    return 0 if passed == len(results) else 1


def mask_dispatch(argv) -> int:
    from footprintmask import carbon4, flows, sanitizer
    from footprintmask.brains import evaluate
    sub = argv[0] if argv else "checks"
    if sub in ("checks", "report"):
        print("sysadmin-footprint-mask — local SysAdmin mask + footprint sanitizer")
        print("Own-system, local, educational. System logs / audit = HOLD.")
        return mask_checks()
    if sub == "sanitize":
        cleaned = sanitizer.sanitize(dict(MASK_SAMPLE_ENV))
        print(f"purged: {cleaned['purged']}")
        for k, v in cleaned["clean_env"].items():
            print(f"  {k}={v}")
        return 0
    if sub == "flows":
        _print(flows.merged_plan()); return 0
    if sub == "carbon":
        carbon = carbon4.run(mask_session_report())
        _print(carbon)
        return 0 if carbon["decision"] == "PROCEED" else 2
    if sub == "hold-demo":
        for action in ("wipe_system_logs", "disable_system_audit"):
            for g in evaluate({"action": action}):
                print(f"HOLD [{g.trigger}] {g.reason}")
        print("VERDICT: HOLD")
        return 2
    print("mask subcommands: checks | sanitize | flows | carbon | hold-demo")
    return 2


# ------------------------------------------------------------- COUNCIL ----
def council_status() -> dict:
    """ONE unified council surface for the whole project (dedupe, v1.3.0).

    The Carbon 4 / Muse seat CONCEPT appears in every source lab, but each
    lab's engine is different code deciding different subjects, so the
    engines stay inside their labs (see docs/DEDUPE_MAP.md). This command
    is the single place that reports all of them — no per-lab council
    commands at the top level.
    """
    from cve_re.carbon4 import seat_status as cve_seat
    from footprintmask.carbon4 import carbon_status as mask_seat
    from llmx_netlab.brains.carbon4 import THINKING_TIERS as netlab_tiers
    from math_matrix import brains as matrix_brains
    probe = matrix_brains.council_evaluate("council-status-probe", 0.9, False)
    return {
        "surface": "single unified council status (engines remain per-lab, code differs)",
        "seats": {
            "netlab (LLM-x council)": {"tiers": netlab_tiers, "default_budget": 8192,
                                       "mode": "online — hold gates removed (its v1.1.0)"},
            "math-the-matrix": {"tiers": matrix_brains.CARBON4["tiers"],
                                "default_tier": matrix_brains.CARBON4["default_tier"],
                                "probe_final": probe["final"],
                                "muse_can_lift_hold": matrix_brains.MUSE["can_lift_hold"]},
            "cve-re": cve_seat(),
            "sysadmin-footprint-mask": mask_seat(),
        },
        "live_calls_made": False,
    }


def combined_hold_demo() -> int:
    """Top-level --hold-demo: every lab's gates, one demo, exit 2."""
    from cve_re.gates import gate_check
    from footprintmask.brains import evaluate
    from math_matrix import gates as matrix_gates
    d = gate_check("live_exploitation")
    print(f"HOLD [cve-re] {d['action']} — {d['reason']}")
    print(f"HOLD [math-the-matrix] real_deployment — {dict(matrix_gates.HOLD_GATES)['real_deployment']}")
    for g in evaluate({"action": "wipe_system_logs"}):
        print(f"HOLD [sysadmin-footprint-mask:{g.trigger}] {g.reason}")
    print("VERDICT: HOLD — no gate lifted (only Darion can lift one, per action)")
    return 2


# ------------------------------------------------- CHAMBER / HONEYPOT ----
def chamber_dispatch(argv) -> int:
    """Sandbox-API chamber — from credkellar/sandbox-api (8,467 pulls).
    Static triage only: nothing is ever executed, network is always off."""
    from php_re.sandbox import sandbox_demo, triage
    from php_re.samples import get_sample
    sub = argv[0] if argv else "demo"
    if sub == "demo":
        _print(sandbox_demo()); return 0
    if sub == "triage":
        _print(triage(get_sample(argv[1]))); return 0
    print("chamber subcommands: demo | triage <sample-id>")
    return 2


def honeypot_dispatch(argv) -> int:
    """Honeypot — from credkellar/honeyroot-x (325 pulls). Log analysis
    ONLY: no listener exists in this code, bait never grants access."""
    from php_re.honeypot import honeypot_summary
    sub = argv[0] if argv else "report"
    if sub == "report":
        _print(honeypot_summary()); return 0
    print("honeypot subcommands: report")
    return 2
