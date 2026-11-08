import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from math_matrix import brains, catalog, flows, gates
from math_matrix.deploy import deploy_successful
from math_matrix.labs import generate_candidates, synthetic_signal_test
from math_matrix.test_runner import run_thousands


def test_all_formulas_verify():
    passed, total, failed = catalog.verify_all()
    assert passed == total and not failed


def test_domains_cover_user_list():
    domains = {f.domain for f in catalog.FORMULAS}
    for d in ["algebra", "biology", "science", "data-science", "robotics",
              "transportation", "levitation", "medicine-math", "spacetime",
              "computers", "llm", "ml", "nnl", "ai-ladder",
              "atomic", "natural-resources", "natural-medicine", "nutrition",
              "supercomputing", "quantum-computing"]:
        assert d in domains, d


def test_video_seed_formulas_present():
    for fid in ["pemdas", "kruskal", "schwarzschild"]:
        assert fid in catalog.BY_ID


def test_candidates():
    cands = generate_candidates()
    assert len(cands) >= 46
    assert all(c.basis in catalog.BY_ID for c in cands)
    kinds = {c.kind for c in cands}
    for k in ["medical-hypothesis", "tech-invention", "biology", "science",
              "data-science", "robotics", "transportation", "levitation",
              "computers", "llm", "slm", "ml", "nnl", "ani", "agi", "asi",
              "atomic", "natural-resources", "natural-medicine", "nutrition",
              "supercomputing", "quantum-computing"]:
        assert k in kinds, k


def test_synthetic_signal():
    assert synthetic_signal_test()


def test_thousands_run_clean():
    run = run_thousands(2048)
    assert run.total >= 2048 and run.ok


def test_gates():
    assert len(gates.HOLD_GATES) == 12
    for name in ["clinical_use", "real_deployment", "live_hardware", "human_testing"]:
        assert gates.check(name) == "HOLD"
    assert gates.check("run_local_tests") == "PROCEED"


def test_council_strictest_wins():
    assert brains.stress_controls()
    assert brains.CARBON4["can_lift_hold"] is False
    assert brains.CARBON4["default_tier"] == 32768
    assert brains.CARBON4["stages"] == ["MAP", "MODEL", "STRESS", "DECIDE"]
    assert brains.MUSE["authority"] == "none"
    assert brains.MUSE["decision_authority"] == "none"


def test_carbon4_full_seat_and_muse_advice():
    out = brains.council_evaluate("demo", 0.9, False)
    assert out["final"] == "PROCEED"
    assert out["carbon4"]["live_call_made"] is False
    assert len(out["muse_advice"]) == 4
    gated = brains.council_evaluate("clinical thing", 0.99, True)
    assert gated["final"] == "HOLD"  # friendly score + advice never override a gate


def test_flows():
    assert flows.all_flows_used()
    plan = flows.merged_plan("demo")
    assert plan["flowx"]["count"] >= 13
    assert plan["filmmaking"]["rendered"] is False
    assert flows.carbon_flow_plan("demo")["all_flows_used"]
    assert flows.muse_flow_plan("demo")["all_flows_used"]


def test_deploy_is_sandbox_only(tmp_path):
    payload = deploy_successful(generate_candidates(), tmp_path / "reg.json")
    assert payload["registry"] == "sandbox-only"
    assert payload["real_world_deployment"] == "HOLD"
    assert (tmp_path / "reg.json").exists()
