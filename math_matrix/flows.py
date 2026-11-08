"""Google Flows — ALL 4, full merged plan, plan-only (no live calls).

1. FlowX (Gemini-FlowX)   — 13-subtask graph that plans a lab run.
2. Workspace Studio Flows — workspace/studio plan for organising runs.
3. Flow Filmmaking        — script -> storyboard explainer plan.
                            rendered = False always: a plan is never
                            evidence of a cure, invention or result.
4. DataX Flow             — telemetry/engine plan for run metrics.

Both brains use all four flows: carbon_flow_plan() and muse_flow_plan()
return the same merged plan shape with all_flows_used = True.
"""
from __future__ import annotations

FLOWX_SUBTASKS = [
    "intake-candidate", "map-formula", "verify-formula", "score-candidate",
    "run-battery", "stress-controls", "council-review", "gate-screen",
    "sandbox-promote", "registry-write", "telemetry-log", "explainer-plan",
    "report-draft",
]

FLOWS = {
    "FlowX": {"kind": "graph", "subtasks": len(FLOWX_SUBTASKS), "mode": "plan-only"},
    "Workspace Studio": {"kind": "studio-plan", "mode": "plan-only"},
    "Filmmaking": {"kind": "video-plan", "mode": "plan-only", "rendered": False},
    "DataX": {"kind": "telemetry-engine-plan", "mode": "plan-only"},
}


def merged_plan(subject: str) -> dict:
    return {
        "subject": subject,
        "flowx": {"subtasks": FLOWX_SUBTASKS, "count": len(FLOWX_SUBTASKS)},
        "studio": {"plan": ["organise-run", "attach-formulas", "file-results"],
                   "mode": "plan-only"},
        "filmmaking": {"script": f"Explainer outline for {subject}",
                       "storyboard": ["hook", "formula", "tests", "verdict", "hold-note"],
                       "rendered": False},
        "datax": {"metrics": ["formulas_passed", "battery_passed", "candidates_promoted"],
                  "mode": "plan-only"},
        "all_flows_used": True,
        "live_calls_made": False,
    }


def carbon_flow_plan(subject: str) -> dict:
    plan = merged_plan(subject)
    plan["brain"] = "gemini-carbon-4-extended-thinking"
    return plan


def muse_flow_plan(subject: str) -> dict:
    plan = merged_plan(subject)
    plan["brain"] = "muse-ai-advisor"
    return plan


def all_flows_used() -> bool:
    plan = merged_plan("probe")
    return (
        set(FLOWS) == {"FlowX", "Workspace Studio", "Filmmaking", "DataX"}
        and all(v["mode"] == "plan-only" for v in FLOWS.values())
        and plan["all_flows_used"] is True
        and plan["flowx"]["count"] >= 13
        and plan["filmmaking"]["rendered"] is False
        and carbon_flow_plan("probe")["all_flows_used"] is True
        and muse_flow_plan("probe")["all_flows_used"] is True
    )
