"""Google Flows -- ALL FOUR flows, plan-only.

1. Gemini-FlowX: CVE triage decomposed into a subtask graph (>=13).
2. Google Workspace Studio Flows: report-delivery plan only; nothing sent.
3. Google Flow Filmmaking: a triage report as storyboard + timeline,
   mode="offline-plan", rendered=False.
4. DataX Flow engine: engine_id="google_flow", name google_flow.

Generating a real video is a HOLD gate (``live_video_generation``) --
the lab only ever plans.
"""
from __future__ import annotations

FLOWX = "Gemini-FlowX"
WORKSPACE = "Google Workspace Studio Flows"
FILMMAKING = "Google Flow Filmmaking"
ENGINE_FLOW = "Google Flow engine"

_SUBTASKS = [
    {"id": "intake", "name": "Catalog intake (records as data only)", "depends_on": [], "agents": 1},
    {"id": "dedupe", "name": "CVE ID dedupe / uniqueness check", "depends_on": ["intake"], "agents": 1},
    {"id": "classify", "name": "Classify by type (RCE / memory / chain)", "depends_on": ["dedupe"], "agents": 2},
    {"id": "vendor_group", "name": "Group by vendor / product", "depends_on": ["classify"], "agents": 1},
    {"id": "kev_check", "name": "KEV / exploited flag check (offline data)", "depends_on": ["classify"], "agents": 1},
    {"id": "priority", "name": "Deterministic priority scoring", "depends_on": ["kev_check", "vendor_group"], "agents": 2},
    {"id": "remediation", "name": "Remediation plan per CVE", "depends_on": ["priority"], "agents": 2},
    {"id": "rotation_check", "name": "Session / MachineKey rotation closure check", "depends_on": ["remediation"], "agents": 1},
    {"id": "gate_check", "name": "HOLD gate check (anything live is held)", "depends_on": ["remediation"], "agents": 1},
    {"id": "carbon4_decision", "name": "Carbon 4 MAP-MODEL-STRESS-DECIDE", "depends_on": ["priority", "rotation_check", "gate_check"], "agents": 1},
    {"id": "video_storyboard", "name": "Flow video storyboard (plan only)", "depends_on": ["remediation"], "agents": 1},
    {"id": "report_plan", "name": "Workspace Studio delivery plan (plan only)", "depends_on": ["carbon4_decision"], "agents": 1},
    {"id": "final_verdict", "name": "Final triage verdict (strictest wins)", "depends_on": ["carbon4_decision", "video_storyboard", "report_plan"], "agents": 1},
]


def _levels(subtasks):
    level = {}
    def lev(t):
        if t["id"] not in level:
            level[t["id"]] = 0 if not t["depends_on"] else 1 + max(
                lev(next(x for x in subtasks if x["id"] == d)) for d in t["depends_on"])
        return level[t["id"]]
    for t in subtasks:
        t["level"] = lev(t)
    return subtasks


def flowx_plan(report: dict = None) -> dict:
    subtasks = _levels([dict(t) for t in _SUBTASKS])
    by_level = {}
    for t in subtasks:
        by_level[t["level"]] = by_level.get(t["level"], 0) + 1
    widest = max(by_level, key=lambda k: by_level[k])
    return {"flow": FLOWX, "subject": (report or {}).get("cve_id", "lab-run"),
            "subtasks": subtasks, "subtask_count": len(subtasks),
            "levels": sorted(by_level), "widest_level": widest,
            "widest_level_size": by_level[widest],
            "recommended_agents": sum(t["agents"] for t in subtasks),
            "queue_wait": 0}


def workspace_studio_plan(report: dict = None) -> dict:
    return {"flow": WORKSPACE,
            "starters": {"gmail": "email_trigger", "google_forms": "form_trigger",
                         "webhook": "webhook_listener"},
            "steps": ["send_chat_message", "card_layout"],
            "delivers": f"CVE-RE report for {(report or {}).get('cve_id', 'lab-run')}",
            "mode": "plan-only", "sent": False,
            "note": "delivery plan only -- nothing is sent by this lab"}


def script_to_storyboard(report: dict = None) -> list:
    r = report or {}
    label = r.get("cve_id", "CVE")
    vuln = r.get("vuln_type", "vulnerability")
    return [
        {"shot": 1, "track": "setup", "title": f"Meet {label}",
         "veo_prompt": f"Cinematic wide shot of a defensive triage lab, a CVE card labelled {label} on a glass screen, blue light, no people"},
        {"shot": 2, "track": "analyze", "title": "Rank the exposure",
         "veo_prompt": f"Macro shot of a risk dial rising for a {vuln} record, amber highlight, no real systems shown"},
        {"shot": 3, "track": "verdict", "title": "Carbon 4 decides",
         "veo_prompt": "Two abstract AI orbs confer over a HOLD stamp, the stricter verdict glowing red"},
        {"shot": 4, "track": "teardown", "title": "Patch and rotate",
         "veo_prompt": "Close-up of a patch checklist completed and session tokens being rotated, green checkmark, calm ending frame"},
    ]


def build_timeline(shots: list = None) -> dict:
    shots = shots if shots is not None else script_to_storyboard()
    tracks = {n: [s for s in shots if s["track"] == n]
              for n in ("setup", "analyze", "verdict", "teardown")}
    return {"tracks": tracks, "track_names": list(tracks),
            "mode": "offline-plan", "rendered": False}


def filmmaking_plan(report: dict = None) -> dict:
    shots = script_to_storyboard(report)
    return {"flow": FILMMAKING, "storyboard": shots,
            "timeline": build_timeline(shots),
            "mode": "offline-plan", "rendered": False}


def flow_engine() -> dict:
    return {"flow": ENGINE_FLOW, "engine_id": "google_flow",
            "name": "google_flow", "primary_capability": "workflow",
            "mode": "offline-plan"}


def merged_plan(report: dict = None) -> dict:
    fx, ws, film, eng = (flowx_plan(report), workspace_studio_plan(report),
                         filmmaking_plan(report), flow_engine())
    parts = {"flowx": fx, "workspace_studio": ws, "filmmaking": film, "engine": eng}
    return {"flows": [FLOWX, WORKSPACE, FILMMAKING, ENGINE_FLOW],
            "plans": parts, "subtask_count": fx["subtask_count"],
            "all_flows_used": all((fx["subtask_count"] >= 13, not ws["sent"],
                                    film["rendered"] is False,
                                    eng["engine_id"] == "google_flow")),
            "queue_wait": fx["queue_wait"]}


def brain_flow_plan(brain: str = "carbon4", report: dict = None) -> dict:
    if brain != "carbon4":
        raise ValueError(f"unknown brain: {brain}")
    film = filmmaking_plan(report)
    return {"brain": brain, "role": "decider", "flowx": flowx_plan(report),
            "video_plan": film, "routed_through": [FLOWX, FILMMAKING],
            "rendered": film["rendered"],
            "verdict_source": "Gemini Carbon 4 Extended Thinking"}


def carbon_flow_plan(report: dict = None) -> dict:
    return brain_flow_plan("carbon4", report)
