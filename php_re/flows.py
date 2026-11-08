"""Google Flows -- ALL FOUR flows, plan-only, applied to BOTH brains.

1. Gemini-FlowX: a PHP analysis decomposed into a subtask graph.
2. Google Workspace Studio Flows: report-delivery starters/steps -- a
   PLAN only; nothing is ever sent.
3. Google Flow Filmmaking: a sample report turned into a storyboard +
   timeline plan (Veo-style prompts). mode="offline-plan", rendered=False.
4. Google Flow engine (from DataX): engine_id="google_flow", primary
   capability "workflow".

Both brains are routed through the flows: Carbon 4 (the decider) and
Muse (the advisor) each get a FlowX plan and a Flow video plan for the
same report. Generating a real video is a HOLD gate
(``live_video_generation``) -- the lab only ever plans.
"""
from __future__ import annotations

FLOWX = "Gemini-FlowX"
WORKSPACE = "Google Workspace Studio Flows"
FILMMAKING = "Google Flow Filmmaking"
ENGINE_FLOW = "Google Flow engine"

_SUBTASKS = [
    {"id": "intake", "name": "Sample intake (data only, never executed)", "depends_on": [], "agents": 1},
    {"id": "fingerprint", "name": "Code fingerprint (sources/sinks/sanitizers)", "depends_on": ["intake"], "agents": 2},
    {"id": "encoded_check", "name": "Encoded-file check (ionCube/Zend markers)", "depends_on": ["intake"], "agents": 1},
    {"id": "taint", "name": "Source-to-sink taint mapping", "depends_on": ["fingerprint"], "agents": 3},
    {"id": "obfuscation", "name": "Obfuscation layer counting", "depends_on": ["fingerprint"], "agents": 2},
    {"id": "framework", "name": "Framework fingerprint", "depends_on": ["fingerprint"], "agents": 1},
    {"id": "sandbox_triage", "name": "Sandbox-API static triage", "depends_on": ["taint", "obfuscation"], "agents": 2},
    {"id": "honeypot_correlation", "name": "Honeypot log correlation", "depends_on": ["taint"], "agents": 2},
    {"id": "hardening", "name": "Hardening fix plan", "depends_on": ["taint", "sandbox_triage"], "agents": 2},
    {"id": "video_storyboard", "name": "Flow video storyboard (plan only)", "depends_on": ["hardening"], "agents": 1},
    {"id": "carbon4_decision", "name": "Carbon 4 MAP-MODEL-STRESS-DECIDE", "depends_on": ["hardening", "honeypot_correlation"], "agents": 1},
    {"id": "muse_advice", "name": "Muse advisory pass (authority: none)", "depends_on": ["hardening", "honeypot_correlation"], "agents": 1},
    {"id": "council_verdict", "name": "Council verdict (strictest wins)", "depends_on": ["carbon4_decision", "muse_advice", "video_storyboard"], "agents": 1},
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
    widest_level = max(by_level, key=lambda k: by_level[k])
    return {
        "flow": FLOWX,
        "subject": (report or {}).get("id", "lab-run"),
        "subtasks": subtasks, "subtask_count": len(subtasks),
        "levels": sorted(by_level), "widest_level": widest_level,
        "widest_level_size": by_level[widest_level],
        "recommended_agents": sum(t["agents"] for t in subtasks),
        "agents_at_widest_level": sum(t["agents"] for t in subtasks if t["level"] == widest_level),
        "queue_wait": 0,
    }


def workspace_studio_plan(report: dict = None) -> dict:
    return {
        "flow": WORKSPACE,
        "starters": {"gmail": "email_trigger", "google_forms": "form_trigger",
                     "webhook": "webhook_listener"},
        "steps": ["send_chat_message", "card_layout"],
        "delivers": f"PHP-Vuln-RE report for {(report or {}).get('id', 'lab-run')}",
        "mode": "plan-only", "sent": False,
        "note": "delivery plan only -- nothing is sent by this lab",
    }


def script_to_storyboard(report: dict = None) -> list:
    r = report or {}
    label = r.get("id", "sample")
    vuln = r.get("vuln_type", "php_vulnerability")
    risk = r.get("risk_score", "?")
    shots = [
        {"shot": 1, "track": "setup", "title": f"Meet {label}",
         "veo_prompt": f"Cinematic wide shot of a code-analysis lab, a PHP file labelled {label} on a glass screen, defensive blue light, no people"},
        {"shot": 2, "track": "analyze", "title": "Trace the taint path",
         "veo_prompt": f"Macro shot following a glowing data thread from a $_GET source to a dangerous sink, {vuln} highlighted in amber"},
        {"shot": 3, "track": "verdict", "title": "The council decides",
         "veo_prompt": f"Two abstract AI orbs confer over a risk dial reading {risk} out of 100, the stricter orb's HOLD stamp glowing red"},
        {"shot": 4, "track": "teardown", "title": "Apply the hardening fix",
         "veo_prompt": "Close-up of the vulnerable line being replaced by a prepared-statement fix, green checkmark bloom, calm ending frame"},
    ]
    return shots


def build_timeline(shots: list = None) -> dict:
    shots = shots if shots is not None else script_to_storyboard()
    tracks = {name: [s for s in shots if s["track"] == name]
              for name in ("setup", "analyze", "verdict", "teardown")}
    return {"tracks": tracks, "track_names": list(tracks),
            "mode": "offline-plan", "rendered": False}


def filmmaking_plan(report: dict = None) -> dict:
    shots = script_to_storyboard(report)
    timeline = build_timeline(shots)
    return {"flow": FILMMAKING, "storyboard": shots, "timeline": timeline,
            "mode": "offline-plan", "rendered": False}


def flow_engine() -> dict:
    return {"flow": ENGINE_FLOW, "engine_id": "google_flow",
            "primary_capability": "workflow", "mode": "offline-plan"}


def merged_plan(report: dict = None) -> dict:
    fx = flowx_plan(report)
    ws = workspace_studio_plan(report)
    film = filmmaking_plan(report)
    eng = flow_engine()
    parts = {"flowx": fx, "workspace_studio": ws, "filmmaking": film, "engine": eng}
    return {
        "flows": [FLOWX, WORKSPACE, FILMMAKING, ENGINE_FLOW],
        "plans": parts,
        "subtask_count": fx["subtask_count"],
        "all_flows_used": all((fx["subtask_count"] >= 10, not ws["sent"],
                                film["rendered"] is False,
                                eng["engine_id"] == "google_flow")),
        "queue_wait": fx["queue_wait"],
    }


def brain_flow_plan(brain: str, report: dict = None) -> dict:
    """Route one brain's verdict through FlowX + the Flow video plan."""
    if brain not in ("carbon4", "muse"):
        raise ValueError(f"unknown brain: {brain}")
    film = filmmaking_plan(report)
    return {
        "brain": brain,
        "role": "decider" if brain == "carbon4" else "advisor",
        "flowx": flowx_plan(report),
        "video_plan": film,
        "routed_through": [FLOWX, FILMMAKING],
        "rendered": film["rendered"],
        "verdict_source": ("Gemini Carbon 4 Extended Thinking" if brain == "carbon4"
                           else "Muse (advisor, authority none)"),
    }


def carbon_flow_plan(report: dict = None) -> dict:
    return brain_flow_plan("carbon4", report)


def muse_flow_plan(report: dict = None) -> dict:
    return brain_flow_plan("muse", report)
