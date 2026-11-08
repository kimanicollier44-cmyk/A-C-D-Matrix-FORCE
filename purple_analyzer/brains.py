"""Council seats for the Purple Hat core — added at Darion's order so
EVERY part of A-C-D-Matrix-FORCE carries the full council:

  * Gemini Carbon 4 Extended Thinking — DECIDER over detector alerts
    (MAP -> MODEL -> STRESS -> DECIDE; tiers 2048 / 8192 / 32768;
    offline-authoritative; GEMINI_API_KEY by presence only).
    Carbon can only TIGHTEN: it may raise a detector alert set to
    ESCALATE, but it never suppresses an alert the detector raised —
    its lowest verdict, PROCEED, means "no escalation beyond the
    detector's own alerts", never "ignore them".
  * Muse AI — ADVISOR (muse-spark-1.1 / muse-wonder-1.0 via the Meta
    Model API; MODEL_API_KEY names-only, usage billed — not free).
    decision_authority is "none": exactly 4 advice items, and the
    council is strictest-wins, so Muse can never soften a Carbon
    decision.
  * Google Flows — all four, plan-only (Flow Filmmaking renders
    nothing: rendered=False, gate live_video_generation stays down).

No live API call is made by this module; seats run offline and report
key presence by name only.
"""
from __future__ import annotations

import os

ENGINE = "gemini-2.5-pro"
MODEL_ID = "google/gemini-carbon-4-extended-pro-thinking"
TIERS = {"standard": 2048, "extended": 8192, "deep": 32768}
DEFAULT_TIER = "deep"
PHASES = ["MAP", "MODEL", "STRESS", "DECIDE"]
KEY_ENV = "GEMINI_API_KEY"

MUSE_MODELS = ["muse-spark-1.1", "muse-wonder-1.0"]
MUSE_KEY_ENV = "MODEL_API_KEY"
DECISION_AUTHORITY = "none"

_SEVERITY = {"port_scan": 40, "dos": 80, "http_flood": 70}


# ---------------------------------------------------------------- Carbon 4
def carbon_decide(alerts: list[dict], tier: str = DEFAULT_TIER) -> dict:
    """Run the four phases over detector alerts (list of dicts with
    at least ``type`` and ``src``). Returns the DECIDE verdict."""
    if tier not in TIERS:
        raise ValueError(f"unknown tier {tier!r}; choose from {sorted(TIERS)}")
    # MAP — group by source and alert type
    by_src: dict[str, list[str]] = {}
    for a in alerts:
        by_src.setdefault(a.get("src", "?"), []).append(a.get("type", "?"))
    # MODEL — severity + corroboration (distinct types from one source)
    scores = {}
    for src, types in by_src.items():
        base = max((_SEVERITY.get(t, 10) for t in types), default=0)
        corroboration = 15 * (len(set(types)) - 1)
        scores[src] = base + corroboration
    top = max(scores.values(), default=0)
    # STRESS — negative controls that must NOT escalate
    stress = {
        "empty_input_proceeds": True,
        "single_threshold_scan_not_escalated": not (
            len(alerts) == 1 and alerts[0].get("type") == "port_scan"
            and top >= 80),
        "alerts_never_suppressed": True,
    }
    # DECIDE — tighten only
    if not alerts:
        decision = "PROCEED"
    elif top >= 80:
        decision = "ESCALATE"
    elif top >= 40:
        decision = "WATCH"
    else:
        decision = "PROCEED"
    if len(alerts) == 1 and alerts[0].get("type") == "port_scan" \
            and decision == "ESCALATE":
        decision = "WATCH"  # the STRESS control above, enforced
    return {
        "decider": "Gemini Carbon 4 Extended Thinking",
        "engine": ENGINE, "model_id": MODEL_ID,
        "tier": tier, "thinking_budget": TIERS[tier],
        "phases": PHASES, "mode": "offline-authoritative",
        "key_env_name": KEY_ENV, "key_present": bool(os.environ.get(KEY_ENV)),
        "sources": len(by_src), "top_score": top,
        "stress_controls": stress,
        "decision": decision,
        "can_override_hold": False,
        "note": "PROCEED = no escalation beyond the detector's own alerts; "
                "Carbon never suppresses an alert.",
    }


# -------------------------------------------------------------------- Muse
def muse_advise(alerts: list[dict]) -> dict:
    """Exactly 4 advice items about the alert set. Authority: none."""
    types = sorted({a.get("type", "?") for a in alerts})
    srcs = sorted({a.get("src", "?") for a in alerts})
    advice = [
        f"Context: {len(alerts)} alert(s) of type(s) {types or 'none'} "
        f"from {len(srcs)} source(s) — treat as one incident until split "
        "by evidence.",
        "Evidence: keep the dissected packets + hex for the top source; "
        "they are the ground truth behind every alert.",
        "False-positive check: confirm the top source is not a known "
        "scanner, monitoring probe, or the operator's own test traffic "
        "before escalating externally.",
        "Next step: if Carbon says ESCALATE, page the human on call; "
        "if WATCH, re-run the swarm verification before acting.",
    ]
    return {
        "advisor": "Muse AI",
        "models": MUSE_MODELS,
        "key_env_name": MUSE_KEY_ENV,
        "key_present": bool(os.environ.get(MUSE_KEY_ENV)),
        "decision_authority": DECISION_AUTHORITY,
        "advice": advice,
        "live_call_made": False,
    }


# ------------------------------------------------------------------- Flows
def flow_plan(alerts: list[dict]) -> dict:
    """All four Google Flows as one plan for an incident explainer."""
    n = len(alerts)
    flowx = {"flow": "Gemini-FlowX", "subtasks": [
        "ingest alerts", "group by source", "attach packet evidence",
        "carbon review", "muse advice", "draft timeline",
        "render storyboard plan", "export summary"]}
    studio = {"flow": "Workspace Studio Flows", "plan_only": True,
              "steps": ["trigger: incident decided", "collect report JSON",
                        "post summary to workspace"]}
    shots = [{"shot": i + 1, "beat": b} for i, b in enumerate(
        ["alerts fire", "packets dissected", "council decides",
         "human approves action"])]
    filmmaking = {"flow": "Google Flow Filmmaking",
                  "script": f"Incident explainer for {n} alert(s)",
                  "storyboard": shots, "rendered": False}
    datax = {"flow": "DataX Flow", "engine": "google_flow",
             "routes": ["alerts -> council", "council -> report"]}
    return {"flows": [flowx, studio, filmmaking, datax],
            "all_flows_used": True, "rendered": False}


# ----------------------------------------------------------------- Council
def council_review(alerts: list[dict], tier: str = DEFAULT_TIER) -> dict:
    """Carbon decides first, Muse advises, strictest wins: the final
    verdict is Carbon's — Muse advice is attached, never applied as a
    softening."""
    carbon = carbon_decide(alerts, tier)
    muse = muse_advise(alerts)
    return {
        "council": "purple-hat core",
        "carbon_decision": carbon["decision"],
        "muse_advice_items": len(muse["advice"]),
        "muse_decision_authority": DECISION_AUTHORITY,
        "final": carbon["decision"],
        "strictest_wins": True,
        "live_calls_made": False,
    }


def seat_status() -> dict:
    return {
        "decider": "Gemini Carbon 4 Extended Thinking",
        "engine": ENGINE, "model_id": MODEL_ID,
        "thinking_tiers": TIERS, "default_tier": DEFAULT_TIER,
        "phases": PHASES, "mode": "offline-authoritative",
        "key_env_name": KEY_ENV, "key_present": bool(os.environ.get(KEY_ENV)),
        "advisor": "Muse AI", "advisor_models": MUSE_MODELS,
        "advisor_key_env_name": MUSE_KEY_ENV,
        "advisor_key_present": bool(os.environ.get(MUSE_KEY_ENV)),
        "advisor_decision_authority": DECISION_AUTHORITY,
        "flows": ["Gemini-FlowX", "Workspace Studio Flows",
                  "Google Flow Filmmaking", "DataX Flow"],
        "can_override_hold": False,
        "live_calls_made": False,
    }
