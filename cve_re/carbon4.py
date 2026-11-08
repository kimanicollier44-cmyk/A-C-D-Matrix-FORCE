"""Gemini Carbon 4 Extended Thinking -- DECIDER seat (offline).

House pattern: MAP -> MODEL -> STRESS -> DECIDE. Engine gemini-2.5-pro,
model id google/gemini-carbon-4-extended-pro-thinking, thinking tiers
2048 / 8192 / 32768 with the extended tier as default.

Offline structure is authoritative: no live API call is made by this
lab. The Gemini key is checked by NAME / presence only. Carbon 4 can
only TIGHTEN a verdict (HOLD > critical > high > medium > low); it can
never loosen or override a HOLD gate.
"""
from __future__ import annotations
import os

from .analyzer import priority_level, priority_score, remediation_plan
from .catalog import get_record
from .gates import HOLD_GATES

DECIDER_NAME = "Gemini Carbon 4 Extended Thinking"
ENGINE = "gemini-2.5-pro"
MODEL_ID = "google/gemini-carbon-4-extended-pro-thinking"
KEY_ENV_NAME = "GEMINI_API_KEY"
THINKING_TIERS = (2048, 8192, 32768)
DEFAULT_TIER = 32768
PHASES = ("MAP", "MODEL", "STRESS", "DECIDE")
MODE = "offline-authoritative"

_LEVELS = ("low", "medium", "high", "critical")


def key_present() -> bool:
    """Presence only -- the key value is never read into any output."""
    return KEY_ENV_NAME in os.environ


def seat_status() -> dict:
    return {
        "decider": DECIDER_NAME, "engine": ENGINE, "model_id": MODEL_ID,
        "thinking_tiers": list(THINKING_TIERS), "default_tier": DEFAULT_TIER,
        "phases": list(PHASES), "mode": MODE,
        "key_env_name": KEY_ENV_NAME, "key_present": key_present(),
        "can_override_hold": False,
        "note": "names-only seat -- no live API call in this lab",
    }


def _max_level(a: str, b: str) -> str:
    return a if _LEVELS.index(a) >= _LEVELS.index(b) else b


def carbon_decide(record: dict = None, action: str = "triage",
                  base_verdict: str = "ALLOW", patched=False,
                  sessions_rotated=False, keys_rotated=False) -> dict:
    """Run MAP -> MODEL -> STRESS -> DECIDE over one CVE record."""
    record = dict(record or {})
    # MAP -- fingerprint the record statically.
    mapped = {k: record.get(k) for k in
              ("cve_id", "vendor", "product", "vuln_type", "cvss", "kev")}
    # MODEL -- deterministic level from the analyzer priority score.
    plan = remediation_plan(record, patched=patched,
                            sessions_rotated=sessions_rotated,
                            keys_rotated=keys_rotated) if record else None
    closed = bool(plan and plan["status"] == "closed")
    score = priority_score(record) if record else 50.0
    if closed:
        score = min(score, 30.0)
    elif patched and plan and plan["status"] == "patched_not_closed":
        score = max(score, 70.0)  # patched but tokens/keys still live
    model_level = priority_level(score)
    # STRESS -- negative-control conditions, applied to the subject.
    stress = {
        "closed_record": closed,
        "patched_not_closed": bool(plan and plan["status"] == "patched_not_closed"),
        "held_action": action in HOLD_GATES,
        "base_verdict_hold": base_verdict == "HOLD",
    }
    # DECIDE -- strictest, tighten-only.
    level = model_level
    tightened = False
    if stress["patched_not_closed"]:
        raised = _max_level(level, "high")
        tightened = raised != level
        level = raised
    verdict = "ALLOW"
    if stress["held_action"] or stress["base_verdict_hold"]:
        verdict = "HOLD"
        tightened = True
    return {
        "cve_id": record.get("cve_id"), "action": action,
        "verdict": verdict, "level": level, "model_level": model_level,
        "priority_score": score, "closure_status": plan["status"] if plan else None,
        "decider": DECIDER_NAME, "engine": ENGINE, "model_id": MODEL_ID,
        "tier": DEFAULT_TIER, "thinking_tiers": list(THINKING_TIERS),
        "phases": list(PHASES), "mode": MODE,
        "tightened": tightened, "can_override_hold": False,
        "mapped": mapped, "stress": stress, "key_present": key_present(),
        "note": "names-only seat -- no live API call in this lab",
    }


def _synthetic(cve_id=None, **overrides):
    base = dict(get_record(cve_id)) if cve_id else {
        "cve_id": "SYNTH-0000", "name": "", "vendor": "Synthetic",
        "product": "Synthetic", "vuln_type": "memory_disclosure",
        "cvss": 3.0, "kev": False, "exploited": False,
        "unauthenticated": True, "year": 2026, "vuln_class": "CWE-200",
        "remediation": "patch", "requires_session_rotation": False,
        "requires_key_rotation": False}
    base.update(overrides)
    return base


def stress_controls() -> list:
    """Four negative controls that must NOT escalate."""
    bleed = carbon_decide(_synthetic("CVE-2025-5777"), patched=True,
                          sessions_rotated=True)
    info_only = carbon_decide(_synthetic("CVE-2025-61884", cvss=3.1, kev=False))
    low_non_kev = carbon_decide(_synthetic(cvss=2.5, kev=False))
    toolshell = carbon_decide(_synthetic("CVE-2025-53770"), patched=True,
                              sessions_rotated=True, keys_rotated=True)
    return [
        {"name": "patched_rotated_citrixbleed_not_escalated",
         "passed": bleed["level"] in ("low", "medium") and bleed["verdict"] != "HOLD",
         "detail": f"CitrixBleed patched+rotated decided at level {bleed['level']}"},
        {"name": "low_cvss_info_only_not_escalated",
         "passed": info_only["level"] in ("low", "medium"),
         "detail": f"info-only record decided at level {info_only['level']}"},
        {"name": "non_kev_below_cvss4_not_escalated",
         "passed": low_non_kev["level"] == "low",
         "detail": f"kev=False cvss<4 record decided at level {low_non_kev['level']}"},
        {"name": "closed_rotated_toolshell_not_escalated",
         "passed": toolshell["level"] in ("low", "medium") and toolshell["closure_status"] == "closed",
         "detail": f"ToolShell patched+rotated decided at level {toolshell['level']}"},
    ]
