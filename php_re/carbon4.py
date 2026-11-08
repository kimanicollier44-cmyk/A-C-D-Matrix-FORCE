"""Gemini Carbon 4 Extended Thinking -- full DECIDER seat (offline).

House pattern: MAP -> MODEL -> STRESS -> DECIDE. Engine gemini-2.5-pro,
model id google/gemini-carbon-4-extended-pro-thinking, thinking tiers
2048 / 8192 / 32768 with the extended tier as default.

Offline structure is authoritative: no live API call is made by this lab.
GEMINI_API_KEY is referenced by NAME only -- presence is checked with
``in os.environ`` and the value is never read into any output. Carbon 4
can only tighten a verdict (raise a level, or HOLD); it can never loosen
or override a brains HOLD.
"""
from __future__ import annotations
import os

from .analyzer import analyze
from .brains import HOLD_GATES

DECIDER_NAME = "Gemini Carbon 4 Extended Thinking"
ENGINE = "gemini-2.5-pro"
MODEL_ID = "google/gemini-carbon-4-extended-pro-thinking"
KEY_ENV_NAME = "GEMINI_API_KEY"
THINKING_TIERS = (2048, 8192, 32768)
DEFAULT_TIER = 32768
PHASES = ("MAP", "MODEL", "STRESS", "DECIDE")
MODE = "offline-authoritative"

_LEVELS = ("low", "medium", "high", "critical")
_DANGEROUS_SINKS = ("eval", "create_function", "unserialize", "shell_exec", "system", "exec")

_SANITIZED_CODE = (
    "<?php echo htmlspecialchars($_GET['q'], ENT_QUOTES, 'UTF-8');"
    " $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');"
    " $stmt->execute([intval($_GET['id'])]);"
)
_CRITICAL_CODE = (
    "<?php $d = $_COOKIE['prefs']; $o = unserialize($d); eval($_POST['expr']);"
)
_BENIGN_CODE = "<?php echo 'hello, static world';"


def key_present() -> bool:
    """Presence only -- the key value is never read."""
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


def _level_for_risk(risk: int) -> str:
    if risk >= 90:
        return "critical"
    if risk >= 70:
        return "high"
    if risk >= 40:
        return "medium"
    return "low"


def _max_level(a: str, b: str) -> str:
    return a if _LEVELS.index(a) >= _LEVELS.index(b) else b


def carbon_decide(action: str = "static_analysis", code: str = None,
                  base_verdict: str = "ALLOW", base_risk: int = 50) -> dict:
    """Run MAP -> MODEL -> STRESS -> DECIDE over one subject.

    Tighten-only: a base HOLD stays HOLD, a held action stays HOLD, and a
    critical dangerous-sink subject is raised, never lowered. The STRESS
    phase blocks false escalation: a properly sanitized sample (whose
    analyzer risk is already lowered by its sanitizers) is not escalated.
    """
    # MAP -- fingerprint the subject statically.
    report = analyze(code, base_risk=base_risk) if code else None
    mapped = {
        "sources": report["sources"] if report else [],
        "sinks": report["sinks"] if report else [],
        "sanitizers": report["sanitizers"] if report else [],
    }
    # MODEL -- deterministic level from the analyzer risk score.
    risk = report["risk_score"] if report else base_risk
    model_level = _level_for_risk(risk)
    # STRESS -- negative controls, applied to the subject.
    sanitized = bool(mapped["sanitizers"]) and not any(
        s in mapped["sinks"] for s in _DANGEROUS_SINKS)
    dangerous = any(s in mapped["sinks"] for s in _DANGEROUS_SINKS) and bool(mapped["sources"])
    stress = {
        "sanitized_sample_not_escalated": sanitized,
        "dangerous_sink_present": dangerous,
        "held_action": action in HOLD_GATES,
        "base_verdict_hold": base_verdict == "HOLD",
    }
    # DECIDE -- strictest, tighten-only.
    level = model_level
    tightened = False
    if dangerous and not sanitized:
        raised = _max_level(level, "high")
        tightened = raised != level
        level = raised
    verdict = "ALLOW"
    if stress["held_action"] or stress["base_verdict_hold"]:
        verdict = "HOLD"
        tightened = True
    elif dangerous and level in ("high", "critical") and action != "static_analysis":
        verdict = "HOLD"
        tightened = True
    return {
        "action": action, "verdict": verdict, "level": level,
        "model_level": model_level, "risk_score": risk,
        "decider": DECIDER_NAME, "engine": ENGINE, "model_id": MODEL_ID,
        "tier": DEFAULT_TIER, "thinking_tiers": list(THINKING_TIERS),
        "phases": list(PHASES), "mode": MODE,
        "tightened": tightened, "can_override_hold": False,
        "mapped": mapped, "stress": stress,
        "key_present": key_present(),
        "note": "names-only seat -- no live API call in this lab",
    }


def stress_controls() -> list:
    """The lab's named STRESS negative controls, evaluated live each call."""
    sanitized_level = carbon_decide("static_analysis", _SANITIZED_CODE)["level"]
    benign = carbon_decide("static_analysis", _BENIGN_CODE)
    critical = carbon_decide("execute_php_sample", _CRITICAL_CODE)
    tighten = carbon_decide("static_analysis", _BENIGN_CODE, base_verdict="HOLD")
    return [
        {"name": "sanitized_sample_not_escalated",
         "passed": sanitized_level in ("low", "medium"),
         "detail": f"htmlspecialchars/PDO-prepare sample decided at level {sanitized_level}"},
        {"name": "benign_static_analysis_proceeds",
         "passed": benign["verdict"] == "ALLOW",
         "detail": f"benign static analysis verdict {benign['verdict']}"},
        {"name": "eval_unserialize_critical_stays_high_or_hold",
         "passed": critical["verdict"] == "HOLD" and critical["level"] in ("high", "critical"),
         "detail": f"eval/unserialize subject level {critical['level']}, verdict {critical['verdict']}"},
        {"name": "carbon_can_only_tighten",
         "passed": tighten["verdict"] == "HOLD",
         "detail": "a base HOLD is never loosened by Carbon 4"},
    ]
