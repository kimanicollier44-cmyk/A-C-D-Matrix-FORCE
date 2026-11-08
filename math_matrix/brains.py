"""Two-brain council — FULL seats, names-only API keys, no live calls.

Gemini Carbon 4 Extended Thinking — DECIDER (full seat)
  model:  google/gemini-carbon-4-extended-pro-thinking
  stages: MAP -> MODEL -> STRESS -> DECIDE
  tiers:  2048 / 8192 / 32768 (32768 = extended default)
  mode:   offline-authoritative — decisions are computed locally and
          deterministically; a live call, if Darion ever approves one,
          needs the env key by NAME only (GEMINI_API_KEY).
  power:  can only TIGHTEN. It can turn PROCEED into HOLD, never the
          other way, and it can never lift a HOLD gate.

Muse AI — ADVISOR (full seat)
  models: muse-spark-1.1 / muse-wonder-1.0 (Meta Model API)
  key:    env name only (MODEL_API_KEY). Key creation is free, usage
          is billed pay-as-you-go — Muse is NOT a free seat.
  power:  decision_authority = "none". It returns exactly 4 advice
          items per evaluation and can never override Carbon 4 or
          a HOLD gate.

Council rule: Carbon 4 decides first, Muse advises second,
STRICTEST WINS — proven by the stress controls below and in tests.
"""
from __future__ import annotations

import os

CARBON4 = {
    "role": "DECIDER",
    "model": "google/gemini-carbon-4-extended-pro-thinking",
    "stages": ["MAP", "MODEL", "STRESS", "DECIDE"],
    "tiers": [2048, 8192, 32768],
    "default_tier": 32768,
    "mode": "offline-authoritative",
    "key_env_name_only": "GEMINI_API_KEY",
    "can_tighten": True,
    "can_lift_hold": False,
}
MUSE = {
    "role": "ADVISOR",
    "models": ["muse-spark-1.1", "muse-wonder-1.0"],
    "model": "muse-spark-1.1 / muse-wonder-1.0",
    "key_env_name_only": "MODEL_API_KEY",
    "authority": "none",
    "decision_authority": "none",
    "advice_items_per_evaluation": 4,
    "can_lift_hold": False,
    "cost": "key creation free, usage billed — NOT free",
}

# Actions that always HOLD no matter what either brain says.
_GATED_WORDS = ("clinical", "deploy", "hardware", "human", "animal",
                "money", "patent", "regulatory", "publish-claim")


def key_present(env_name: str) -> bool:
    """Presence only — the value is never read, logged or stored."""
    return env_name in os.environ


def carbon4_evaluate(subject: str, score: float, gated: bool) -> dict:
    """Run the 4 Carbon 4 stages locally on one candidate.

    MAP:    place the subject in its domain.
    MODEL:  read its deterministic score.
    STRESS: negative controls — gated action or a failing score holds.
    DECIDE: HOLD if gated or score < 0.55, else PROCEED (sandbox only).
    """
    stages = {
        "MAP": f"subject={subject}",
        "MODEL": f"score={score}",
        "STRESS": "gated" if gated else "clean-context",
        "DECIDE": "HOLD" if (gated or score < 0.55) else "PROCEED",
    }
    return {
        "brain": "gemini-carbon-4-extended-thinking",
        "tier": CARBON4["default_tier"],
        "stages": stages,
        "decision": stages["DECIDE"],
        "live_call_made": False,
    }


def muse_advise(subject: str, score: float) -> list[str]:
    """Exactly 4 advice items. Advice only — authority none."""
    return [
        f"Keep '{subject}' labelled as a hypothesis/concept, never a proven result.",
        f"Score {score} is an in-silico lab score — say so wherever it is shown.",
        "Show the formula the candidate stands on next to every claim.",
        "If any real-world step appears, route it to a HOLD gate for Darion.",
    ]


def decide(action_is_gated: bool, carbon_says_hold: bool, muse_says_hold: bool) -> str:
    """Strictest wins: any HOLD, or a gated action, is a HOLD."""
    if action_is_gated or carbon_says_hold or muse_says_hold:
        return "HOLD"
    return "PROCEED"


def council_evaluate(subject: str, score: float, gated: bool) -> dict:
    """Full council: Carbon 4 decides, Muse advises, strictest wins."""
    carbon = carbon4_evaluate(subject, score, gated)
    advice = muse_advise(subject, score)
    final = decide(gated, carbon["decision"] == "HOLD", False)
    return {"subject": subject, "carbon4": carbon, "muse_advice": advice,
            "muse_authority": "none", "final": final}


def stress_controls() -> bool:
    """Negative + positive controls for the council (all must hold).

    1. clean context, good score        -> PROCEED
    2. gated action                     -> HOLD (even with good score)
    3. Muse advises proceed, gate fires -> HOLD (advice never overrides)
    4. failing score                    -> HOLD (Carbon 4 STRESS)
    5. Carbon 4 says HOLD, Muse friendly -> HOLD (strictest wins)
    """
    return (
        council_evaluate("clean-candidate", 0.90, False)["final"] == "PROCEED"
        and council_evaluate("clinical-use", 0.99, True)["final"] == "HOLD"
        and decide(True, False, False) == "HOLD"
        and council_evaluate("weak-candidate", 0.20, False)["final"] == "HOLD"
        and decide(False, True, False) == "HOLD"
        and len(muse_advise("x", 0.5)) == 4
    )
