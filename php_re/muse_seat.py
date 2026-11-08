"""Muse AI advisor seat -- full seat, names-only, NO decision authority.

The key is referenced by NAME only (MODEL_API_KEY, a must-plug seat). Its
value is never read into output, never logged, and no live call is made
by this lab. Usage of the real Muse API is billed by Meta; it is not
free -- only key creation is. This lab runs fully without it.

Council protocol: Gemini Carbon 4 Extended Thinking DECIDES first, Muse
advises second, and the strictest verdict wins. Muse's
decision_authority is "none": friendly Muse advice can never loosen a
Carbon 4 / brains HOLD.
"""
from __future__ import annotations
import os

ADVISOR_NAME = "Muse (advisor)"
ADVISOR_MODELS = ("muse-spark-1.1", "muse-wonder-1.0")
KEY_ENV_NAME = "MODEL_API_KEY"
DECISION_AUTHORITY = "none"


def seat_status() -> dict:
    return {
        "advisor": ADVISOR_NAME, "models": list(ADVISOR_MODELS),
        "key_env_name": KEY_ENV_NAME,
        "key_present": KEY_ENV_NAME in os.environ,
        "must_plug": True,
        "decision_authority": DECISION_AUTHORITY,
        "can_override_hold": False,
        "note": "advisor only -- strictest verdict wins; no live call in this lab",
    }


def _advice_items(action: str, decider_verdict: str) -> list:
    return [
        f"Trace the source-to-sink path for '{action}' before trusting any verdict.",
        "Check that a real sanitizer (not just a cast or a comment) sits between source and sink.",
        "Apply the sample's publisher-side hardening fix and re-run the static analyzer.",
        ("This action sits on a HOLD gate -- keep it held; static, synthetic study only."
         if decider_verdict == "HOLD" else
         "Static / synthetic / local analysis only -- no live target, no execution."),
    ]


def advise(action: str, decider_verdict: str) -> dict:
    # Advisor agrees with, or tightens, the decider -- it cannot loosen a HOLD.
    verdict = "HOLD" if decider_verdict == "HOLD" else "ALLOW"
    return {"action": action, "advisor_verdict": verdict,
            "advice_items": _advice_items(action, decider_verdict),
            "advice_count": 4,
            "models": list(ADVISOR_MODELS),
            "decision_authority": DECISION_AUTHORITY,
            "can_override_hold": False}


def council(action: str, code: str = None, advisor_verdict: str = "ALLOW",
            base_risk: int = 50) -> dict:
    """Carbon 4 decides first, Muse advises, strictest wins.

    ``advisor_verdict`` is Muse's independent advice for this run. Even a
    friendly "ALLOW" from Muse cannot loosen a HOLD: if Carbon 4 (or the
    gate list) holds the action, the council verdict is HOLD.
    """
    from .carbon4 import carbon_decide  # local import: no import cycle
    decision = carbon_decide(action, code=code, base_risk=base_risk)
    advice = advise(action, decision["verdict"])
    verdicts = (decision["verdict"], advisor_verdict, advice["advisor_verdict"])
    final = "HOLD" if "HOLD" in verdicts else "ALLOW"
    return {
        "action": action,
        "decider": decision["decider"], "decider_verdict": decision["verdict"],
        "decider_level": decision["level"],
        "advisor": ADVISOR_NAME, "advisor_verdict": advisor_verdict,
        "advice_items": advice["advice_items"], "advice_count": advice["advice_count"],
        "decision_authority": DECISION_AUTHORITY,
        "verdict": final, "rule": "strictest wins -- Muse can never override a HOLD",
    }
