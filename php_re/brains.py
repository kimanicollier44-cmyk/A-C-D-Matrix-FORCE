"""Gemini Carbon 4 Extended Thinking -- DECIDER seat (offline, names-only).

No API call is made by this lab. The seat records the decision protocol:
Carbon 4 decides, Muse advises, the strictest verdict wins, and a HOLD
can never be overridden by the advisor.
"""
from __future__ import annotations
import os

DECIDER_MODEL = "gemini-2.5-pro"
DECIDER_NAME = "Gemini Carbon 4 Extended Thinking"
THINKING_BUDGETS = (2048, 8192, 32768)

HOLD_GATES = [
    "execute_php_sample",
    "exploit_live_site",
    "upload_web_shell",
    "live_auth_bypass",
    "live_unserialize_payload",
    "remote_file_fetch_ssrf_rfi",
    "deploy_vulnerable_app_public",
    "extract_live_credentials",
    "live_video_generation",
    "detonate_live_file",
    "execute_php_outside_chamber",
    "sandbox_network_access",
    "open_live_honeypot_listener",
    "deploy_honeypot_public",
]


def is_held(action: str) -> bool:
    return action in HOLD_GATES


def decide(action: str, advisor_verdict: str = "ALLOW") -> dict:
    """Strictest wins. Advisor can tighten, never loosen, a HOLD."""
    held = is_held(action)
    verdict = "HOLD" if (held or advisor_verdict == "HOLD") else "ALLOW"
    return {
        "action": action, "verdict": verdict, "decider": DECIDER_NAME,
        "model": DECIDER_MODEL, "thinking_budgets": list(THINKING_BUDGETS),
        "advisor_verdict": advisor_verdict,
        "reason": "action is on the HOLD gate list" if held else "static / synthetic / local analysis only",
        "api_key_present": bool(os.environ.get("GEMINI_API_KEY")),
        "note": "names-only seat -- no live API call in this lab",
    }
