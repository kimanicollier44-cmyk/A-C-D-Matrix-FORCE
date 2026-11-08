"""HOLD gates -- anything live is held, never executed by this lab."""
from __future__ import annotations

HOLD_GATES = {
    "live_exploitation": "exploiting a live system is never done by this lab",
    "live_scanning_public_target": "scanning a public / third-party target is held",
    "exploit_payload_generation": "no exploit payloads are generated -- records are data only",
    "use_disclosed_credentials_or_sessions": "leaked credentials or session tokens are never used",
    "persistence_or_webshell_install": "no persistence, webshells or implants",
    "live_target_fingerprinting": "no fingerprinting of live targets",
    "live_video_generation": "Flow filmmaking is plan-only; rendering is held",
    "live_gemini_api_call": "live Carbon 4 / Gemini API call needs a key-owner order",
    "live_network_probe": "no network probes of any kind from this lab",
    "credential_acquisition": "no acquiring, harvesting or testing credentials",
    "live_patch_deployment": "deploying patches to a live system is an owner action, held here",
    "mass_target_enumeration": "no enumeration of internet-facing hosts",
}


def is_held(action: str) -> bool:
    return action in HOLD_GATES


def gate_check(action: str) -> dict:
    if action in HOLD_GATES:
        return {"action": action, "verdict": "HOLD",
                "reason": HOLD_GATES[action]}
    return {"action": action, "verdict": "ALLOW",
            "reason": "static, offline, data-only lab action"}
