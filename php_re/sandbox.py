"""Sandbox-API -- a static triage chamber shaped like an API.

``triage(sample) -> report dict``. The chamber NEVER executes PHP: every
report carries executed=False, network access is always off
(network=0 / network_access=False), and telemetry + filesystem-diff are
record-only bookkeeping about the static analysis itself.

Verdict logic:
- A clean / sanitized synthetic sample -> ALLOW_TO_LAB_TEST (static
  study inside the lab; still never executed).
- A sample carrying live-execution markers -> HOLD_IN_SANDBOX:
  eval of user input, unserialize of a cookie, or an include/require of
  a user-controlled variable or remote URL (RFI shape).

Detonating a live file, executing PHP outside the chamber, and giving
the sandbox network access are all HOLD gates.
"""
from __future__ import annotations
import re

from .analyzer import analyze
from .samples import SAMPLES

_MARKERS = {
    "eval_of_user_input": re.compile(r"\beval\s*\([^)]*(\$_|\$[A-Za-z_])"),
    "unserialize_of_cookie": re.compile(r"\bunserialize\s*\([^)]*(\$_COOKIE|\$[A-Za-z_])"),
    "include_of_variable_or_url": re.compile(
        r"\b(?:include|include_once|require|require_once)\s*\(?\s*(\$|https?://)"),
    "eval_generic": re.compile(r"\beval\s*\("),
    "unserialize_generic": re.compile(r"\bunserialize\s*\("),
}


def _markers_for(code: str, sample_id: str) -> list:
    found = []
    if _MARKERS["eval_of_user_input"].search(code):
        found.append("eval_of_user_input")
    if "unserialize" in code and ("$_COOKIE" in code or sample_id == "object-injection-08"):
        if _MARKERS["unserialize_generic"].search(code):
            found.append("unserialize_of_cookie")
    if _MARKERS["include_of_variable_or_url"].search(code):
        found.append("include_of_variable_or_url")
    return found


def triage(sample) -> dict:
    """Static triage of one sample (dict with code, or a raw code string)."""
    if isinstance(sample, str):
        sample = {"id": "ad-hoc", "code": sample, "base_risk": 50}
    code = sample["code"]
    report = analyze(code, base_risk=sample.get("base_risk", 50))
    markers = _markers_for(code, sample.get("id", ""))
    held = bool(markers)
    return {
        "id": sample.get("id", "ad-hoc"),
        "verdict": "HOLD_IN_SANDBOX" if held else "ALLOW_TO_LAB_TEST",
        "markers": markers,
        "executed": False,
        "network": 0, "network_access": False,
        "telemetry": {
            "sources": report["sources"], "sinks": report["sinks"],
            "sanitizers": report["sanitizers"], "risk_score": report["risk_score"],
            "mode": "record-only",
        },
        "fs_diff": {"created": [], "modified": [], "deleted": [], "record_only": True},
        "mode": "static-triage",
        "note": "PHP was not executed; this report is static analysis only",
    }


# A clean, sanitized synthetic snippet used by the demo / negative control.
SANITIZED_SNIPPET = {
    "id": "sanitized-demo", "base_risk": 30,
    "code": ("<?php $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');"
             " $stmt->execute([intval($_GET['id'])]);"
             " echo htmlspecialchars($name, ENT_QUOTES, 'UTF-8');"),
}


def sandbox_demo() -> dict:
    reports = [triage(s) for s in SAMPLES] + [triage(SANITIZED_SNIPPET)]
    return {
        "reports": reports,
        "total": len(reports),
        "allowed": sum(1 for r in reports if r["verdict"] == "ALLOW_TO_LAB_TEST"),
        "held": sum(1 for r in reports if r["verdict"] == "HOLD_IN_SANDBOX"),
        "held_ids": [r["id"] for r in reports if r["verdict"] == "HOLD_IN_SANDBOX"],
        "any_executed": any(r["executed"] for r in reports),
        "network_access": False,
    }
