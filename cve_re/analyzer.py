"""Deterministic risk / priority triage over the CVE catalog."""
from __future__ import annotations

from .catalog import CATALOG

_TYPE_BONUS = {"rce": 10, "memory_disclosure": 8, "auth_bypass_chain": 6}


def priority_score(record: dict) -> float:
    """0-100 priority from CVSS + KEV + unauthenticated + type."""
    base = record.get("cvss")
    score = (float(base) * 7.0) if base is not None else 35.0
    if record.get("kev"):
        score += 15
    if record.get("unauthenticated"):
        score += 5
    score += _TYPE_BONUS.get(record.get("vuln_type"), 0)
    if record.get("requires_key_rotation"):
        score += 3
    return round(min(score, 100.0), 2)


def priority_level(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def rank(records=None) -> list:
    items = list(CATALOG if records is None else records)
    return sorted(items, key=lambda r: (-priority_score(r), r["cve_id"]))


def group_by(records, key: str) -> dict:
    out = {}
    for r in records:
        out.setdefault(r[key], []).append(r)
    return out


def group_by_vendor(records=None) -> dict:
    return group_by(CATALOG if records is None else records, "vendor")


def group_by_type(records=None) -> dict:
    return group_by(CATALOG if records is None else records, "vuln_type")


def filter_catalog(vendor=None, vuln_type=None, kev_only=False, query=None):
    out = list(CATALOG)
    if vendor:
        out = [r for r in out if r["vendor"].lower() == vendor.lower()]
    if vuln_type:
        out = [r for r in out if r["vuln_type"] == vuln_type]
    if kev_only:
        out = [r for r in out if r["kev"]]
    if query:
        q = query.lower()
        out = [r for r in out if q in r["cve_id"].lower()
               or q in r["name"].lower() or q in r["product"].lower()
               or q in r["vendor"].lower()]
    return out


def search(query: str) -> list:
    return filter_catalog(query=query)


def remediation_plan(record: dict, patched=False, sessions_rotated=False,
                     keys_rotated=False) -> dict:
    """Closure check expressing the rotation nuance.

    Patching alone is NOT closure when the record requires session
    rotation (CitrixBleed family) or key rotation (ToolShell /
    Heartbleed): the status stays ``patched_not_closed`` until the
    required rotations are also done.
    """
    steps = ["patch"]
    if record.get("requires_session_rotation"):
        steps.append("rotate_sessions")
    if record.get("requires_key_rotation"):
        steps.append("rotate_keys")
    missing = []
    if not patched:
        missing.append("patch")
    if record.get("requires_session_rotation") and not sessions_rotated:
        missing.append("rotate_sessions")
    if record.get("requires_key_rotation") and not keys_rotated:
        missing.append("rotate_keys")
    if not patched:
        status = "open"
    elif missing:
        status = "patched_not_closed"
    else:
        status = "closed"
    return {"cve_id": record["cve_id"], "remediation": record["remediation"],
            "steps": steps, "missing": missing, "status": status,
            "patch_alone_closes": not (record.get("requires_session_rotation")
                                       or record.get("requires_key_rotation"))}
