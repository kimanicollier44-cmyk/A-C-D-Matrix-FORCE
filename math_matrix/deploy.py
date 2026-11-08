"""Deploy successful creations — to the SANDBOX registry only.

'Deploy' here means: a candidate that passed the test battery is written
to a local verified-creations registry (data, in this repo / runtime).
Real-world deployment, clinical use, hardware builds and publishing a
candidate as proven are HOLD gates (see gates.py).
"""
from __future__ import annotations

import json
from pathlib import Path

from . import gates
from .labs import Candidate


def deploy_successful(candidates: list[Candidate], registry: Path) -> dict:
    if gates.check("real_deployment") != "HOLD":
        raise RuntimeError("real_deployment gate missing — refusing")
    promoted = [c for c in candidates if c.status == "PROMOTED_TO_SANDBOX"]
    payload = {
        "registry": "sandbox-only",
        "real_world_deployment": "HOLD",
        "count": len(promoted),
        "creations": [
            {"id": c.id, "kind": c.kind, "name": c.name, "basis": c.basis, "score": c.score}
            for c in promoted
        ],
    }
    registry.parent.mkdir(parents=True, exist_ok=True)
    registry.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return payload
