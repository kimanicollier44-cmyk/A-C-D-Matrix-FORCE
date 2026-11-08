"""HOLD gates — hard stops. Only Darion can lift one, explicitly, per action."""
from __future__ import annotations

HOLD_GATES = [
    ("clinical_use", "No candidate is a proven cure. Clinical use / human trials are HOLD."),
    ("medical_advice", "Lab output is never medical advice for a real person."),
    ("real_deployment", "Deploying a creation into the real world is HOLD. Sandbox registry only."),
    ("live_hardware", "Building / powering real hardware from an invention concept is HOLD."),
    ("human_testing", "Testing any substance, device or procedure on a person is HOLD."),
    ("animal_testing", "Testing on animals is HOLD."),
    ("mainnet_or_money", "Spending real money, minting, or financial deployment is HOLD."),
    ("external_publish_claim", "Publishing a candidate as a proven cure / working invention is HOLD."),
    ("untrusted_code_exec", "Executing untrusted / generated code outside the sandbox is HOLD."),
    ("live_data_fetch", "Fetching live patient, market or private data is HOLD. Offline only."),
    ("regulatory_filing", "Filing with FDA / any regulator is HOLD."),
    ("patent_filing", "Filing a real patent application is HOLD."),
]

GATE_NAMES = [name for name, _ in HOLD_GATES]


def check(action: str) -> str:
    """Return 'HOLD' for any gated action, else 'PROCEED'."""
    return "HOLD" if action in GATE_NAMES else "PROCEED"


def hold_demo() -> int:
    """Print every gate. Exit code 2 mirrors Darion's other labs."""
    for name, why in HOLD_GATES:
        print(f"HOLD  {name}: {why}")
    print(f"{len(HOLD_GATES)} HOLD gates — none lifted.")
    return 2
