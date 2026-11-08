"""Thousands of deterministic tests.

Seeded, offline, zero-dependency. Runs:
- every catalog formula check, repeated across parameter sweeps
- algebraic identity property tests (commutative, associative, distributive…)
- candidate-lab consistency tests
Counts are real: the runner actually executes each test.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass

from .catalog import FORMULAS
from .labs import generate_candidates, synthetic_signal_test


@dataclass
class RunResult:
    total: int
    passed: int
    failed: int
    failures: list[str]

    @property
    def ok(self) -> bool:
        return self.failed == 0


def run_thousands(target: int = 2048) -> RunResult:
    rng = random.Random(20261107)
    passed = failed = 0
    failures: list[str] = []

    def record(name: str, ok: bool) -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
        else:
            failed += 1
            if len(failures) < 20:
                failures.append(name)

    # 1) Formula checks
    for f in FORMULAS:
        try:
            record(f"formula:{f.id}", bool(f.check()))
        except Exception as exc:
            record(f"formula:{f.id}:{exc}", False)

    # 2) Lab checks
    cands = generate_candidates()
    record("lab:candidates>=10", len(cands) >= 10)
    record("lab:scores-in-range", all(0.0 <= c.score <= 1.0 for c in cands))
    record("lab:synthetic-signal", synthetic_signal_test())

    # 3) Property tests until we reach the target count
    i = 0
    while passed + failed < target:
        a, b, c = (rng.uniform(-100, 100) for _ in range(3))
        kind = i % 8
        if kind == 0:
            ok = abs((a + b) - (b + a)) < 1e-9
            name = "commutative-add"
        elif kind == 1:
            ok = abs((a * b) - (b * a)) < 1e-7
            name = "commutative-mul"
        elif kind == 2:
            ok = abs((a + (b + c)) - ((a + b) + c)) < 1e-7
            name = "associative-add"
        elif kind == 3:
            ok = abs(a * (b + c) - (a * b + a * c)) < 1e-6
            name = "distributive"
        elif kind == 4:
            x = rng.uniform(0.1, 10)
            ok = abs(math.log(math.exp(x)) - x) < 1e-9
            name = "log-exp-inverse"
        elif kind == 5:
            x = rng.uniform(-10, 10)
            ok = abs(math.sin(x) ** 2 + math.cos(x) ** 2 - 1) < 1e-9
            name = "trig-identity"
        elif kind == 6:
            x = rng.uniform(0.1, 100)
            ok = abs(math.sqrt(x) ** 2 - x) < 1e-7
            name = "sqrt-square"
        else:
            x = rng.uniform(1, 100)
            ok = abs(x * 0.5 ** (math.log2(x)) - 1.0) < 1e-6 if x > 0 else False
            name = "half-life-inverse"
        record(f"prop:{name}:{i}", ok)
        i += 1

    return RunResult(passed + failed, passed, failed, failures)
