"""Candidate labs: medical hypotheses and tech inventions.

HONEST SCOPE: these are in-silico scored *hypotheses / concepts*, not
proven cures and not working inventions. A high score means 'passes the
lab's own maths checks and is worth human expert review' — nothing more.
Clinical use, human testing and real deployment are HOLD gates.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass


@dataclass(frozen=True)
class Candidate:
    id: str
    kind: str  # medical-hypothesis | tech-invention
    name: str
    basis: str  # formula id(s) it stands on
    claim: str
    score: float  # 0..1 deterministic in-silico score
    status: str  # PROMOTED_TO_SANDBOX | REVIEW | REJECTED


def _score(seed_text: str, base: float) -> float:
    rng = random.Random(seed_text)
    return round(max(0.0, min(1.0, base + rng.uniform(-0.08, 0.08))), 4)


_MEDICAL = [
    ("med-01", "SIR-timed intervention window model", "sir",
     "Model hypothesis: intervention timing windows change peak I in simulation."),
    ("med-02", "Half-life dosing-interval maths check", "half-life",
     "Maths hypothesis: interval = half-life keeps simulated levels in a band. Not dosing advice."),
    ("med-03", "Logistic treatment-response curve fit", "logistic",
     "Model hypothesis: response curves fit a logistic shape in synthetic data."),
    ("med-04", "BMI-independent risk-index formula study", "bmi",
     "Formula study: compare index variants on synthetic data only."),
    ("med-05", "Fourier denoising of synthetic ECG-like signals", "fourier",
     "Signal hypothesis: Fourier filtering removes synthetic noise from a fake signal."),
    ("med-06", "Compound-decay combination model", "compound",
     "Model hypothesis: two decaying agents interact additively in simulation."),
]

_TECH = [
    ("tech-01", "Rocket propellant fraction optimiser", "rocket",
     "Concept: use the rocket equation to rank propellant fractions in simulation."),
    ("tech-02", "Wave-energy harvester frequency matcher", "wave",
     "Concept: match harvester resonance to wave frequency in simulation."),
    ("tech-03", "Battery thermal power budget model", "ohm-power",
     "Concept: Ohm-power maths sizes a simulated cooling budget."),
    ("tech-04", "Kinetic regenerative braking estimator", "kinetic",
     "Concept: KE maths estimates recoverable braking energy in simulation."),
    ("tech-05", "Kruskal-coordinate visualiser for education", "kruskal",
     "Concept: interactive diagram of U/V coordinates for teaching. Education only."),
    ("tech-06", "Logistic data-centre capacity planner", "logistic",
     "Concept: logistic curve plans simulated capacity growth."),
]


_EXPANSION = [
    # (id, kind, name, basis, claim)
    ("bio-01", "biology", "Hardy-Weinberg synthetic population simulator", "hardy-weinberg",
     "Simulation: track genotype frequencies over synthetic generations."),
    ("bio-02", "biology", "Enzyme kinetics parameter fitter", "michaelis-menten",
     "Simulation: fit Vmax/Km to synthetic enzyme data. Wet-lab work is HOLD."),
    ("sci-01", "science", "Ideal-gas chamber maths model", "ideal-gas",
     "Simulation: predict pressure/volume changes in a sealed virtual chamber."),
    ("data-01", "data-science", "Bayesian diagnostic maths explorer", "bayes",
     "Maths explorer: show how base rates change posterior probability. Not medical advice."),
    ("data-02", "data-science", "Entropy-based anomaly scorer", "entropy",
     "Concept: score synthetic data streams by Shannon entropy shift."),
    ("data-03", "data-science", "Regression trend forecaster (synthetic)", "linreg",
     "Concept: fit trends to synthetic series only."),
    ("rob-01", "robotics", "2-link arm trajectory planner", "robot-fk",
     "Simulation-only: plan arm paths with forward kinematics. Real hardware is HOLD."),
    ("rob-02", "robotics", "PID tuning sandbox", "pid",
     "Simulation-only: tune a virtual controller, no real actuator."),
    ("trans-01", "transportation", "Braking-distance safety calculator", "stopping",
     "Calculator concept: stopping distance by speed and road friction."),
    ("trans-02", "transportation", "EV / drag range optimiser", "ev-range",
     "Simulation: trade drag vs range for a virtual vehicle."),
    ("lev-01", "levitation", "Maglev force-balance design study", "maglev",
     "Design study in maths only: size B and area to beat weight on paper. Building a rig is HOLD."),
    ("lev-02", "levitation", "Acoustic levitation node mapper", "acoustic-lev",
     "Simulation: map standing-wave nodes for tiny-particle trapping concepts."),
]


_AI_EXPANSION = [
    ("comp-01", "computers", "Algorithm cost visualiser", "big-o",
     "Concept: plot Big-O growth curves for teaching / planning."),
    ("comp-02", "computers", "Binary / number-systems trainer", "binary",
     "Concept: interactive base-conversion drills."),
    ("llm-01", "llm", "Softmax temperature explorer", "softmax",
     "Maths explorer: how temperature reshapes token probabilities. No model trained / deployed."),
    ("llm-02", "llm", "Attention pattern visualiser (tiny, synthetic)", "attention",
     "Concept: visualise attention weights on a toy sequence only."),
    ("slm-01", "slm", "Small-model efficiency estimator", "softmax",
     "Concept: estimate SLM vs LLM cost from parameter / token maths on paper."),
    ("ml-01", "ml", "Gradient-descent playground", "grad-descent",
     "Simulation: watch a virtual optimiser minimise toy losses."),
    ("ml-02", "ml", "Perceptron decision-boundary lab", "perceptron",
     "Simulation: fit a perceptron to synthetic 2-D data."),
    ("nnl-01", "nnl", "Neural layer forward-pass builder", "nn-forward",
     "Concept: stack hand-checked tiny layers (NNL) in simulation only."),
    ("ani-01", "ani", "ANI task-scope evaluator", "capability-ladder",
     "Rubric: score a narrow-AI concept on one task only. ANI = narrow, single-domain."),
    ("agi-01", "agi", "AGI readiness rubric (evaluation only)", "capability-ladder",
     "Evaluation framework only: checklist for generality claims. Does NOT build AGI."),
    ("asi-01", "asi", "ASI governance / HOLD-gate rubric", "capability-ladder",
     "Governance rubric only: what must stay HOLD before any ASI claim. Does NOT build ASI."),
]


_NATURE_EXPANSION = [
    ("atom-01", "atomic", "Isotope / proton-count explorer", "proton-charge",
     "Concept: explore elements by proton count, charge and mass number on paper."),
    ("atom-02", "atomic", "Hydrogen spectrum level calculator", "hydrogen-level",
     "Calculator: electron level energies in hydrogen."),
    ("natres-01", "natural-resources", "Solar + hydro site maths ranker", "solar-harvest",
     "Simulation: rank virtual sites by solar/hydro power maths. No real build."),
    ("natres-02", "natural-resources", "Natural oil energy budget model", "oil-energy",
     "Maths model: energy budgets for natural oils as fuel/food data only."),
    ("natmed-01", "natural-medicine", "Plant extraction-yield lab analyser", "extraction-yield",
     "Lab-analysis concept only: yield maths for plant/oil extraction. Not a remedy, ingestion / human use is HOLD."),
    ("nutri-01", "nutrition", "Fruit + vegetable nutrient mixer", "nutrient-sum",
     "Information concept: sum labelled nutrients in a fruit/veg mix. Not dietary advice."),
    ("nutri-02", "nutrition", "Glycemic-load meal estimator", "glycemic-load",
     "Information concept: GL maths for meals. Not dietary / medical advice."),
    ("super-01", "supercomputing", "Supercomputer job speedup planner", "amdahl",
     "Simulation: plan parallel jobs with Amdahl's law. No live cluster is used."),
    ("super-02", "supercomputing", "FLOPS capacity estimator", "flops-scaling",
     "Estimator: total FLOPS from node maths on paper."),
    ("quant-01", "quantum-computing", "Qubit state-space visualiser", "qubit-dim",
     "Education concept: show 2^n growth. Local simulation only, no quantum hardware."),
    ("quant-02", "quantum-computing", "Grover search teaching simulator", "grover",
     "Teaching simulation of Grover iteration counts on tiny spaces only."),
]


def generate_candidates() -> list[Candidate]:
    out: list[Candidate] = []
    for cid, name, basis, claim in _MEDICAL:
        s = _score(cid, 0.62 + (len(name) % 7) * 0.03)
        out.append(Candidate(cid, "medical-hypothesis", name, basis, claim, s, _status(s)))
    for cid, name, basis, claim in _TECH:
        s = _score(cid, 0.60 + (len(name) % 9) * 0.03)
        out.append(Candidate(cid, "tech-invention", name, basis, claim, s, _status(s)))
    for cid, kind, name, basis, claim in _EXPANSION:
        s = _score(cid, 0.61 + (len(name) % 8) * 0.03)
        out.append(Candidate(cid, kind, name, basis, claim, s, _status(s)))
    for cid, kind, name, basis, claim in _AI_EXPANSION:
        s = _score(cid, 0.61 + (len(name) % 8) * 0.03)
        out.append(Candidate(cid, kind, name, basis, claim, s, _status(s)))
    for cid, kind, name, basis, claim in _NATURE_EXPANSION:
        s = _score(cid, 0.61 + (len(name) % 8) * 0.03)
        out.append(Candidate(cid, kind, name, basis, claim, s, _status(s)))
    return out


def _status(score: float) -> str:
    if score >= 0.72:
        return "PROMOTED_TO_SANDBOX"
    if score >= 0.55:
        return "REVIEW"
    return "REJECTED"


def synthetic_signal_test(samples: int = 512) -> bool:
    """med-05 check: Fourier-style smoothing reduces noise on a FAKE signal."""
    rng = random.Random(42)
    clean = [math.sin(2 * math.pi * i / 64) for i in range(samples)]
    noisy = [v + rng.uniform(-0.5, 0.5) for v in clean]
    smooth = [
        sum(noisy[max(0, i - 2): i + 3]) / len(noisy[max(0, i - 2): i + 3])
        for i in range(samples)
    ]
    err_noisy = sum(abs(a - b) for a, b in zip(clean, noisy)) / samples
    err_smooth = sum(abs(a - b) for a, b in zip(clean, smooth)) / samples
    return err_smooth < err_noisy
