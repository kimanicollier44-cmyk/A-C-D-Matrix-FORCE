"""Equation / formula catalog.

Every entry is data + a pure numeric check function. Nothing here is
executed from a string, fetched live, or claimed beyond its math.
The video seed ideas (order of operations, Kruskal-Szekeres coordinates,
advanced-calculus pathways) are included as catalog entries, honestly
labelled as coordinate / framework math, not new physics.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class Formula:
    id: str
    name: str
    domain: str  # algebra | geometry | calculus | physics | spacetime | biology | medicine-math | engineering
    expression: str
    meaning: str
    check: Callable[[], bool]


def _close(a: float, b: float, tol: float = 1e-9) -> bool:
    return abs(a - b) <= tol


def _pemdas() -> bool:
    # (3 + 2 * 6) / (4 - 1) with parentheses > exponents > mult/div > add/sub
    return _close((3 + 2 * 6) / (4 - 1), 5.0)


def _quadratic() -> bool:
    a, b, c = 1.0, -5.0, 6.0
    disc = b * b - 4 * a * c
    r1 = (-b + math.sqrt(disc)) / (2 * a)
    r2 = (-b - math.sqrt(disc)) / (2 * a)
    return _close(r1, 3.0) and _close(r2, 2.0)


def _pythagoras() -> bool:
    return _close(math.hypot(3, 4), 5.0)


def _euler_identity() -> bool:
    return abs((math.e ** (1j * math.pi) + 1)) < 1e-9


def _derivative_power() -> bool:
    # d/dx x^3 = 3x^2, numeric check at x=2
    h = 1e-6
    num = ((2 + h) ** 3 - (2 - h) ** 3) / (2 * h)
    return _close(num, 12.0, 1e-4)


def _integral_power() -> bool:
    # integral 0..1 of x^2 dx = 1/3, Simpson check
    n = 1000
    s = 0.0
    for i in range(n + 1):
        x = i / n
        w = 1 if i in (0, n) else (4 if i % 2 else 2)
        s += w * x * x
    return _close(s / (3 * n), 1 / 3, 1e-6)


def _schwarzschild_radius() -> bool:
    # r_s = 2GM/c^2 for 1 solar mass ~ 2953 m
    g, m, c = 6.67430e-11, 1.98847e30, 299792458.0
    return _close(2 * g * m / c ** 2, 2953.0, 5.0)


def _kruskal_u_v() -> bool:
    # Kruskal-Szekeres: U*V = -(r/2M - 1) * e^(r/2M) in G=c=1 units.
    # Identity check: for r=4 (M=1), U*V must equal -(2-1)*e^2.
    r, m = 4.0, 1.0
    uv = -(r / (2 * m) - 1) * math.exp(r / (2 * m))
    return _close(uv, -math.e ** 2)


def _rocket_equation() -> bool:
    # Tsiolkovsky: dv = ve * ln(m0/mf)
    return _close(3000 * math.log(10), 6907.755, 0.01)


def _ohm_power() -> bool:
    return _close(12 * 2, 24.0) and _close(12 ** 2 / 6, 24.0)  # V*I == V^2/R


def _logistic() -> bool:
    # Logistic growth at t=0 is K/2 when r*t offset is 0 form P=K/(1+e^0)
    k = 100.0
    return _close(k / (1 + math.exp(0)), 50.0)


def _sir_conservation() -> bool:
    # SIR compartments must sum to the population at every step (Euler, small dt)
    s, i, r, n = 990.0, 10.0, 0.0, 1000.0
    beta, gamma, dt = 0.3, 0.1, 0.01
    for _ in range(100):
        ds = -beta * s * i / n * dt
        di = (beta * s * i / n - gamma * i) * dt
        dr = gamma * i * dt
        s, i, r = s + ds, i + di, r + dr
    return _close(s + i + r, n, 1e-6)


def _half_life() -> bool:
    # Pharmacokinetic decay: after one half-life, half remains.
    return _close(100 * 0.5 ** (6 / 6), 50.0)


def _bmi() -> bool:
    return _close(70 / 1.75 ** 2, 22.857, 0.01)


def _compound_growth() -> bool:
    return _close(1000 * 1.05 ** 10, 1628.895, 0.01)


def _wave_speed() -> bool:
    return _close(440 * 2.0, 880.0)  # f * wavelength


def _kinetic() -> bool:
    return _close(0.5 * 2 * 3 ** 2, 9.0)


def _hardy_weinberg() -> bool:
    p, q = 0.6, 0.4
    return _close(p * p + 2 * p * q + q * q, 1.0)


def _michaelis_menten() -> bool:
    # v = Vmax*[S]/(Km+[S]); at [S]=Km, v=Vmax/2
    return _close(100 * 5 / (5 + 5), 50.0)


def _ideal_gas() -> bool:
    # PV = nRT -> V = nRT/P
    return _close(1 * 0.082057 * 300 / 1, 24.617, 0.01)


def _bayes() -> bool:
    # P(A|B) = P(B|A)P(A)/P(B) = 0.9*0.01 / (0.9*0.01+0.05*0.99)
    return _close(0.9 * 0.01 / (0.9 * 0.01 + 0.05 * 0.99), 0.1538, 0.001)


def _entropy_binary() -> bool:
    # Shannon entropy of a fair coin = 1 bit
    return _close(-(0.5 * math.log2(0.5) + 0.5 * math.log2(0.5)), 1.0)


def _linear_regression_slope() -> bool:
    # Perfect line y=2x+1 has slope exactly 2
    xs, ys = [0, 1, 2, 3], [1, 3, 5, 7]
    mx, my = sum(xs) / 4, sum(ys) / 4
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / sum((x - mx) ** 2 for x in xs)
    return _close(slope, 2.0)


def _robot_forward_kinematics() -> bool:
    # 2-link planar arm, both links 1, angles 0 and 90deg -> end at (1,1)
    x = math.cos(0) + math.cos(math.pi / 2)
    y = math.sin(0) + math.sin(math.pi / 2)
    return _close(x, 1.0) and _close(y, 1.0)


def _pid_step() -> bool:
    # P-only control: output = Kp * error
    return _close(2.0 * (10 - 7), 6.0)


def _stopping_distance() -> bool:
    # d = v^2/(2*mu*g) = 20^2/(2*0.7*9.81) ~ 29.13 m
    return _close(20 ** 2 / (2 * 0.7 * 9.81), 29.13, 0.05)


def _drag_force() -> bool:
    # F = 0.5*rho*v^2*Cd*A
    return _close(0.5 * 1.225 * 30 ** 2 * 0.3 * 2.0, 330.75, 0.01)


def _ev_range() -> bool:
    # range = battery_kwh * efficiency_km_per_kwh
    return _close(75 * 6.0, 450.0)


def _maglev_force_balance() -> bool:
    # Levitation condition in simulation: magnetic pressure force >= weight.
    # F = B^2*A/(2*mu0); B=1T, A=0.01 m2 -> ~3978 N, lifts ~405 kg in maths.
    mu0 = 4 * math.pi * 1e-7
    force = 1.0 ** 2 * 0.01 / (2 * mu0)
    return _close(force, 3978.87, 1.0) and force > 100 * 9.81


def _acoustic_levitation() -> bool:
    # Standing-wave nodes are spaced lambda/2 apart: 40kHz in air ~ 4.29 mm
    wavelength = 343 / 40000
    return _close(wavelength / 2 * 1000, 4.2875, 0.01)


def _binary_place_value() -> bool:
    return sum(b * 2 ** i for i, b in enumerate(reversed([1, 0, 1, 1]))) == 11


def _big_o_growth() -> bool:
    # O(n log n) at n=1024 is 10240 operations in unit maths
    return _close(1024 * math.log2(1024), 10240.0)


def _softmax() -> bool:
    xs = [1.0, 2.0, 3.0]
    exps = [math.exp(x) for x in xs]
    return _close(sum(e / sum(exps) for e in exps), 1.0)


def _attention_score() -> bool:
    # Scaled dot-product: softmax(QK^T/sqrt(d)) — check scale factor for d=64
    return _close(1 / math.sqrt(64), 0.125)


def _perceptron() -> bool:
    # y = step(w.x + b): weights [1,-1], input [2,1], b=0 -> 1 -> step=1
    return (1 * 2 + -1 * 1 + 0) > 0


def _gradient_descent_step() -> bool:
    # Minimise x^2: x1 = x0 - lr*2*x0 = 3 - 0.1*6 = 2.4
    return _close(3 - 0.1 * 2 * 3, 2.4)


def _cross_entropy() -> bool:
    # Perfect prediction (p=1 for true class) has loss 0
    return _close(-math.log(1.0), 0.0)


def _nn_forward() -> bool:
    # Tiny 2->1 network, sigmoid: inputs [1,0], weights [0.5,-0.5], b=0
    z = 1 * 0.5 + 0 * -0.5
    return _close(1 / (1 + math.exp(-z)), 0.622459, 1e-5)


def _moores_law() -> bool:
    # Doubling every 2 years: after 10 years, 2^5 = 32x
    return _close(2 ** (10 / 2), 32.0)


def _capability_ladder() -> bool:
    # Lab's own ordering check: ANI < AGI < ASI in claimed generality score.
    # A taxonomy / evaluation rubric only — NOT a claim any rung is built here.
    scores = {"ani": 1, "agi": 2, "asi": 3}
    return scores["ani"] < scores["agi"] < scores["asi"]


def _avogadro_atoms() -> bool:
    # atoms = moles * Avogadro's number; 2 mol -> 1.204428e24
    return _close(2 * 6.02214076e23, 1.204428152e24, 1e15)


def _proton_charge() -> bool:
    # Total charge of Z protons: Q = Z*e; carbon Z=6
    return _close(6 * 1.602176634e-19, 9.613059804e-19, 1e-27)


def _hydrogen_level() -> bool:
    # Bohr energy level E_n = -13.6 / n^2 eV; n=2 -> -3.4 eV
    return _close(-13.6 / 2 ** 2, -3.4)


def _atomic_mass_approx() -> bool:
    # Mass number A = protons + neutrons; carbon-12: 6+6=12
    return 6 + 6 == 12


def _solar_harvest() -> bool:
    # P = irradiance * area * efficiency = 1000 * 10 * 0.20 = 2000 W
    return _close(1000 * 10 * 0.20, 2000.0)


def _hydro_power() -> bool:
    # P = rho*g*Q*h = 1000*9.81*2*10 = 196200 W
    return _close(1000 * 9.81 * 2 * 10, 196200.0)


def _extraction_yield() -> bool:
    # Oil / compound extraction yield: 18 kg out of 100 kg seed = 18%
    return _close(18 / 100 * 100, 18.0)


def _glycemic_load() -> bool:
    # GL = GI * carbs_g / 100 = 50 * 20 / 100 = 10
    return _close(50 * 20 / 100, 10.0)


def _nutrient_sum() -> bool:
    # Nutrient total for a fruit+veg mix is additive on a label maths basis:
    # e.g. vitamin C 60 + 40 = 100 (units per serving, synthetic example data)
    return _close(60 + 40, 100.0)


def _oil_energy() -> bool:
    # Energy = mass * calorific value; 1 kg oil at ~37 MJ/kg -> 37 MJ
    return _close(1 * 37, 37.0)


def _amdahl_speedup() -> bool:
    # Amdahl: S = 1 / ((1-p) + p/N); p=0.9, N=10 -> 1/(0.1+0.09) = 5.263
    return _close(1 / ((1 - 0.9) + 0.9 / 10), 5.263, 0.001)


def _flops_scaling() -> bool:
    # Total FLOPS = nodes * FLOPS/node; 100 * 1e12 = 1e14 (100 TFLOPS)
    return _close(100 * 1e12, 1e14, 1e9)


def _qubit_dimension() -> bool:
    # n qubits live in a 2^n-dimensional state space; 10 qubits -> 1024
    return 2 ** 10 == 1024


def _qubit_probabilities() -> bool:
    # Probabilities of a qubit alpha|0>+beta|1> must sum to 1
    a, b = math.sqrt(0.5), math.sqrt(0.5)
    return _close(a * a + b * b, 1.0)


def _grover_iterations() -> bool:
    # Grover search needs ~ (pi/4)*sqrt(N) iterations; N=64 -> ~6.28
    return _close((math.pi / 4) * math.sqrt(64), 6.283, 0.001)


def _fourier_term() -> bool:
    # A single sine term integrates to 0 over a full period.
    n = 2000
    s = sum(math.sin(2 * math.pi * i / n) for i in range(n)) / n
    return abs(s) < 1e-3


FORMULAS: list[Formula] = [
    Formula("pemdas", "Order of Operations (PEMDAS)", "algebra",
            "(3 + 2*6) / (4 - 1) = 5", "Evaluation order: parentheses, exponents, mult/div, add/sub.", _pemdas),
    Formula("quadratic", "Quadratic Formula", "algebra",
            "x = (-b +/- sqrt(b^2-4ac)) / 2a", "Roots of ax^2+bx+c=0.", _quadratic),
    Formula("pythagoras", "Pythagorean Theorem", "geometry",
            "a^2 + b^2 = c^2", "Right-triangle side relation.", _pythagoras),
    Formula("euler", "Euler Identity", "calculus",
            "e^(i*pi) + 1 = 0", "Links e, i, pi, 1 and 0.", _euler_identity),
    Formula("deriv-power", "Power Rule (derivative)", "calculus",
            "d/dx x^n = n*x^(n-1)", "Rate of change of a power function.", _derivative_power),
    Formula("int-power", "Power Rule (integral)", "calculus",
            "integral x^2 dx (0..1) = 1/3", "Area under a power curve.", _integral_power),
    Formula("schwarzschild", "Schwarzschild Radius", "spacetime",
            "r_s = 2GM/c^2", "Radius of a non-rotating black hole event horizon.", _schwarzschild_radius),
    Formula("kruskal", "Kruskal-Szekeres Coordinates", "spacetime",
            "U*V = -(r/2M - 1) * e^(r/2M)", "Maximal extension removing the coordinate singularity at r=2M; the horizon is a coordinate issue, the centre is the true singularity.", _kruskal_u_v),
    Formula("rocket", "Tsiolkovsky Rocket Equation", "physics",
            "dv = ve * ln(m0/mf)", "Velocity change from expelling propellant.", _rocket_equation),
    Formula("ohm-power", "Ohm / Electric Power", "engineering",
            "P = V*I = V^2/R", "Electrical power dissipation.", _ohm_power),
    Formula("logistic", "Logistic Growth", "biology",
            "P = K / (1 + e^(-r*t))", "Population growth capped by carrying capacity K.", _logistic),
    Formula("sir", "SIR Epidemic Model", "medicine-math",
            "dS+dI+dR = 0 (total conserved)", "Susceptible-Infected-Recovered compartment model. A model, not a cure.", _sir_conservation),
    Formula("half-life", "Half-Life / Drug Decay", "medicine-math",
            "A = A0 * 0.5^(t / t_half)", "Exponential decay used in pharmacokinetics dosing maths. Maths only, not dosing advice.", _half_life),
    Formula("bmi", "Body Mass Index", "medicine-math",
            "BMI = kg / m^2", "Population statistic. Not a diagnosis.", _bmi),
    Formula("compound", "Compound Growth", "algebra",
            "A = P*(1+r)^t", "Exponential growth over periods.", _compound_growth),
    Formula("wave", "Wave Speed", "physics",
            "v = f * lambda", "Speed of a wave from frequency and wavelength.", _wave_speed),
    Formula("kinetic", "Kinetic Energy", "physics",
            "KE = 0.5*m*v^2", "Energy of a moving mass.", _kinetic),
    Formula("hardy-weinberg", "Hardy-Weinberg Equilibrium", "biology",
            "p^2 + 2pq + q^2 = 1", "Allele / genotype frequencies in an ideal population.", _hardy_weinberg),
    Formula("michaelis-menten", "Michaelis-Menten Kinetics", "biology",
            "v = Vmax*[S] / (Km + [S])", "Enzyme reaction rate vs substrate concentration.", _michaelis_menten),
    Formula("ideal-gas", "Ideal Gas Law", "science",
            "PV = nRT", "Pressure, volume, moles and temperature of an ideal gas.", _ideal_gas),
    Formula("bayes", "Bayes Theorem", "data-science",
            "P(A|B) = P(B|A)*P(A) / P(B)", "Updating a belief with evidence — core of data science inference.", _bayes),
    Formula("entropy", "Shannon Entropy (fair coin)", "data-science",
            "H = -sum(p * log2 p)", "Information content / uncertainty of a distribution.", _entropy_binary),
    Formula("linreg", "Linear Regression Slope", "data-science",
            "slope = cov(x,y) / var(x)", "Best-fit line slope for paired data.", _linear_regression_slope),
    Formula("robot-fk", "Robot Forward Kinematics (2-link)", "robotics",
            "x = cos(t1) + cos(t1+t2)", "End-effector position from joint angles. Simulation only.", _robot_forward_kinematics),
    Formula("pid", "PID Control (P term)", "robotics",
            "u = Kp * e", "Proportional control output from error. Simulation only.", _pid_step),
    Formula("stopping", "Vehicle Stopping Distance", "transportation",
            "d = v^2 / (2*mu*g)", "Braking distance from speed, friction and gravity.", _stopping_distance),
    Formula("drag", "Aerodynamic Drag Force", "transportation",
            "F = 0.5 * rho * v^2 * Cd * A", "Drag force on a moving vehicle / craft.", _drag_force),
    Formula("ev-range", "EV Range Estimate", "transportation",
            "range = kWh * km/kWh", "Range estimate from battery size and efficiency.", _ev_range),
    Formula("maglev", "Magnetic Levitation Force Balance", "levitation",
            "F = B^2*A / (2*mu0) >= m*g", "Magnetic pressure must beat weight to levitate. Maths / simulation only — no real rig.", _maglev_force_balance),
    Formula("acoustic-lev", "Acoustic Levitation Node Spacing", "levitation",
            "node spacing = lambda / 2", "Standing-wave nodes that can trap tiny particles in simulation / known lab demos.", _acoustic_levitation),
    Formula("binary", "Binary Place Value", "computers",
            "1011b = 8+0+2+1 = 11", "How computers represent numbers.", _binary_place_value),
    Formula("big-o", "Big-O Growth (n log n)", "computers",
            "T = n * log2(n)", "Algorithm cost growth — core computer science maths.", _big_o_growth),
    Formula("moores", "Moore's Law Doubling", "computers",
            "N = N0 * 2^(years/2)", "Historical transistor-density trend, an observation not a law of physics.", _moores_law),
    Formula("softmax", "Softmax (LLM/SLM output)", "llm",
            "softmax(x_i) = e^x_i / sum(e^x)", "Turns model scores into probabilities — used by LLMs and SLMs alike.", _softmax),
    Formula("attention", "Scaled Dot-Product Attention Scale", "llm",
            "Attention = softmax(QK^T / sqrt(d)) * V", "Transformer attention scaling. Formula study only, no model is trained here.", _attention_score),
    Formula("perceptron", "Perceptron (ML origin)", "ml",
            "y = step(w.x + b)", "Single-unit classifier, the building block of ML.", _perceptron),
    Formula("grad-descent", "Gradient Descent Step", "ml",
            "x1 = x0 - lr * grad", "One optimisation step downhill on a loss surface.", _gradient_descent_step),
    Formula("cross-entropy", "Cross-Entropy Loss", "ml",
            "L = -log(p_true)", "Training loss for classifiers / language models.", _cross_entropy),
    Formula("nn-forward", "Neural Net Forward Pass (NNL)", "nnl",
            "a = sigmoid(Wx + b)", "One tiny neural-network layer computed by hand. NNL = neural network layer/lab in this repo.", _nn_forward),
    Formula("capability-ladder", "ANI / AGI / ASI Ladder (rubric)", "ai-ladder",
            "ANI (narrow) < AGI (general) < ASI (super)", "Evaluation rubric / taxonomy only. This lab does NOT build AGI or ASI — it scores concepts against the rubric.", _capability_ladder),
    Formula("avogadro", "Avogadro Atom Count", "atomic",
            "atoms = moles * 6.02214076e23", "Counting atoms / particles from moles.", _avogadro_atoms),
    Formula("proton-charge", "Proton Charge (atomic number)", "atomic",
            "Q = Z * e", "Total proton charge of a nucleus with Z protons.", _proton_charge),
    Formula("hydrogen-level", "Hydrogen Energy Level (Bohr)", "atomic",
            "E_n = -13.6 / n^2 eV", "Electron energy levels in hydrogen.", _hydrogen_level),
    Formula("mass-number", "Atomic Mass Number", "atomic",
            "A = protons + neutrons", "Nucleon count of an isotope, e.g. carbon-12.", _atomic_mass_approx),
    Formula("solar-harvest", "Solar Harvest Power", "natural-resources",
            "P = irradiance * area * efficiency", "Power from sunlight on a panel / collector.", _solar_harvest),
    Formula("hydro-power", "Hydro Power", "natural-resources",
            "P = rho * g * Q * h", "Power from flowing water (density, flow, head height).", _hydro_power),
    Formula("extraction-yield", "Natural Extraction Yield", "natural-medicine",
            "yield% = extracted / raw * 100", "Oil / plant-compound extraction maths. Lab analysis only — not a remedy claim, ingestion is HOLD.", _extraction_yield),
    Formula("glycemic-load", "Glycemic Load (fruit/veg maths)", "nutrition",
            "GL = GI * carbs / 100", "Nutrition maths for fruits / vegetables / meals. Information only, not dietary advice.", _glycemic_load),
    Formula("nutrient-sum", "Nutrient Total (additive labels)", "nutrition",
            "total = sum(per-serving nutrients)", "Adding labelled nutrients across fruits + vegetables in a mix.", _nutrient_sum),
    Formula("oil-energy", "Oil Energy Content", "natural-resources",
            "E = mass * calorific value", "Energy stored in natural oils (~37 MJ/kg class). Fuel/food maths only.", _oil_energy),
    Formula("amdahl", "Amdahl's Law (supercomputer speedup)", "supercomputing",
            "S = 1 / ((1-p) + p/N)", "Parallel speedup limit for a supercomputer job. Simulation only.", _amdahl_speedup),
    Formula("flops-scaling", "Supercomputer FLOPS Scaling", "supercomputing",
            "total = nodes * FLOPS per node", "Aggregate compute from node count.", _flops_scaling),
    Formula("qubit-dim", "Qubit State-Space Dimension", "quantum-computing",
            "dim = 2^n", "State space of n qubits. Local simulation only, no live quantum hardware.", _qubit_dimension),
    Formula("qubit-prob", "Qubit Probability Rule", "quantum-computing",
            "|alpha|^2 + |beta|^2 = 1", "Measurement probabilities must sum to 1.", _qubit_probabilities),
    Formula("grover", "Grover Iteration Count", "quantum-computing",
            "iters ~ (pi/4) * sqrt(N)", "Quantum search iteration estimate. Teaching simulation only.", _grover_iterations),
    Formula("fourier", "Fourier Sine Term Mean", "calculus",
            "mean of sin over a full period = 0", "Basis idea behind Fourier series / signal decomposition.", _fourier_term),
]

BY_ID = {f.id: f for f in FORMULAS}


def verify_all() -> tuple[int, int, list[str]]:
    passed, failed = 0, []
    for f in FORMULAS:
        try:
            ok = bool(f.check())
        except Exception as exc:  # a crashing check is a failed check
            ok, failed = False, failed + [f"{f.id}: {exc}"]
        if ok:
            passed += 1
        elif f.id not in " ".join(failed):
            failed.append(f.id)
    return passed, len(FORMULAS), failed
