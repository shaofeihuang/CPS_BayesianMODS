# Bayesian and Multi-Objective Decision Support for Real-Time Cyber-Physical Incident Mitigation - Project Repository

## Overview

This repository implements a Bayesian multi-objective decision support framework for real-time cyber-physical incident mitigation. It integrates AutomationML-based CPS modeling with Bayesian Networks (BNs) to enable probabilistic risk assessment across cybersecurity, reliability, and safety dimensions. The framework supports dynamic threat analysis for critical infrastructure, including industrial control systems, distributed energy resources, and railway signalling systems.

This repository accompanies the paper: ["Bayesian and Multi-Objective Decision Support for Real-Time Cyber-Physical Incident Mitigation"](https://arxiv.org/abs/2509.00770).

---

## Repository Contents

### Main Scripts

- **`AML_Bayesian.py`** — Performs BN-based CPS risk assessment on an AutomationML model, computing probabilities of failure and system-level impact.

- **`Optuna_Concurrent_3D.py`** — Multi-objective optimization tool for decision support using the [Optuna library](https://optuna.org).

### Reference Materials

- **`Reference Data Sheet.pdf`** — Data and formulae used in the project for risk assessment and probability calculations.
- **`Examples/`** - AutomationML models representing CPS architectures and attack scenarios. GeNIE (xdsl) sample.
- **`Figures/`** — High-resolution versions of figures from the paper.

---

## Usage

### Requirements

- Python 3.12+ (tested on Python 3.12.8)
- Required libraries: `pgmpy`, `optuna` (for optimization scripts)

Install dependencies:
```bash
pip install pgmpy optuna
```

### Example Run

To execute a risk assessment on the generic CPS model:
```bash
python AML_Bayseian.py -i GenericCPS.aml
```

For multi-objective decision optimization:
```bash
python Optuna_Concurrent_3D.py -i SolarPV.aml
```

---

## Contribution and Contact

Contributions, feedback, and collaboration inquiries are welcome. For questions or suggestions, please open an issue or contact the repository maintainer via GitHub.

---

## License

Please refer to the repository for license information.
