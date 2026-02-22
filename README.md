
# Linux Attacker Timeline Detection Engine

[![CI](https://github.com/djbpm/linux-attacker-timeline/actions/workflows/ci.yml/badge.svg)]()
[![CodeQL](https://github.com/djbpm/linux-attacker-timeline/actions/workflows/codeql.yml/badge.svg)]()
![License](https://img.shields.io/badge/license-MIT-blue)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)

A modular, pipeline-based Linux detection engine that reconstructs attacker kill chains from raw system logs and maps activity to MITRE ATT&CK techniques.

This project focuses on multi-stage attack detection, structured logging, and deterministic rule execution within a clean, extensible architecture.

---

## Purpose

Attackers operate in sequences — not isolated events.

This engine is designed to:

- Ingest Linux authentication & system logs
- Normalize raw log lines into structured event objects
- Apply rule-based detection logic
- Generate severity-classified alerts
- Correlate related alerts into multi-stage attack chains
- Map detections to MITRE ATT&CK tactics & techniques
- Reconstruct attacker activity timelines

The goal is to simulate a lightweight SOC-grade detection pipeline with clean architecture and CI-backed validation.

---

## Architecture

The engine follows a structured pipeline:
Log Input
↓
Collection
↓
Normalization
↓
Detection Engine
↓
Correlation Engine
↓
MITRE Mapping
↓
Timeline Builder
↓
Output Renderer
---
Each stage is isolated by responsibility, allowing independent testing and future extensibility.

---

## 📁 Project Structure
---

# 🧠 System Architecture

The engine follows a deterministic, stage-isolated detection pipeline.

```mermaid
flowchart TD

A[Log File Input]
B[Collection Layer]
C[Normalization Layer]
D[Rule Engine]
E[Alert Aggregation]
F[Correlation Engine]
G[MITRE ATT&CK Mapping]
H[Timeline Builder]
I[Output Renderer]

A --> B
B --> C
C --> D
D --> E
E --> F
F --> G
G --> H
H --> I

linux-attacker-timeline/
│
├── src/
│   ├── cli.py                  # CLI entry point
│   │
│   ├── parser/                 # Raw log ingestion
│   ├── normalizer/             # Event normalization layer
│   │
│   ├── detection/
│   │   ├── rule_engine.py      # Rule execution core
│   │   ├── rule_registry.py    # Rule loading & registration
│   │   └── rules/              # Individual detection rules
│   │
│   ├── correlation/            # Multi-stage attack correlation
│   ├── timeline/               # Chronological reconstruction
│   ├── output/                 # CLI & JSON rendering
│   └── utils/                  # Logging & shared utilities
│
└── tests/                      # Pytest validation suite
## Detection Capabilities

Currently implemented detections include:

- SSH Brute Force Success
- Suspicious Login After Multiple Failures
- Sudo Privilege Escalation
- Reverse Shell Execution
- Cron-Based Persistence
- Log Tampering Detection
- Unauthorized User Creation
- Multi-Stage Attack Correlation
- MITRE ATT&CK Technique Mapping
- Timeline Reconstruction

Example correlated attack chain:
Brute Force
→ Successful Login
→ Privilege Escalation
→ Reverse Shell
→ Persistence
→ Log Tampering

This enables detection of attacker progression instead of isolated alerts.

---

## Engine Observability

The engine includes:

- Structured logging
- Log-level controls (DEBUG / INFO / WARNING / ERROR)
- Stage-based debug summaries
- Execution timing instrumentation
- Alert count aggregation
- Correlated incident summaries

Example pipeline output:

DEBUG | Parsed 17 events
DEBUG | Loaded 7 detection rules
DEBUG | Generated 7 alerts
DEBUG | Generated 1 correlated incident

---

## Design Principles

- Modular pipeline architecture
- Clear separation of parsing, detection, and correlation
- Deterministic rule-based evaluation
- Multi-stage attack awareness
- MITRE ATT&CK alignment
- Extensible rule framework
- CI-driven validation

---

## 🖥 Usage

### Clone Repository

```bash
git clone https://github.com/djbpm/linux-attacker-timeline
cd linux-attacker-timeline


### 2️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Detection Engine

```bash
python -m src.cli --input src/sample.log
```
### Optional flags

python -m src.cli --input src/sample.log --output json
python -m src.cli --input src/sample.log --log-level DEBUG

### 4️⃣ Run Test Suite

```bash
pytest
```

Current Status

Phase 1 – Detection Ladder: Complete
Completed:
	•	Detection rule framework
	•	Alert aggregation
	•	Multi-stage correlation (basic implementation)
	•	MITRE mapping
	•	Structured logging
	•	Debug instrumentation
	•	CLI interface
	•	CI validation

  Phase 2 Roadmap
	•	Intelligence-driven multi-stage correlation
	•	Enhanced JSON export schema
	•	Plugin-based rule architecture
	•	CI stability improvements
	•	Expanded test coverage

License

MIT License

Author

Kailas
sunsetmachine
