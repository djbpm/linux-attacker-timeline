# Linux Attacker Timeline Detection Engine

A modular log analysis and detection framework that reconstructs attacker activity timelines and maps findings to MITRE ATT&CK techniques.

## Architecture
The detection engine follows a modular pipeline-based architecture.

Each stage is isolated by responsibility, allowing independent testing,
extension, and rule evolution without breaking upstream or downstream logic.

### Design Principles

- Separation of concerns between parsing, detection, and rendering
- Deterministic rule-based detection logic
- MITRE ATT&CK alignment for structured threat mapping
- Test-driven validation using pytest and CI
- Extensible rule engine for future plugin support

## System Flow

```mermaid
graph TD
    A[Log File Input] --> B[Collection]
    B --> C[Normalization]
    C --> D[Correlation]
    D --> E[Detection Engine]
    E --> F[MITRE Mapping]
    F --> G[Timeline Builder]
    G --> H[Output Renderer]
```

### Component Responsibilities

**Collection**
- Ingests raw log input
- Handles file loading and basic validation

**Normalization**
- Transforms raw log lines into structured event objects
- Ensures consistent schema for downstream processing

**Correlation**
- Links related events into logical attack chains
- Enables multi-stage attack detection

**Detection Engine**
- Applies rule-based logic to normalized events
- Produces alert objects with severity classification

**MITRE Mapping**
- Maps detection results to MITRE ATT&CK techniques
- Adds tactic and technique context

**Timeline Builder**
- Orders correlated events chronologically
- Reconstructs attacker activity flow

**Output Renderer**
- Formats alerts and timelines for CLI output
- Future support: JSON export / SIEM integration


## Detection Capabilities

- Brute Force Login Detection (T1110)
- Suspicious Tool Transfer (T1105)
- Multi-Stage Attack Correlation
- Timeline Reconstruction
- MITRE ATT&CK Technique Mapping

## Usage


### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Detection Engine

```bash
python -m src.cli --input src/sample.log
```

### Run Test Suite

```bash
pytest
```

### Example Output

```
[ALERT] Brute Force Login Attempt
Severity: high
MITRE Technique: T1110 - Brute Force
Tactic: Credential Access
```




## Project Structure

src/
+-- collector/
+-- correlator/
+-- detection/
+-- intel/
+-- normalizer/
+-- output/
+-- timeline/

## Design Principles

- Modular detection engine
- Pattern-based correlation
- Frequency-aware detection logic
- MITRE ATT&CK alignment
- Extensible rule framework

## Roadmap

- JSON export support
- Unit test coverage
- Structured logging
- CI pipeline
- Plugin rule system

Author: Kailas
