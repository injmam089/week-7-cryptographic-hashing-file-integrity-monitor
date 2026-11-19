# Sentinel FIM — File Integrity Monitor

A modular, lightweight File Integrity Monitoring (FIM) tool built in Python using cryptographic SHA-256 hashing to verify file integrity, detect unauthorized modifications, and flag anomalies across monitored directories.

---

## 1. Project Objective

The objective of **Sentinel FIM** is to provide automated detection of unauthorized filesystem modifications, file tampering, injections, and deletions within designated target directories. By establishing a cryptographically verified baseline state, Sentinel FIM enables security analysts and administrators to rapidly audit and detect indicators of compromise (IoC) or accidental alterations.

---

## 2. SHA-256 File Integrity Monitoring

File Integrity Monitoring relies on cryptographic hash functions to produce a unique, deterministic digital fingerprint for every file:

* **Algorithm**: SHA-256 (Secure Hash Algorithm 256-bit), standard under FIPS 180-4.
* **Collision Resistance**: Computationally infeasible for two distinct files to yield the identical SHA-256 digest ($2^{256}$ potential state space).
* **Avalanche Effect**: Modifying even a single character or byte in a monitored file completely alters its resulting SHA-256 checksum.
* **Mechanism**:
  1. A trusted snapshot (baseline) records relative file paths paired with their SHA-256 digests.
  2. Subsequent verification passes re-hash current files in 64 KB memory-efficient streams.
  3. Mismatches against the baseline immediately classify files into **INTACT**, **MODIFIED**, **ADDED**, or **DELETED**.

---

## 3. Project Architecture

```text
sentinel-fim/
│
├── src/
│   ├── __init__.py            # Package initialization and metadata
│   ├── fim_monitor.py         # Primary orchestration entrypoint & CLI
│   ├── hasher.py              # Cryptographic hashing engine (SHA-256)
│   ├── baseline.py            # Baseline database creation and persistence
│   └── integrity_checker.py   # Integrity comparison & anomaly detection
│
├── config/
│   └── fim_config.json        # FIM operational configuration
│
├── monitored/                 # Monitored directory target
│   ├── documents/
│   │   └── guide.txt          # Synthetic nested sample data
│   └── sample.txt             # Synthetic sample data for tamper testing
│
├── output/                    # Baseline & audit report storage
│   └── .gitkeep
│
├── tests/                     # Unit and integration test suite
│   └── __init__.py
│
├── screenshots/               # Visual proof and operational logs
│   └── .gitkeep
│
├── .gitignore                 # Version control exclusion rules
├── requirements.txt           # Dependency declaration (Standard library)
└── README.md                  # Project documentation
```

### Architecture Principles:
- **Baseline Isolation**: `baseline.json` is stored strictly in `output/` (outside `monitored/`) to prevent recursive hashing loops or self-tampering.
- **Portability**: All file records use relative paths, ensuring cross-platform and environment independence.
- **Minimal Footprint**: Operates exclusively with Python's standard library without bloated third-party dependencies.
- **Windows 11 Compatibility**: Native support for Windows path separators and file permission semantics.

---

## 4. Configuration

Sentinel FIM is configured via `config/fim_config.json`:

```json
{
  "algorithm": "sha256",
  "monitored_directory": "monitored",
  "baseline_file": "output/baseline.json"
}
```

---

## 5. Technology Stack

* **Language**: Python 3.10+ (tested on Python 3.14)
* **Standard Library**:
  * `hashlib`: Cryptographic SHA-256 hashing
  * `json`: Baseline database and configuration serialization
  * `pathlib` / `os`: Cross-platform filesystem navigation
  * `sys`: Process management and exit codes
  * `datetime`: Event timestamps and audit records
* **Third-Party Dependencies**: None (Standard Library only)

---

## 6. Planned Features

* **Phase 1 — Core Hashing & Baseline Engine**:
  * Chunked stream hashing for large files.
  * Recursive directory crawler with path normalization.
  * Baseline snapshot generation saved to `output/baseline.json`.
* **Phase 2 — Real-Time / Periodic Integrity Verification**:
  * Real-time verification comparing live files against baseline.
  * Categorization of files: `INTACT`, `MODIFIED`, `ADDED`, `DELETED`.
* **Phase 3 — Alerting & Audit Logging**:
  * Colorized terminal alerts.
  * Structured logging with timestamped security events.
* **Phase 4 — Automated Testing & Edge Case Hardening**:
  * Unit tests for corrupted files, empty files, and permission errors.
  * Tamper simulation scripts.

---

## 7. Current Status: Phase 0

* **Status**: **Phase 0 — Project Foundation (Completed)**
* **Current State**:
  * Project tree initialized with modular source packages.
  * Configuration schema defined and validated.
  * Harmless synthetic sample files deployed for testing.
  * Exclusion rules established (`.gitignore` protects secrets and temp files while preserving `baseline.json`).
  * Full FIM detection engine and baseline generation will commence in **Phase 1** upon developer review.
