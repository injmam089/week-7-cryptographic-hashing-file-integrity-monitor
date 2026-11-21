# Sentinel FIM — Cryptographic File Integrity Monitor

A modular, enterprise-grade File Integrity Monitoring (FIM) tool built in Python using cryptographic SHA-256 hashing to establish filesystem baselines, detect unauthorized file modifications, flag rogue file injections, and alert on deleted assets across monitored directories.

---

## 1. Project Objective

In cybersecurity and system administration, establishing and maintaining filesystem trust is critical. Attackers who gain unauthorized access frequently deploy backdoors, alter configuration files, tamper with source code, or delete audit logs.

**Sentinel FIM** solves this problem by providing automated, high-assurance file integrity monitoring:
* **Establish Cryptographic Baseline**: Recursively scans designated target folders, calculating deterministic SHA-256 checksums in memory-efficient binary streams, and saving the trusted state to `output/baseline.json`.
* **Real-Time Differential Auditing**: Re-scans the target filesystem and performs differential analysis against the baseline to classify files into **`[OK] INTACT`**, **`[ALERT] CREATED`**, **`[ALERT] MODIFIED`**, and **`[ALERT] DELETED`**.
* **Automation & CI/CD Readiness**: Emits standardized exit codes (`0` for verified clean, `1` for compromised state) to enable integration into automated security pipelines, SIEM collectors, and cron/scheduler jobs.

---

## 2. Cryptographic Security: Why SHA-256 over MD5 and SHA-1?

Sentinel FIM mandates **SHA-256 (Secure Hash Algorithm 256-bit)**, standardized under NIST FIPS 180-4, and strictly rejects obsolete legacy algorithms like MD5 and SHA-1.

### 2.1 Collision Resistance Comparison

A cryptographic hash function possesses *collision resistance* if it is computationally infeasible to find any two distinct inputs $x \neq y$ such that:

$$H(x) = H(y)$$

* **MD5 (Message Digest 5 - Broken)**:
  * Digest length: 128 bits.
  * In 2004, Xiaoyun Wang et al. demonstrated practical collision attacks against MD5. By 2005, rogue MD5 collisions could be generated in seconds on commodity hardware. Attackers can produce two executables with identical MD5 checksums where one is benign and the other contains malicious shellcode.
* **SHA-1 (Secure Hash Algorithm 1 - Broken)**:
  * Digest length: 160 bits.
  * In 2017, researchers from CWI Amsterdam and Google announced the **SHAttered** attack, generating two distinct PDF documents with identical SHA-1 hashes in $2^{63.1}$ evaluations. In 2020, chosen-prefix collision attacks on SHA-1 were demonstrated. NIST officially mandated phasing out SHA-1 by December 31, 2030.
* **SHA-256 (Secure Hash Algorithm 256-bit - Secure)**:
  * Digest length: 256 bits.
  * SHA-256 yields $2^{256} \approx 1.1579 \times 10^{77}$ possible hash states. Under the Birthday Paradox, finding a collision requires on the order of $2^{128}$ evaluations—an astronomical workload that remains computationally infeasible across all foreseeable classical computing systems.

### 2.2 Pre-Image and Second Pre-Image Security

Beyond collision resistance, file integrity monitoring relies on:
1. **Pre-Image Resistance (One-Way Property)**: Given a hash digest $h$, it is computationally infeasible to find an input $m$ such that $H(m) = h$.
2. **Second Pre-Image Resistance (Weak Collision Resistance)**: Given a specific input $m_1$, it is computationally infeasible to find another input $m_2 \neq m_1$ such that $H(m_1) = H(m_2)$.

In an adversarial FIM scenario, second pre-image resistance is paramount: if an attacker modifies or replaces a monitored system file, they must not be able to generate or craft an altered file that produces the exact same hash as the original baseline entry.
* **MD5 and SHA-1**: Significant security margin reduction, vulnerability to length extension, and collision-assisted pre-image compromises make them unacceptable for security-critical integrity monitoring.
* **SHA-256**: Provides a full 256-bit second pre-image security level ($2^{256}$ operations), ensuring that no modified file can forge a matching baseline digest.

### 2.3 The Cryptographic Avalanche Effect

A core security property of SHA-256 is the **avalanche effect**: altering even a single bit or character in an input file produces an entirely uncorrelated, pseudorandomly distributed 256-bit output hash.

**Real Test Demonstration (`monitored/sample.txt`):**
* **Original Content** (`... Clean / Unmodified.`):
  `f48a80cbb4a4cb88448a55a84eb5e04420dd0ba7db0893852fd41351f6aabc52`
* **Altered 1 Character** (`... Clean / Xnmodified.`):
  `83bc51ff1476f0b684125e163ef0cde975df69dc99167e0798a657ed30d0f5d6`

A single character modification changed 100% of the hex representation, instantly triggering an integrity breach alert.

---

## 3. Project Architecture

The repository is structured following Single Responsibility and Separation of Concerns principles:

```text
sentinel-fim/
├── src/
│   ├── __init__.py            # Package initialization & exports
│   ├── hasher.py              # Authoritative descriptor-bound SHA-256 scanner & TOCTOU guard
│   ├── baseline.py            # BaselineManager: atomic persistence & schema validation
│   ├── integrity_checker.py   # IntegrityChecker: differential analysis & anomaly classification
│   └── fim_monitor.py         # Primary CLI entrypoint, argument parsing, & terminal reporting
├── config/
│   └── fim_config.json        # Operational configuration (paths, algorithm)
├── monitored/                 # Sample monitored directory target
│   ├── documents/
│   │   └── guide.txt          # Synthetic nested sample file
│   └── sample.txt             # Synthetic root sample file for tamper testing
├── output/                    # Baseline storage (isolated from monitored directory)
│   ├── .gitkeep
│   └── baseline.json          # Cryptographic baseline mapping
├── tests/                     # Comprehensive automated unit & integration test suite
│   ├── __init__.py
│   ├── test_hasher.py         # 19 tests: streaming, chunks, stability, symlink rejection
│   ├── test_baseline.py       # 16 tests: generation, atomic save, schema validation
│   ├── test_integrity_checker.py # 13 tests: intact, created, modified, deleted, scan errors
│   └── test_fim_monitor.py    # 11 tests: CLI args, exit codes, config loading, tamper workflow
├── .gitignore                 # Version control exclusion rules (.venv/, .dist/, __pycache__/)
├── requirements.txt           # Standard library only (zero third-party bloat)
└── README.md                  # Comprehensive technical documentation & tamper proofs
```

### Key Architectural Safeguards:
* **Baseline Storage Isolation**: `baseline.json` is stored strictly in `output/` (outside `monitored/`) to prevent self-referential hashing loops or recursive hash tampering.
* **Descriptor-Bound Hashing**: Hashing uses low-level file descriptors (`os.open` with `O_RDONLY | O_NOFOLLOW` and `os.fstat`) to defend against Time-Of-Check to Time-Of-Use (TOCTOU) file substitution attacks.
* **Chunked Streaming**: Files are read in fixed 4 KB (4096-byte) binary streams, preventing memory exhaustion on large files.
* **Atomic Persistence**: Baselines are saved via temporary files and `os.replace()` to prevent file corruption if interrupted.
* **Cross-Platform Path Normalization**: Files are indexed using normalized POSIX relative paths, ensuring baseline portability between Windows, Linux, and macOS.

---

## 4. Configuration

The default configuration is maintained in `config/fim_config.json`:

```json
{
  "algorithm": "sha256",
  "monitored_directory": "monitored",
  "baseline_file": "output/baseline.json"
}
```

CLI flags can override any configuration setting at runtime.

---

## 5. Usage Guide: Baseline vs. Monitor Mode

Sentinel FIM provides two operational modes via `src/fim_monitor.py`.

### 5.1 Baseline Mode (`--mode baseline`)

Establishes a new, trusted cryptographic snapshot of all files within the monitored folder.

#### Syntax:
```bash
python src/fim_monitor.py --mode baseline [--dir <PATH>] [--baseline <PATH>] [--config <PATH>]
```

#### What It Does:
1. Recursively discovers all regular files in the target directory (rejecting symlinks).
2. Computes the SHA-256 digest for each file using descriptor-bound streaming.
3. Validates that every digest is a 64-character lowercase hex string.
4. Atomically serializes the mapping to `output/baseline.json`.
5. Returns exit code `0` on success, or `1` on error.

#### Sample Terminal Output:
```text
=================================================================
 SENTINEL FIM -- BASELINE SNAPSHOT GENERATION
=================================================================
[*] Timestamp           : 2026-11-22 01:42:28
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

---

### 5.2 Monitor Mode (`--mode monitor`)

Performs an integrity verification audit by recalculating current hashes and comparing them against `output/baseline.json`.

#### Syntax:
```bash
python src/fim_monitor.py --mode monitor [--dir <PATH>] [--baseline <PATH>] [--config <PATH>]
```

#### What It Does:
1. Reads and validates the baseline database from `output/baseline.json`.
2. Rescans the monitored folder in real time, computing live SHA-256 digests.
3. Performs set-differential analysis to identify anomalies:
   * **`[ALERT] CREATED:`** Files present on disk but absent from baseline.
   * **`[ALERT] MODIFIED:`** Files present in both but with differing SHA-256 digests.
   * **`[ALERT] DELETED:`** Files recorded in baseline but missing from disk.
   * **`[OK] INTACT:`** Files matching baseline exactly (displayed when verified).
4. Returns:
   * **Exit Code `0`**: System intact — all files verified against baseline.
   * **Exit Code `1`**: System compromised — one or more anomalies or scan errors detected.

#### Sample Clean Verification Output:
```text
=================================================================
 SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT
=================================================================
[*] Timestamp           : 2026-11-22 01:42:42
[*] Monitored Directory : monitored
[*] Reference Baseline  : output/baseline.json
-----------------------------------------------------------------
[OK] INTACT:    monitored/documents/guide.txt
[OK] INTACT:    monitored/sample.txt
-----------------------------------------------------------------
AUDIT SUMMARY:
  Baseline Files : 2
  Current Files  : 2
  Intact Files   : 2
  Created Files  : 0
  Modified Files : 0
  Deleted Files  : 0
-----------------------------------------------------------------
[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.
=================================================================
```

---

## 6. Real Tamper Simulation Test & Terminal Proof

A real multi-vector tamper simulation was executed in the terminal to verify Sentinel FIM's detection capabilities across all three anomaly types simultaneously.

### 6.1 Simulation Steps

#### Step 1: Establish Initial Trusted Baseline
```bash
python src/fim_monitor.py --mode baseline
```

#### Step 2: Introduce Tampering Vectors
```powershell
# Windows PowerShell:

# 1. MODIFIED: Alter 1 character in an existing monitored file
(Get-Content "monitored/sample.txt") -replace "Clean / Unmodified.", "Clean / Xnmodified." | Set-Content "monitored/sample.txt"

# 2. CREATED: Inject a rogue/unauthorized file
Set-Content -Path "monitored/rogue_file.txt" -Value "[UNAUTHORIZED] Rogue intruder payload injected at runtime."

# 3. DELETED: Remove an existing monitored document
Remove-Item -Path "monitored/documents/guide.txt"
```

*(Linux/macOS equivalent commands)*:
```bash
# sed -i 's/Clean \/ Unmodified./Clean \/ Xnmodified./' monitored/sample.txt
# echo "[UNAUTHORIZED] Rogue intruder payload injected at runtime." > monitored/rogue_file.txt
# rm monitored/documents/guide.txt
```

#### Step 3: Run Monitor Mode to Detect Tampering
```bash
python src/fim_monitor.py --mode monitor
```

---

### 6.2 Exact Captured Terminal Output

```text
=================================================================
 SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT
=================================================================
[*] Timestamp           : 2026-11-22 01:43:05
[*] Monitored Directory : monitored
[*] Reference Baseline  : output/baseline.json
-----------------------------------------------------------------
[ALERT] CREATED:  monitored/rogue_file.txt
        SHA-256: 4717f6f03fc93c6b6fd0919c2ae8baa875d369edfbea897c6ce2a85786f026fe
[ALERT] MODIFIED: monitored/sample.txt
        Baseline SHA-256: f48a80cbb4a4cb88448a55a84eb5e04420dd0ba7db0893852fd41351f6aabc52
        Current  SHA-256: 83bc51ff1476f0b684125e163ef0cde975df69dc99167e0798a657ed30d0f5d6
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

*Process exited with code `1` (anomalies detected).*

---

### 6.3 Restoration & Clean Re-Verification

After the simulation, the sample monitored folder was restored to its trusted state:

```powershell
# Revert 1-character alteration
(Get-Content "monitored/sample.txt") -replace "Clean / Xnmodified.", "Clean / Unmodified." | Set-Content "monitored/sample.txt"

# Remove rogue file
Remove-Item -Path "monitored/rogue_file.txt"

# Restore deleted document
git checkout -- monitored/documents/guide.txt

# Run monitor mode to verify clean state
python src/fim_monitor.py --mode monitor
```

**Restored Output Proof:**
```text
=================================================================
 SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT
=================================================================
[*] Timestamp           : 2026-11-22 01:43:52
[*] Monitored Directory : monitored
[*] Reference Baseline  : output/baseline.json
-----------------------------------------------------------------
[OK] INTACT:    monitored/documents/guide.txt
[OK] INTACT:    monitored/sample.txt
-----------------------------------------------------------------
AUDIT SUMMARY:
  Baseline Files : 2
  Current Files  : 2
  Intact Files   : 2
  Created Files  : 0
  Modified Files : 0
  Deleted Files  : 0
-----------------------------------------------------------------
[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.
=================================================================
```

*Process exited with code `0` (clean verification).*

---

## 7. Automated Test Suite

Sentinel FIM includes an exhaustive unit and integration test suite with 59 test cases covering every module:

```bash
python -m unittest discover tests -v
```

### Test Coverage Summary:
* **`tests/test_hasher.py` (19 tests)**:
  * Stream-based SHA-256 hashing in 4 KB chunks.
  * Descriptor stability (`fstat` vs `lstat`) and metadata tracking.
  * Rejection of symbolic links and non-regular files (`O_NOFOLLOW`).
  * Confinement checks (paths escaping root).
* **`tests/test_baseline.py` (16 tests)**:
  * Recursive directory scanning and baseline dictionary generation.
  * Atomic persistence via temporary file swap (`os.replace`).
  * Cryptographic schema validation (64-char lowercase hex regex).
  * Error surfacing (refusal to generate baseline on unreadable files).
* **`tests/test_integrity_checker.py` (13 tests)**:
  * Differential comparison (`intact`, `created`, `modified`, `deleted`).
  * Normalization parity for legacy and POSIX paths.
  * Scan error propagation (unreadable files prevent false-clean status).
* **`tests/test_fim_monitor.py` (11 tests)**:
  * CLI argument parsing (`--mode baseline`, `--mode monitor`).
  * Configuration fallback and custom config loading.
  * Exit code verification (`0` on clean, `1` on anomaly/error).
  * Full end-to-end multi-anomaly tamper workflow.

---

## 8. Version Control Hygiene (.gitignore)

The repository's `.gitignore` excludes non-source runtime and build artifacts:
* `.venv/` and `venv/` (Python virtual environments)
* `.dist/`, `dist/`, `build/`, and `*.egg-info/` (Packaging and binary distributions)
* `__pycache__/` and `*.pyc` (Bytecode caches)
* `.env` (Environment configurations)
* `!output/baseline.json` (Explicit tracking exception ensuring baseline database is preserved in Git)

---

## 9. Conclusion & Readiness

Sentinel FIM fulfills all Week 7 File Integrity Monitoring requirements:
1. **Cryptographic Integrity**: SHA-256 chunked streaming, collision resistance, pre-image security.
2. **Operational Capabilities**: Baseline generation, live monitoring, multi-anomaly detection (`CREATED`, `MODIFIED`, `DELETED`).
3. **Robust Engineering**: DRY modular architecture, atomic persistence, TOCTOU defenses, and 59 automated unit tests.
4. **Git Hygiene**: Clean working tree, all required ignore patterns active.
