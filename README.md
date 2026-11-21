# 🛡️ Week 7 — Cryptographic Hashing & File Integrity Monitoring (FIM)

<p align="center">

<img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python&logoColor=white" />
<img src="https://img.shields.io/badge/Crypto-SHA--256-red?style=for-the-badge&logo=letsencrypt&logoColor=white" />
<img src="https://img.shields.io/badge/Security-FIM-purple?style=for-the-badge&logo=shield&logoColor=white" />
<img src="https://img.shields.io/badge/JSON-Baseline-black?style=for-the-badge&logo=json&logoColor=white" />
<img src="https://img.shields.io/badge/Tests-59%20Passing-brightgreen?style=for-the-badge&logo=pytest&logoColor=white" />

</p>

<p align="center">
  <strong>Python-Based Cryptographic File Integrity Monitoring & Tamper Detection Engine</strong>
</p>

<p align="center">
  GetIntern — 8-Week Cybersecurity Internship | Month 2: Applied Cryptography & Integrity Verification | Week 7
</p>

---

## 📌 Project Overview

This project implements **Sentinel FIM**, a lightweight **File Integrity Monitor (FIM)** built in Python to detect unauthorized file modifications, additions, and deletions across critical directories.

The tool recursively traverses a target directory, computes **SHA-256** cryptographic checksums using memory-efficient 4 KB chunk streaming, and stores a clean fingerprint map in `output/baseline.json`. On subsequent audits, it recalculates live hashes and compares them against the trusted baseline to flag anomalies immediately.

The implementation follows a practical defensive-security workflow:

> **Traverse → Hash (SHA-256) → Baseline → Monitor → Diff → Alert**

The tool supports two core operational modes:

- **Baseline Mode (`--mode baseline`):** Generates a clean cryptographic snapshot of the target directory and atomically writes it to `output/baseline.json`.
- **Monitor Mode (`--mode monitor`):** Recalculates live SHA-256 digests, compares them against `output/baseline.json`, flags `CREATED`, `MODIFIED`, and `DELETED` files, and returns exit code `0` (intact) or `1` (compromised) for CI/CD and automation pipelines.

---

## 🎯 Objectives

The main objectives of this task were:

1. Understand how cryptographic hash functions verify file integrity and detect tampering.
2. Recursively traverse a target directory and compute SHA-256 checksums using Python's standard library.
3. Persist a clean baseline fingerprint map in JSON format (`output/baseline.json`) using atomic writes.
4. Compare live directory states against the saved baseline to detect `CREATED`, `MODIFIED`, and `DELETED` files.
5. Validate detection accuracy through a controlled 3-vector tamper simulation test.
6. Document the cryptographic rationale for choosing SHA-256 over deprecated algorithms like MD5 and SHA-1.
7. Verify reliability with an automated unit test suite.

---

## 🧠 What is File Integrity Monitoring (FIM)?

**File Integrity Monitoring (FIM)** is an internal security control that validates the integrity of operating system files, application code, and configuration files by comparing their current state against a known, trusted baseline.

Attackers frequently modify web shells, configuration files, or system binaries to establish persistence. FIM helps defenders detect:

- **Unauthorized Modifications (`MODIFIED`):** Subtle tampering, such as altering a single character in a config file or injecting malicious code.
- **Rogue Additions (`CREATED`):** Newly dropped payloads, backdoors, or unauthorized scripts.
- **Suspicious Deletions (`DELETED`):** Removal of critical logs, security policies, or application files.

---

## 🔐 Cryptographic Rationale: Why SHA-256 over MD5 / SHA-1?

Sentinel FIM strictly enforces **SHA-256** (part of the SHA-2 family) rather than deprecated algorithms like **MD5** or **SHA-1**:

| Property | MD5 (Deprecated) | SHA-1 (Deprecated) | SHA-256 (Used Here) |
|---|---|---|---|
| **Digest Size** | 128-bit | 160-bit | 256-bit (64 hex chars) |
| **Collision Resistance** | Broken (Wang et al., 2004/2005) | Broken (SHAttered, 2017; $2^{63.1}$ ops) | Secure ($2^{128}$ work factor) |
| **Pre-Image Security** | Weak / Deprecated | Deprecated | Secure ($2^{256}$ work factor) |
| **FIM Suitability** | ❌ Unsafe | ❌ Unsafe | ✅ Industry Standard |

### Key Security Properties
- **Collision Resistance:** MD5 and SHA-1 are cryptographically broken—attackers can practically generate two different files (one legitimate, one malicious) that share the exact same hash, bypassing integrity checks. SHA-256 has no known practical collision attacks.
- **Pre-Image & Second Pre-Image Security:** With a $2^{256}$ work factor, it is computationally infeasible for an attacker to reverse-engineer a file from its digest or craft a tampered file that matches an existing baseline hash.
- **Avalanche Effect:** Changing even a single bit or character in a monitored file (e.g., `Unmodified.` → `Xnmodified.`) completely transforms the resulting 256-bit digest, guaranteeing immediate detection.

---

## 🏗️ Environment

| Component | Details |
|---|---|
| Operating System | Windows 11 (Cross-platform path normalization supported) |
| Language | Python 3.10+ |
| Hash Algorithm | SHA-256 (`hashlib`, 4096-byte chunk streaming) |
| Storage Format | JSON (`output/baseline.json`) with atomic `os.replace` writes |
| Testing | Python `unittest` (59 automated tests) |
| Editor | Visual Studio Code |
| Version Control | Git & GitHub |
| Training | GetIntern Cybersecurity Internship |
| Task | Week 7 — Cryptographic Hashing & File Integrity Monitoring (FIM) |

---

## 🛠️ Tools & Python Modules Used

- **`hashlib`** — Computing SHA-256 cryptographic digests.
- **`os` / `pathlib`** — Low-level file descriptor streaming, atomic writes (`os.replace`), and cross-platform path normalization.
- **`json`** — Serializing and validating the `baseline.json` fingerprint map.
- **`argparse`** — Command-line interface for `--mode`, `--dir`, `--baseline`, and `--config`.
- **`datetime` & `sys`** — UTC/local audit timestamps and process exit codes (`0` / `1`).
- **`unittest`** — Automated verification across all modules.

The project uses only Python standard-library modules. **No third-party packages are required.**

---

## 📁 Project Structure

```text
week-7-cryptographic-hashing-file-integrity-monitor/
│
├── src/
│   └── fim_monitor.py          # Main CLI entry point (Baseline & Monitor modes)
│
├── monitored/                  # Sample target directory for testing
│   ├── sample.txt
│   └── documents/
│       └── guide.txt
│
├── output/
│   └── baseline.json           # Generated SHA-256 cryptographic baseline
│
├── tests/
│   └── test_fim_monitor.py     # Automated unit test suite (59 tests total)
│
├── .gitignore
└── README.md
```

---

## 🏛️ Integrity Monitoring Workflow

```text
                 Monitored Directory
                          │
                          ▼
            Recursive File Discovery
                          │
                          ▼
        4 KB Chunk Streaming & SHA-256 Hash
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
       [Baseline Mode]         [Monitor Mode]
              │                       │
              ▼                       ▼
     Atomic Write JSON      Load output/baseline.json
   (output/baseline.json)             │
                                      ▼
                            Set-Differential Diff
                       (CREATED / MODIFIED / DELETED)
                                      │
                                      ▼
                         Audit Report + Exit Code (0/1)
```

---

## ▶️ How to Run

### Requirements
- Python 3.10 or newer
- No external packages required

### 1. Clone the Repository
```bash
git clone [https://github.com/injmam089/week-7-cryptographic-hashing-file-integrity-monitor.git](https://github.com/injmam089/week-7-cryptographic-hashing-file-integrity-monitor.git)
cd week-7-cryptographic-hashing-file-integrity-monitor
```

### 2. Generate a Clean Baseline (`--mode baseline`)
```bash
python src/fim_monitor.py --mode baseline --dir monitored --baseline output/baseline.json
```

### 3. Run Integrity Verification (`--mode monitor`)
```bash
python src/fim_monitor.py --mode monitor --dir monitored --baseline output/baseline.json
```

### CLI Arguments
| Argument | Purpose |
|---|---|
| `--mode` | Execution mode: `baseline` (record hashes) or `monitor` (verify integrity) |
| `--dir` | Path to the target directory to monitor (default: `monitored`) |
| `--baseline` | Path to the JSON baseline file (default: `output/baseline.json`) |
| `--config` | Optional configuration file path |

---

## 🧪 Tamper Simulation & Verification

### A. Clean Baseline Generation
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

### B. Controlled Tampering Vectors Injected
1. **MODIFIED:** Altered a single character in `monitored/sample.txt` (`Unmodified.` → `Xnmodified.`).
2. **CREATED:** Added an unauthorized rogue file `monitored/rogue_file.txt`.
3. **DELETED:** Removed existing nested file `monitored/documents/guide.txt`.

### C. Live Audit Alert Output (Exit Code `1`)
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

### D. Post-Restoration Clean Re-Verification (Exit Code `0`)
After restoring `sample.txt`, removing `rogue_file.txt`, and restoring `guide.txt`:
```text
=================================================================
 SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT
=================================================================
[*] Timestamp           : 2026-11-22 01:46:55
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

### E. Automated Unit Tests
```text
Ran 59 tests in 0.507s
OK (skipped=2)
```

---

## 🔍 Security Considerations & Limitations

- **Baseline Protection:** In production, `baseline.json` should be stored on read-only media, a remote server, or cryptographically signed (HMAC/GPG) so an attacker with local write access cannot tamper with both the files and the baseline.
- **On-Demand Scanning:** This version performs on-demand audits rather than continuous kernel-level file watching (e.g., `inotify` / `ReadDirectoryChangesW`).
- **Metadata Scope:** Currently verifies file content integrity via SHA-256; file permissions, ownership, and timestamps are not yet tracked.

---

## 🔮 Future Improvements

```text
v2.0
├── HMAC / Digital signature verification for baseline.json
├── Real-time filesystem event monitoring (watchdog / inotify)
├── File permission & ownership metadata auditing
├── Automated Slack / Email / Webhook alerting
└── SIEM log export (CEF / Syslog)
```

---

## 👨‍💻 Author

**Injmam Ansari**

Cybersecurity Intern — GetIntern.in

Week 7 — Applied Cryptography & File Integrity Monitoring (FIM)

---

## ⚖️ Disclaimer

This project was developed for **cybersecurity learning and educational purposes** as part of internship training. Use it only on directories and systems you own or are explicitly authorized to monitor.
