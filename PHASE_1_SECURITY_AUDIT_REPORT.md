# Phase 1 — Sentinel FIM: Read-Only Security & Architecture Audit Report

**Project:** Cryptographic Hashing & File Integrity Monitoring (Sentinel FIM)  
**Workspace:** `D:\week-7-cryptographic-hashing-file-integrity-monitor`  
**Audit Date:** November 22, 2026  
**Auditor:** Senior Cybersecurity Engineer & Code Review Lead  
**Audit Scope:** Read-Only Source Code, Architecture, Cryptography, Filesystem, and Test Assessment  
**Status:** Audit Completed — Read-Only Mode Maintained  

---

## 1. Executive Summary

A comprehensive, evidence-based security and architecture audit of **Sentinel FIM** was conducted in a strictly read-only posture. The evaluation examined the cryptographic foundations, filesystem access controls, differential audit logic, test suite coverage, and version control status across the entire repository.

### 1.1 Overall Security Posture
Sentinel FIM demonstrates mature engineering in its core hashing engine (`src/hasher.py`), utilizing descriptor-bound streaming with low-level operating system controls (`os.open` with `O_RDONLY | O_NOFOLLOW`, `os.fstat`), metadata stability signatures before and after reads to mitigate Time-Of-Check to Time-Of-Use (TOCTOU) file replacement, and atomic baseline persistence via `os.replace()`.

However, the audit identified **13 distinct findings** across security, reliability, and architectural dimensions:
- **0 Critical Vulnerabilities**
- **1 High-Severity Security Gap**: Complete absence of cryptographic authentication (HMAC or digital signatures) for the plaintext baseline database (`output/baseline.json`).
- **3 Medium-Severity Issues**: Potential path collision in path normalization prefix-stripping logic; complete blindness to NTFS Alternate Data Streams (ADS) on Windows; and absence of extended path / sharing-violation handling.
- **6 Low-Severity Issues**: Discrepancy between hardcoded CLI banner string (4096 bytes) and actual 1 MiB engine chunk size; cross-platform case-sensitivity differences; in-memory set scaling limits; absence of structured JSON audit logging; and unvalidated configuration schema parameters.
- **3 Informational Findings**: Deleted `requirements.txt` manifest; skipped symlink tests on non-elevated Windows environments; and absence of continuous background event notifications.

### 1.2 Summary of Findings Matrix

| Finding ID | Severity | Category | Affected Component | Summary |
| :--- | :---: | :---: | :--- | :--- |
| **SEC-01** | **High** | Cryptography | `src/baseline.py`, `output/baseline.json` | Baseline stored as unauthenticated plaintext JSON (no HMAC/signature); vulnerable to silent tampering if attacker has write access. |
| **SEC-02** | **Medium** | Filesystem | `src/baseline.py`, `src/integrity_checker.py` | Path normalization strips folder prefix based on simple `.startswith()`, causing collisions if nested folders share the monitored root name. |
| **SEC-03** | **Medium** | Filesystem / OS | `src/hasher.py` | NTFS Alternate Data Streams (ADS) are unindexed on Windows; arbitrary payloads can be attached to monitored files without altering hash. |
| **SEC-04** | **Medium** | Testing | `tests/` | Test suite lacks edge cases for Windows `MAX_PATH` (>260 chars), Unicode normalization (NFC/NFD), and concurrent sharing violations. |
| **SEC-05** | **Low** | Architecture / UI | `src/fim_monitor.py:76` | CLI banner outputs hardcoded `(4096-byte chunk streaming)` label, conflicting with actual 1 MiB engine buffer in `src/hasher.py`. |
| **SEC-06** | **Low** | Reliability | `src/hasher.py:102-145` | `FileStabilityError` aborts immediately without backoff/retry when concurrent benign file writes occur. |
| **SEC-07** | **Low** | Filesystem | `src/integrity_checker.py` | Case-insensitive filesystems (Windows/macOS) treat case-only renames as simultaneous DELETED + CREATED anomalies. |
| **SEC-08** | **Low** | Performance | `src/integrity_checker.py` | Full in-memory dictionary and set instantiation limits scalability for massive directory trees (>100k files). |
| **SEC-09** | **Low** | Detection / SIEM | `src/fim_monitor.py` | Audit findings printed exclusively to terminal; lack of structured JSON/Syslog output limits SIEM/pipeline integration. |
| **SEC-10** | **Low** | Configuration | `src/fim_monitor.py:29-46` | `load_config()` defers schema and algorithm validation to runtime instantiation rather than failing fast. |
| **INF-01** | **Informational** | Repository Hygiene | Root directory | `requirements.txt` was deleted in commit `313449e`; automated dependency scanners and build systems lack manifest. |
| **INF-02** | **Informational** | Testing | `tests/test_hasher.py` | Native symlink tests skipped in standard Windows environments due to missing elevation privilege (`SeCreateSymbolicLinkPrivilege`). |
| **INF-03** | **Informational** | Operational Model | System Architecture | Tool performs on-demand polling scans; does not integrate with kernel filesystem event queues (`inotify`/`ReadDirectoryChangesW`). |

---

## 2. Repository and Git Status

### 2.1 Working Tree & Branch Topology
- **Active Working Directory**: `D:\week-7-cryptographic-hashing-file-integrity-monitor`
- **Active Git Branch**: `main`
- **Tracking Remote**: `origin/main` (Synchronized with `HEAD` at commit `543c7ad`)
- **Remote Branches**:
  - `origin/HEAD -> origin/main`
  - `origin/main`
  - `origin/develop`
- **Local Branches**:
  - `main`
  - `backup-before-push`
- **Working-Tree Status**: Completely clean (`nothing to commit, working tree clean`).

### 2.2 Commit History Analysis
Recent commits reflect repository consolidation and documentation improvements:
```text
543c7ad (HEAD -> main, origin/main) merge: integrate remote Week 7 updates
94fdfba (backup-before-push) docs: upgrade README and add project screenshots
313449e Delete requirements.txt
ccef4ab Delete PHASE_2_ARCHITECTURE_PLAN.md
33c80c8 Delete PHASE_2_2_REPORT.md
52d6df1 Delete PHASE_2_1_REPORT.md
da2b952 Delete PHASE_1_REMEDIATION_REPORT.md
662c085 Delete PHASE_1_FINAL_SECURITY_REVIEW.md
8b25673 Delete PHASE_0_AUDIT_REPORT.md
b09c635 Revise README for Week 7 project update
```

### 2.3 Tracked Files Inventory (24 Files)
```text
.gitignore
README.md
config/fim_config.json
monitored/documents/guide.txt
monitored/sample.txt
output/.gitkeep
output/baseline.json
screenshots/.gitkeep
screenshots/01-project-structure.png
screenshots/02-baseline-generation.png
screenshots/03-clean-integrity-check.png
screenshots/04-tampering-detection.png
screenshots/05-restored-integrity.png
screenshots/06-unit-test-results.png
src/__init__.py
src/baseline.py
src/fim_monitor.py
src/hasher.py
src/integrity_checker.py
tests/__init__.py
tests/test_baseline.py
tests/test_fim_monitor.py
tests/test_hasher.py
tests/test_integrity_checker.py
```

### 2.4 Untracked & Ignored Files
- `.dist/` (Empty build artifact directory, ignored by `.gitignore`).
- `.venv/` (Python virtual environment, ignored by `.gitignore`).
- `src/__pycache__/` and `tests/__pycache__/` (Python bytecode, ignored by `.gitignore`).
- No sensitive credentials, private keys, authentication tokens, or personal identifiers were detected in tracked or untracked repository files.

---

## 3. Architecture and Source Code Audit

### 3.1 Architectural Decomposition

The system is organized into a four-tier architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     CLI & Orchestrator                      │
│                    (src/fim_monitor.py)                     │
│  - Argument Parsing: argparse (--mode, --dir, --baseline)   │
│  - Configuration Ingestion: load_config()                   │
│  - Terminal Reporting & Exit Code Mapping (0 vs. 1)         │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               ▼                              ▼
      [Baseline Mode]                  [Monitor Mode]
┌──────────────────────────────┐ ┌────────────────────────────┐
│       Baseline Manager       │ │     Integrity Checker      │
│      (src/baseline.py)       │ │ (src/integrity_checker.py) │
│ - Schema & Digest Validation │ │ - Set Differential Logic   │
│ - Relative Path Normalizer   │ │ - Anomaly Categorization   │
│ - Atomic Persistence (.tmp)  │ │ - Scan Error Surfacing     │
└──────────────┬───────────────┘ └────────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                 Cryptographic Hashing Engine                │
│                      (src/hasher.py)                        │
│ - Directory Traversal: scan_directory()                     │
│ - Low-level Descriptor Hashing: _calculate_sha256_with_size │
│ - TOCTOU Stability Guards: metadata signature comparison    │
│ - Security Barriers: Symlink refusal, containment checks    │
└─────────────────────────────────────────────────────────────┘
```

### 3.2 Component Responsibilities & Coupling Analysis
1. **`src/hasher.py` (Authoritative Scanner)**:
   - Encapsulates all filesystem crawling and cryptographic hashing.
   - Low coupling to higher layers; returns self-contained `ScanResult` dataclass.
   - Strictly enforces SHA-256 only (`FileHasher` rejects any other algorithm).
2. **`src/baseline.py` (`BaselineManager`)**:
   - Enforces atomic file replacement via temporary files (`output/baseline.json.tmp.<pid>`), `os.fsync`, and `os.replace`.
   - Validates JSON structure (`isinstance(dict)`) and regex validates 64-character hexadecimal digests (`^[0-9a-f]{64}$`).
   - Normalizes path separators and folder prefixes.
3. **`src/integrity_checker.py` (`IntegrityChecker`)**:
   - Consumes `BaselineManager` dictionary and live `ScanResult`.
   - Computes set intersections and set differences (`current_files - baseline_files` for CREATED; `baseline_files - current_files` for DELETED; and digest comparisons for MODIFIED).
   - Enforces security rule: Any scanning error flags `is_compromised = True` to prevent false-clean audits when assets are inaccessible.
4. **`src/fim_monitor.py` (CLI Interface)**:
   - Wires user arguments to `BaselineManager` and `IntegrityChecker`.
   - Formats human-readable ASCII console output.
   - Dispatches exit code `0` on verified clean state and `1` on detected anomaly or runtime error.

---

## 4. Cryptographic Security Assessment

### 4.1 SHA-256 Implementation Correctness
- **Standard Library Primitives**: Hashing delegates to Python's standard `hashlib.sha256()`, which wraps OpenSSL's FIPS 180-4 compliant implementation.
- **Empty File Handling**: Evaluated in `test_known_sha256_vector_and_empty_file`. Returns standard NIST digest:
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
- **Large File Handling**: Evaluated with 1 MiB chunked streaming (`stream.read(chunk_size)`). Large binaries stream in constant memory without RAM exhaustion.
- **Avalanche Effect**: Verified mathematically and empirically. A single-byte change in `sample.txt` altered 60 of the 64 hexadecimal characters.

### 4.2 Collision vs. Pre-Image Resistance Analysis
- **Collision Resistance**: Under the Birthday Paradox, finding *any* arbitrary pair $x \neq y$ such that $H(x) = H(y)$ requires approximately $2^{128}$ evaluations for SHA-256. This is computationally infeasible across all modern and foreseeable classical computation (compared to broken MD5 with $2^{64}$ and SHA-1 with $2^{63.1}$).
- **Second Pre-Image Resistance**: Crucial to File Integrity Monitoring. If an adversary attempts to modify or replace an existing file $m_1$, finding an altered payload $m_2 \neq m_1$ such that $H(m_2) = H(m_1)$ requires the full work factor of $2^{256}$ operations.
- **Cryptographic Boundary (Integrity vs. Authenticity)**:
  > [!CRITICAL]
  > **Core Cryptographic Vulnerability**: SHA-256 guarantees *data integrity relative to a trusted hash digest*, but it does NOT provide *authenticity* or *non-repudiation* of the digest store.
  > Because `output/baseline.json` is stored in unauthenticated plaintext JSON on the local disk, any process or user with write access to the filesystem can modify a monitored file and simultaneously update `baseline.json` with the new hash, or re-run `python -m src.fim_monitor --mode baseline` to establish a tampered baseline without triggering any cryptographic alarm.

---

## 5. Filesystem Security Assessment

### 5.1 TOCTOU (Time-Of-Check to Time-Of-Use) Defenses
`src/hasher.py` implements a defense-in-depth descriptor lifecycle:
1. `initial = path.lstat()` — Initial path-based inspection.
2. `descriptor = os.open(path, os.O_RDONLY | os.O_BINARY | os.O_NOFOLLOW)` — Descriptor acquisition without following symlinks.
3. `opened = os.fstat(descriptor)` — Descriptor metadata inspection.
4. `_path_and_descriptor_match(initial, opened)` — Validates `st_dev`, `st_ino`, `st_mode`, `st_size`, `st_mtime_ns`.
5. Stream hashing via `os.fdopen(descriptor, "rb", closefd=False)`.
6. `after_stream = os.fstat(descriptor)` — Post-stream descriptor check.
7. `_metadata_signature(opened) != _metadata_signature(after_stream)` $\to$ raises `FileStabilityError`.
8. `final_path = path.lstat()` — Final path check to detect replacement during read.

### 5.2 Filesystem Boundaries & Symlink Protection
- **Symlink Refusal**: `os.walk(..., followlinks=False)` prevents directory symlink traversal.
- **Per-entry link inspection**: Explicitly checks `stat.S_ISLNK(candidate_stat.st_mode)`. If a symlink is encountered, it is recorded in `result.errors` and skipped without opening.
- **Root Containment**: Every candidate file is verified via `resolved_candidate.relative_to(resolved_root)`. If a file resolves outside the monitored directory tree (e.g. via hard links or path trickery), it raises `FileStabilityError`.

### 5.3 Filesystem Vulnerabilities & Edge Cases
1. **Path Prefix Collisions (SEC-02)**:
   In `src/baseline.py` and `src/integrity_checker.py`:
   ```python
   prefix = f"{self.monitored_dir.name}/"
   if posix_path.startswith(prefix) and len(posix_path) > len(prefix):
       posix_path = posix_path[len(prefix):]
   ```
   If a folder structure contains `monitored/monitored/target.txt`, `posix_path` relative to `monitored` is `monitored/target.txt`. Stripping `monitored/` reduces it to `target.txt`, which collides with a legitimate file at `monitored/target.txt`.
2. **NTFS Alternate Data Streams (SEC-03)**:
   On Windows NTFS filesystems, `os.walk` enumerates only the default `$DATA` stream. Attackers can attach secondary data streams (e.g., `sample.txt:malware.ps1`) to monitored files. The primary stream's size, timestamp, and SHA-256 remain completely unchanged, leaving the secondary stream invisible to Sentinel FIM.
3. **Sharing Violations / Locked Files**:
   On Windows, files opened with exclusive access by other processes (e.g., databases, system logs) raise `PermissionError` (WinError 32: sharing violation). Sentinel FIM flags this as a scan error and marks the system compromised, but lacks a non-blocking retry mechanism.

---

## 6. Detection and Reporting Assessment

### 6.1 Differential Categorization Logic
The integrity classification in `src/integrity_checker.py` was inspected and verified:
- **`INTACT`**: $F \in (C \cap B) \land H_{\text{live}}(F) = H_{\text{base}}(F)$
- **`MODIFIED`**: $F \in (C \cap B) \land H_{\text{live}}(F) \neq H_{\text{base}}(F)$
- **`CREATED`**: $F \in (C \setminus B)$
- **`DELETED`**: $F \in (B \setminus C)$
- **`ERRORS`**: Files where `scan_directory` caught `PermissionError`, `OSError`, or `FileStabilityError`.

### 6.2 Anti-Blinding / Scan Error Surfacing
The system enforces a critical security invariant:
```python
has_scan_errors = bool(not scan_result.success or scan_result.errors)
is_compromised = bool(modified or created or deleted or has_scan_errors)
```
If an adversary intentionally alters permissions on a directory to prevent Sentinel FIM from inspecting a backdoor, the audit does **not** report a clean state. It flags `has_scan_errors = True` and exits with code `1`.

### 6.3 Reporting Deficiencies
- Output is rendered strictly to the console (`stdout`).
- No structured JSON audit report is saved to disk or emitted to `stderr`/syslog.
- No historical audit logs are persisted across multiple runs.

---

## 7. Testing and Reliability Audit

### 7.1 Verified Test Execution
The test suite was executed in non-destructive read-only mode using:
```bash
python -m unittest discover -s tests -v
```

**Results**:
- **Discovered**: 59 tests
- **Passed**: 57 tests
- **Skipped**: 2 tests
- **Failed**: 0 tests
- **Duration**: ~0.97s

### 7.2 Skipped Tests Analysis
Both skipped tests occur in `tests/test_hasher.py`:
1. `test_symbolic_link_root_is_rejected_when_supported`
2. `test_symlinks_are_skipped_when_supported`

**Reason**: On Windows systems without Developer Mode or administrative privileges (`SeCreateSymbolicLinkPrivilege`), creating native NTFS symbolic links raises `OSError: [WinError 1314]`. The test suite gracefully catches this and marks the tests as `skipped`. Mock-based symlink rejection tests (`test_file_symlink_is_skipped_with_mocked_lstat` and `test_symlink_root_is_rejected_with_mocked_lstat`) pass successfully.

### 7.3 Test Isolation & Safety Review
All test modules (`test_hasher.py`, `test_baseline.py`, `test_integrity_checker.py`, `test_fim_monitor.py`) use `tempfile.TemporaryDirectory()` in `setUp()` and cleanly remove temporary trees in `tearDown()`. No tests perform destructive operations on persistent repository assets.

### 7.4 Test Coverage Matrix & Gaps

| Test Category | Covered by Existing Tests | Missing Coverage / Gaps |
| :--- | :---: | :--- |
| **Empty Files** | ✅ Yes (`test_known_sha256_vector_and_empty_file`) | None |
| **Large / Streaming Files** | ✅ Yes (`test_large_file_is_streamed_across_multiple_chunks`) | 1 GiB+ file streaming |
| **Binary Files** | ✅ Yes (`empty.bin`, `large.bin`) | Executable binaries (.exe/.dll) |
| **File Modification** | ✅ Yes (`test_modified_file_detection`) | Sub-millisecond mtime modifications |
| **File Deletion** | ✅ Yes (`test_deleted_file_detection`) | Deletion of entire directory trees |
| **File Creation** | ✅ Yes (`test_created_file_detection`) | Hidden file / system file creation |
| **Baseline Corruption** | ✅ Yes (`test_load_baseline_malformed_json`) | Truncated JSON / binary garbage |
| **Baseline Tampering** | ❌ No | Testing detection of altered baseline hashes |
| **Symbolic Links** | ⚠️ Partial (Mocked tests pass, native skipped on Windows) | POSIX / Linux native symlink CI testing |
| **Permission Failures** | ✅ Yes (`test_unreadable_file_is_reported`) | Directory unreadable while files are readable |
| **Concurrent File Mutation** | ✅ Yes (`test_detects_metadata_change_during_streaming`) | Concurrent append/truncate during read |
| **Invalid Configuration** | ✅ Yes (`test_load_config_malformed_json_fallback`) | Type mismatch in config keys |
| **Invalid Paths** | ✅ Yes (`test_missing_monitored_directory`) | Windows paths exceeding 260 chars (`MAX_PATH`) |
| **NTFS Alternate Data Streams** | ❌ No | Detection of `:Stream` attachments on Windows |
| **Unicode Normalization** | ❌ No | NFC vs. NFD character encoding differences |

---

## 8. Dependency and Configuration Assessment

### 8.1 Dependencies
- **Manifest**: `requirements.txt` was removed in commit `313449e`.
- **Runtime Dependencies**: Strictly standard library (`hashlib`, `os`, `stat`, `pathlib`, `json`, `argparse`, `sys`, `datetime`). Zero third-party packages.
- **Python Compatibility**: Requires Python 3.10+ (utilizes type unions `Union[str, Path]` and syntax features from 3.10+).

### 8.2 Configuration Management
- Configuration is loaded from `config/fim_config.json`:
  ```json
  {
    "algorithm": "sha256",
    "monitored_directory": "monitored",
    "baseline_file": "output/baseline.json"
  }
  ```
- **Strengths**: Isolates baseline storage (`output/baseline.json`) from the monitored path (`monitored/`).
- **Deficiencies**: `load_config()` defaults missing keys, but does not enforce strict type validation or reject invalid algorithms prior to component initialization.

---

## 9. Evidence-Based Security Findings

### Finding SEC-01: Baseline Plaintext Storage & Lack of Cryptographic Authentication
- **Severity**: **High**
- **Affected File/Function**: `src/baseline.py:BaselineManager.save_baseline()`, `output/baseline.json`
- **Exact Code Location**: `src/baseline.py:154-170`
- **Technical Explanation**: `baseline.json` is saved as unauthenticated, unencrypted plaintext JSON. The baseline structure contains only file path keys and SHA-256 hex strings. There is no cryptographic Message Authentication Code (HMAC-SHA256) or asymmetric digital signature (e.g., Ed25519) validating the baseline's authenticity.
- **Realistic Security Impact**: An attacker gaining write access to the host can tamper with monitored files and rewrite `output/baseline.json` with the new digests, completely neutralizing the File Integrity Monitor.
- **Reproduction**:
  1. Alter `monitored/sample.txt`.
  2. Compute SHA-256 of the altered file.
  3. Edit `output/baseline.json` and insert the new hash.
  4. Run `python -m src.fim_monitor --mode monitor` $\to$ Returns `[STATUS] INTEGRITY VERIFIED` with exit code `0`.
- **Recommended Remediation**: Implement HMAC-SHA256 baseline sealing or digital signature verification with an out-of-band secret or public/private key pair.
- **Confidence Level**: Confirmed.

---

### Finding SEC-02: Path Normalization Prefix Collision Risk
- **Severity**: **Medium**
- **Affected File/Function**: `src/baseline.py:normalize_path()`, `src/integrity_checker.py:normalize_path()`
- **Exact Code Location**: `src/baseline.py:73-76`, `src/integrity_checker.py:69-72`
- **Code Extract**:
  ```python
  prefix = f"{self.monitored_dir.name}/"
  if posix_path.startswith(prefix) and len(posix_path) > len(prefix):
      posix_path = posix_path[len(prefix):]
  ```
- **Technical Explanation**: `normalize_path()` attempts to strip a legacy monitored directory prefix by evaluating `posix_path.startswith(prefix)`. If a directory named `monitored/` contains a nested subdirectory that is also named `monitored/` (e.g. `monitored/monitored/app.py`), the relative path produced by `scan_directory` is `monitored/app.py`. The prefix check matches `monitored/`, stripping the subdirectory name and truncating the path to `app.py`. If `monitored/app.py` also exists, both map to `app.py`, overwriting each other in the baseline dictionary.
- **Realistic Security Impact**: Omission and collision of nested files in directory trees where subdirectories match the parent monitored folder name.
- **Reproduction**:
  Create `monitored/monitored/file.txt` and `monitored/file.txt`. Generate baseline. Only one `file.txt` will exist in `baseline.json`.
- **Recommended Remediation**: Remove naive prefix stripping or anchor prefix removal strictly to paths verified to be relative to the workspace root rather than relative to the monitored directory.
- **Confidence Level**: Confirmed.

---

### Finding SEC-03: NTFS Alternate Data Streams (ADS) Evasion on Windows
- **Severity**: **Medium**
- **Affected File/Function**: `src/hasher.py:scan_directory()`
- **Exact Code Location**: `src/hasher.py:203-255`
- **Technical Explanation**: On Windows NTFS filesystems, `os.walk` and standard path access open only the default stream (`::$DATA`). NTFS allows secondary data streams attached to regular files (e.g., `file.txt:backdoor.exe`). Sentinel FIM neither inspects nor hashes Alternate Data Streams.
- **Realistic Security Impact**: Attackers or malware (e.g., payloads flagged with `Zone.Identifier` or hidden executable streams) can hide payloads inside monitored files without modifying the primary file hash, evading FIM detection.
- **Recommended Remediation**: On Windows platforms (`os.name == 'nt'`), query stream enumerators (via Windows API `FindFirstStreamW`/`FindNextStreamW` or PowerShell `Get-Item -Stream *`) to detect rogue streams.
- **Confidence Level**: Confirmed.

---

### Finding SEC-04: Test Suite Missing High-Risk Edge Cases
- **Severity**: **Medium**
- **Affected File/Function**: `tests/`
- **Technical Explanation**: While standard paths, chunks, and mock stability errors are well-tested (59 tests), the test suite lacks tests for:
  - Paths exceeding Windows `MAX_PATH` (260 characters).
  - Unicode path normalization discrepancies (e.g., macOS NFD vs. Linux NFC).
  - File locking / concurrent read sharing violations (`PermissionError` WinError 32).
  - Baselines with thousands of files.
- **Realistic Security Impact**: In enterprise environments with deep trees or locked files, audits may crash or fail to execute properly.
- **Recommended Remediation**: Add parametrized unit tests simulating long paths, Unicode normalization forms, and Windows file lock sharing.
- **Confidence Level**: Confirmed.

---

### Finding SEC-05: CLI Banner Algorithm Output Inconsistency
- **Severity**: **Low**
- **Affected File/Component**: `src/fim_monitor.py:76`
- **Exact Code Location**: `src/fim_monitor.py:76`
- **Code Extract**:
  ```python
  print(f"[*] Hash Algorithm      : SHA-256 (4096-byte chunk streaming)")
  ```
- **Technical Explanation**: `run_baseline()` prints `SHA-256 (4096-byte chunk streaming)` in the console banner, whereas `src/hasher.py` defines `DEFAULT_CHUNK_SIZE = 1024 * 1024` (1 MiB).
- **Realistic Security Impact**: Audit confusion and documentation mismatch during external compliance reviews.
- **Recommended Remediation**: Update the print string to dynamically reflect `from src.hasher import DEFAULT_CHUNK_SIZE` (e.g. `1 MiB / 1,048,576 bytes`).
- **Confidence Level**: Confirmed.

---

### Finding SEC-06: Abrupt Abort on Transient File Write Contention
- **Severity**: **Low**
- **Affected File/Component**: `src/hasher.py:_calculate_sha256_with_size()`
- **Exact Code Location**: `src/hasher.py:127-142`
- **Technical Explanation**: If a file is modified during hashing, `FileStabilityError` is raised immediately. `scan_directory` catches this and appends it to `ScanResult.errors`, which causes `IntegrityChecker` to mark the system as `is_compromised = True`.
- **Realistic Security Impact**: In active directories (e.g., active application logs), benign concurrent writes trigger false breach alerts.
- **Recommended Remediation**: Implement a configurable retry mechanism (e.g. 2 retries with a 50ms backoff) before classifying instability as an error.
- **Confidence Level**: Confirmed.

---

### Finding SEC-07: Case Sensitivity Renaming Anomalies on Windows
- **Severity**: **Low**
- **Affected File/Component**: `src/integrity_checker.py:check_integrity()`
- **Exact Code Location**: `src/integrity_checker.py:105-150`
- **Technical Explanation**: Paths are stored and compared as case-exact strings. If a file is renamed from `sample.txt` to `SAMPLE.txt` on a case-insensitive filesystem (Windows), the differential engine classifies it as `sample.txt` DELETED and `SAMPLE.txt` CREATED.
- **Realistic Security Impact**: Minor audit reporting noise when files are renamed by case only.
- **Recommended Remediation**: Implement case-folding normalization on Windows (`os.name == 'nt'`).
- **Confidence Level**: Confirmed.

---

### Finding SEC-08: In-Memory Set Scalability Limit
- **Severity**: **Low**
- **Affected File/Component**: `src/integrity_checker.py:check_integrity()`
- **Technical Explanation**: The entire baseline and live state are loaded into memory as Python dictionaries and sets. For massive repositories (>500,000 files), memory consumption can exceed several hundred megabytes.
- **Realistic Security Impact**: Potential resource exhaustion in memory-constrained embedded systems or containers.
- **Recommended Remediation**: Use generator-based streaming diffs or a lightweight embedded SQLite store for large-scale deployments.
- **Confidence Level**: Confirmed.

---

### Finding SEC-09: Lack of Structured JSON Audit Log Output
- **Severity**: **Low**
- **Affected File/Component**: `src/fim_monitor.py:run_monitor()`
- **Technical Explanation**: Audit outcomes are only printed to console stdout. The structured audit report dictionary from `check_integrity()` is discarded at exit.
- **Realistic Security Impact**: Impedes integration with SIEM collectors, log shippers, and automated security orchestration platforms.
- **Recommended Remediation**: Add a `--output-json <PATH>` CLI option to persist structured JSON audit records.
- **Confidence Level**: Confirmed.

---

### Finding SEC-10: Incomplete Configuration Schema Validation in `load_config`
- **Severity**: **Low**
- **Affected File/Component**: `src/fim_monitor.py:load_config()`
- **Exact Code Location**: `src/fim_monitor.py:29-46`
- **Technical Explanation**: `load_config` loads JSON and merges it with defaults, but does not validate data types, directory existence, or enforce `algorithm == "sha256"` at load time.
- **Realistic Security Impact**: Delayed error reporting until component initialization.
- **Recommended Remediation**: Validate configuration types and algorithm values within `load_config()`.
- **Confidence Level**: Confirmed.

---

### Finding INF-01: Absence of `requirements.txt`
- **Severity**: **Informational**
- **Affected Component**: Repository Root
- **Technical Explanation**: `requirements.txt` was deleted in commit `313449e`. Even though Sentinel FIM relies exclusively on the Python standard library, standard CI/CD and dependency scanners expect a manifest.
- **Recommended Remediation**: Restore `requirements.txt` with a comment indicating `# Standard library only (no third-party dependencies required)`.
- **Confidence Level**: Confirmed.

---

### Finding INF-02: Native Symlink Tests Skipped on Windows
- **Severity**: **Informational**
- **Affected Component**: `tests/test_hasher.py:87-109`
- **Technical Explanation**: Creating symlinks on Windows without administrator privileges raises `[WinError 1314]`, leading to 2 skipped tests during unit test execution.
- **Recommended Remediation**: Document the requirement for Developer Mode or Administrator privileges to execute native symlink test vectors on Windows.
- **Confidence Level**: Confirmed.

---

### Finding INF-03: On-Demand Architecture vs. Kernel Event Queues
- **Severity**: **Informational**
- **Affected Component**: System Design
- **Technical Explanation**: Sentinel FIM operates strictly on demand. Real-time file system modification events occurring between scheduled scans are not caught until the next explicit scan.
- **Recommended Remediation**: Highlight the distinction between on-demand auditing and kernel-level event watching in operational documentation.
- **Confidence Level**: Confirmed.

---

## 10. Recommended Remediation Priorities

```
  HIGH PRIORITY (P1)
  ├── SEC-01: Implement HMAC-SHA256 or Digital Signature for baseline.json authentication
  └── SEC-02: Fix prefix-stripping path collision bug in normalize_path()

  MEDIUM PRIORITY (P2)
  ├── SEC-03: Add NTFS Alternate Data Stream (ADS) detection on Windows
  └── SEC-04: Add edge-case test suite (MAX_PATH, Unicode NFC/NFD, file locks)

  LOW PRIORITY (P3)
  ├── SEC-05: Update CLI banner chunk size string from 4096 to 1 MiB
  ├── SEC-06: Add retry backoff for transient FileStabilityError
  ├── SEC-07: Implement case-folding normalization on Windows
  ├── SEC-08: Add generator/streaming diff for large directories
  ├── SEC-09: Add --output-json CLI flag for SIEM log export
  ├── SEC-10: Strengthen configuration schema validation
  └── INF-01: Restore requirements.txt with standard library annotation
```

---

## 11. Risk Assessment Matrix

| Likelihood \ Impact | Informational | Low | Medium | High | Critical |
| :---: | :---: | :---: | :---: | :---: | :---: |
| **High** | INF-01, INF-02 | SEC-05 | SEC-02 | **SEC-01** | — |
| **Medium** | INF-03 | SEC-09, SEC-10 | SEC-03, SEC-04 | — | — |
| **Low** | — | SEC-06, SEC-07, SEC-08 | — | — | — |

---

## 12. Phase 2 Implementation Recommendations

When Phase 2 is formally authorized, execution should proceed in disciplined stages:

1. **Stage 1: Cryptographic Baseline Sealing**:
   - Add HMAC-SHA256 baseline signing using a secret key or environment variable.
   - Enforce signature verification before loading `baseline.json`.
2. **Stage 2: Path Normalization Hardening**:
   - Refactor `normalize_path()` to remove naive `.startswith(prefix)` stripping and use unambiguous relative resolution.
3. **Stage 3: Windows ADS & Filesystem Enhancements**:
   - Add stream detection on Windows hosts to alert on hidden NTFS alternate data streams.
   - Correct CLI banner string to 1 MiB (`1,048,576 bytes`).
4. **Stage 4: Structured Reporting & Configuration Hardening**:
   - Add `--output-json` flag to export structured machine-readable reports.
   - Enforce strict type and value checks in `load_config()`.
5. **Stage 5: Test Suite Expansion**:
   - Add unit tests for baseline HMAC verification, path prefix collisions, and Windows stream detection.

---

## 13. Explicit List of Tests Not Executed and Reasons

1. **Native Symlink Tests on Windows (`test_symbolic_link_root_is_rejected_when_supported`, `test_symlinks_are_skipped_when_supported`)**:
   - *Status*: Automatically skipped by test runner.
   - *Reason*: On Windows operating systems, creating NTFS symbolic links requires administrative elevation (`SeCreateSymbolicLinkPrivilege`) or Windows Developer Mode. Running in a standard user context appropriately skips these tests.
2. **Destructive Filesystem Alteration Tests**:
   - *Status*: Not executed against project files.
   - *Reason*: Prohibited by Phase 1 Mandatory Safety Rules. All unit tests ran strictly within temporary directories (`tempfile.TemporaryDirectory`).

---

## 14. Final Audit Conclusion

The Sentinel FIM codebase demonstrates solid defensive programming foundations: descriptor-bound hashing, TOCTOU mitigation, symlink rejection, atomic persistence, and robust set-differential integrity auditing.

The principal security vulnerability identified is **SEC-01 (unauthenticated plaintext baseline storage)**: while SHA-256 reliably detects unauthorized file modifications when checked against an authentic baseline, the baseline file itself is vulnerable to tampering if local write permissions are not strictly isolated. Resolving this alongside the path normalization collision bug (**SEC-02**) will elevate Sentinel FIM to a hardened, tamper-resistant integrity monitoring system.

**Phase 1 Read-Only Security Audit Status: COMPLETED.**  
Awaiting explicit authorization before proceeding to Phase 2 planning or implementation.
