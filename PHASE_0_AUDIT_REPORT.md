# Phase 0 Technical Workspace Audit Report: Sentinel FIM

**Project:** Cryptographic Hashing & File Integrity Monitoring (Sentinel FIM)  
**Workspace:** `D:\week-7-cryptographic-hashing-file-integrity-monitor`  
**Audit Date:** November 21, 2026  
**Auditor:** Senior Cybersecurity Engineer & Python Lead  
**Audit Type:** Read-Only Workspace & Security Architecture Assessment  

---

## 1. Executive Summary

A comprehensive read-only technical audit of the Sentinel FIM workspace was conducted prior to authorizing Phase 2 development. 

While the repository contains basic working implementations for SHA-256 baseline generation and differential file integrity monitoring, the audit revealed **critical architectural regressions, broken unit test imports, complete removal of the descriptor-bound Time-Of-Check to Time-Of-Use (TOCTOU) security remediation, triplicated directory traversal logic, and significant Git branch divergence**.

### Key Findings Matrix

| Audit Dimension | Status | Severity | Summary |
| :--- | :---: | :---: | :--- |
| **Git & Branch Alignment** | ⚠️ Diverged | High | Local branch renamed to `main`; remote `origin/develop` is 3 commits behind and unmerged. |
| **Descriptor-Bound Hashing** | ❌ Missing | Critical | Previous Phase 1 descriptor-bound TOCTOU security remediation was completely overwritten and removed. |
| **Test Suite Compatibility** | ❌ Broken | Critical | `tests/test_hasher.py` fails on import (`FileStabilityError`, `scan_directory` missing from `src/hasher.py`). |
| **Code Architecture & DRY** | ⚠️ Duplicated | Medium | Directory traversal and anomaly checking are triplicated across `fim_monitor.py`, `baseline.py`, and `integrity_checker.py`. |
| **Symlink & Path Security** | ⚠️ Vulnerable | High | `Path.is_file()` follows file symlinks without checking `is_symlink()`; no descriptor locking. |
| **Config & Baseline Hardening** | ⚠️ Incomplete | Medium | Configuration parsing silently swallows errors; `baseline.json` lacks tamper protection/HMAC. |
| **Test Execution Status** | ❌ Failed | High | Host environment lacks functional Python interpreter in PATH (`Exit code 1: Python was not found`). |
| **Submission Artifacts** | ⚠️ Missing | Medium | `screenshots/` contains only `.gitkeep`; zero visual proof artifacts captured. |

---

## 2. Current Git and Branch Status

### 2.1 Branch Topology & HEAD State
- **Active Local Branch (`HEAD`)**: `refs/heads/main`
- **Current Local Commit SHA**: `d520ccc681a6c71d2e9688a77647aadf2a1ed8ef`
  - *Commit Message*: `Automated Phase 1 implementation and README update`
  - *Committed*: November 21, 2026, 00:09:35 +05:30
- **Upstream Tracking Branch**: `refs/remotes/origin/main` (`d520ccc681a6c71d2e9688a77647aadf2a1ed8ef` — in sync).
- **Remote `develop` Branch**: `refs/remotes/origin/develop` (`1a194b3411640a1f40573e14a3710151179dfd59` — Phase 0 baseline clone).

### 2.2 Branch Divergence Analysis
The workspace audit prompt specifies `Current branch: develop`. However, repository log analysis shows that the local branch `develop` was forcefully renamed to `main` via `git branch -M main` during the Phase 1 push:

```text
Commit History:
1a194b3 (origin/develop, origin/HEAD) [Initial Phase 0 Foundation]
   │
   └── 865dbe3 "Initial commit: Complete Week 7 FIM project"
         │
         └── 2c61d19 "feat(fim): complete Phase 1 implementation with chunked SHA-256 hashing and tamper simulation proof"
               │
               └── d520ccc (HEAD -> main, origin/main) "Automated Phase 1 implementation and README update"
```

> [!WARNING]
> The local workspace is currently on branch **`main`**, NOT `develop`. Furthermore, `origin/develop` on GitHub is 3 commits behind `origin/main` and contains only the Phase 0 skeleton. If internship evaluation scripts inspect `develop`, they will evaluate an unmaintained branch.

### 2.3 Working Tree and Staged State
- **Tracked Files in Index**: 16 files tracked.
- **Uncommitted Working Tree Changes**: Clean (file contents match the index blobs; minor CRLF/LF line ending normalization handled by Git core).
- **Untracked Files**: None (excluding `.git/` metadata and `__pycache__` directories).

---

## 3. Local versus Remote Differences

| File Path | `origin/develop` (`1a194b3`) | Local Workspace / `origin/main` (`d520ccc`) | Discrepancy Analysis |
| :--- | :--- | :--- | :--- |
| `src/hasher.py` | Overengineered 273-line TOCTOU file (`6fdc705`) | Simplified 72-line chunked streaming hasher (`68da943`) | **Critical regression**: Advanced stability checks stripped; broke `test_hasher.py`. |
| `src/fim_monitor.py` | Phase 0 stub (printed init notice) | Full CLI orchestrator with `--mode baseline` & `--mode monitor` | Operational, but duplicates `baseline.py` and `integrity_checker.py`. |
| `src/baseline.py` | Skeleton (`NotImplementedError`) | Implemented `BaselineManager` | Implemented, but unused by `fim_monitor.py`. |
| `src/integrity_checker.py` | Skeleton (`NotImplementedError`) | Implemented `IntegrityChecker` | Implemented, but unused by `fim_monitor.py`. |
| `output/baseline.json` | Missing (only `.gitkeep`) | Generated JSON with 2 monitored files | Synchronized and tracked. |
| `README.md` | Phase 0 status | Phase 1 status + Section 8 Tamper Proof | Contains minor documentation inconsistencies. |
| `tests/test_hasher.py` | 262-line descriptor test suite | 262-line descriptor test suite | Unmodified; now fails on import against simplified `hasher.py`. |

---

## 4. Existing Architecture Review

### 4.1 Structural Layout
```text
D:\week-7-cryptographic-hashing-file-integrity-monitor/
├── .gitignore                     # Git exclusion rules with !output/baseline.json override
├── README.md                      # Project architecture & simulation proof
├── requirements.txt               # Dependency declaration (Standard library only)
├── config/
│   └── fim_config.json            # Configuration schema (algorithm, paths)
├── monitored/                     # Monitored directory target
│   ├── sample.txt                 # Synthetic test file
│   └── documents/
│       └── guide.txt              # Nested synthetic test file
├── output/
│   ├── .gitkeep
│   └── baseline.json              # Trusted SHA-256 baseline state
├── screenshots/
│   └── .gitkeep                   # Visual evidence storage (CURRENTLY EMPTY)
├── src/
│   ├── __init__.py                # Package metadata (__version__, __author__)
│   ├── baseline.py                # BaselineManager (isolated implementation)
│   ├── fim_monitor.py             # CLI Entry Point & monolithic monitor
│   ├── hasher.py                  # Cryptographic SHA-256 chunked engine
│   └── integrity_checker.py       # IntegrityChecker (isolated implementation)
└── tests/
    ├── __init__.py                # Test package initialization
    └── test_hasher.py             # TOCTOU & descriptor-bound unit tests (BROKEN)
```

### 4.2 Data Flow Architecture
```
                         +------------------------+
                         | config/fim_config.json |
                         +-----------+------------+
                                     |
                                     v
+-----------------------+     +-------------------+     +-----------------------+
|  monitored/ directory | --> |  fim_monitor.py   | <-- |  output/baseline.json |
| (Live Filesystem)     |     | (CLI Orchestrator)|     | (Reference Baseline)  |
+-----------------------+     +---------+---------+     +-----------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
                 v (Baseline Mode)                             v (Monitor Mode)
       +--------------------+                        +--------------------+
       | Write baseline.json|                        | Differential Audit |
       +--------------------+                        +---------+----------+
                                                               |
                                            +------------------+------------------+
                                            |                  |                  |
                                            v                  v                  v
                                     [ALERT] CREATED    [ALERT] MODIFIED   [ALERT] DELETED
```

---

## 5. Completed Implementation Status

1. **`src/hasher.py`**:
   - `calculate_sha256(filepath, chunk_size=4096)`: Memory-efficient streaming implemented using `hashlib.sha256()`. Reads binary blocks in 4 KB chunks. Returns 64-character lowercase hex digest.
   - `FileHasher`: Class wrapper implemented, validates algorithm is `'sha256'`.
2. **`src/fim_monitor.py`**:
   - Uses `argparse` with required `--mode {baseline, monitor}`.
   - Supports optional overrides `--dir`, `--baseline`, `--config`.
   - Baseline mode traverses `monitored/`, hashes files, outputs valid JSON dictionary to `output/baseline.json`.
   - Monitor mode loads `output/baseline.json`, rescans `monitored/`, computes diffs, prints `[ALERT] CREATED:`, `[ALERT] MODIFIED:`, `[ALERT] DELETED:`, and outputs an audit summary table.
   - Returns exit code `0` on clean state and `1` on integrity anomalies or missing baseline.
3. **`src/baseline.py` & `src/integrity_checker.py`**:
   - Fully implemented classes (`BaselineManager` and `IntegrityChecker`) with relative POSIX path conversion and anomaly categorization.

---

## 6. Verification: Descriptor-Bound Hashing Remediation (Instruction 4)

### Audit Question:
*Is the previous Phase 1 descriptor-bound hashing remediation correctly integrated?*

### Finding: **NO — COMPLETELY REGRESSED / REMOVED**

#### Technical Evidence:
In earlier Git tree history (`blob 6fdc7054bee8c58aa3ec3c9091379e09481f0028`), `src/hasher.py` contained an enterprise-grade descriptor-bound hashing implementation designed to prevent Time-Of-Check to Time-Of-Use (TOCTOU) file substitution:

```python
# PREVIOUS DESCRIPTOR-BOUND REMEDIATION (6fdc705)
descriptor = os.open(path, os.O_RDONLY | os.O_BINARY | os.O_NOFOLLOW)
opened = os.fstat(descriptor)
# ... Verified initial lstat signature matches opened descriptor ...
# ... Streamed via os.fdopen(descriptor, "rb", closefd=False) ...
# ... Verified post-stream fstat signature matches opened signature ...
# ... Raised FileStabilityError if file was swapped, mutated, or relinked ...
```

When `src/hasher.py` was overwritten in the previous turn with the simplified script, the following critical defensive primitives were eliminated:
1. `FileStabilityError` exception class.
2. `_metadata_signature()` capturing `(st_dev, st_ino, st_mode, st_size, st_mtime_ns, st_ctime_ns)`.
3. `_path_and_descriptor_match()` handling Windows vs. POSIX `st_ctime_ns` deviations.
4. `os.open` with `O_NOFOLLOW` (symlink race prevention).
5. Pre- and post-stream `os.fstat()` comparison.
6. `ScanResult` dataclass and `scan_directory()` error-handling generator.

**Consequence:** The current `src/hasher.py` uses naive `with open(path, "rb") as stream:`. If an adversary mutates, replaces, or truncates a file while it is being streamed, Sentinel FIM will produce a corrupt hash without signaling a stability failure.

---

## 7. Critical Bugs & Security Weaknesses

### 7.1 Critical Bug: Broken Unit Test Suite (`ImportError`)
In `tests/test_hasher.py` (lines 12–20):
```python
from src.hasher import (
    DEFAULT_CHUNK_SIZE,
    FileHasher,
    FileStabilityError,           # <-- CRITICAL BUG: DOES NOT EXIST in src/hasher.py
    _safe_error_relative_path,    # <-- CRITICAL BUG: DOES NOT EXIST in src/hasher.py
    _validate_chunk_size,         # <-- CRITICAL BUG: DOES NOT EXIST in src/hasher.py
    calculate_sha256,
    scan_directory,               # <-- CRITICAL BUG: DOES NOT EXIST in src/hasher.py
)
```
Because four essential symbols were dropped from `src/hasher.py`, importing `tests/test_hasher.py` raises an immediate `ImportError`. The test suite cannot even load, much less execute.

### 7.2 Architectural Bug: Code Triplication & Violation of DRY
Directory traversal and SHA-256 calculation are implemented three separate times:
1. `src/fim_monitor.py::scan_directory()`
2. `src/baseline.py::BaselineManager.generate_baseline()`
3. `src/integrity_checker.py::IntegrityChecker._scan_current_state()`

Similarly, anomaly differential logic is implemented twice:
1. `src/fim_monitor.py::run_monitor()`
2. `src/integrity_checker.py::IntegrityChecker.check_integrity()`

`src/fim_monitor.py` completely bypasses both `BaselineManager` and `IntegrityChecker`, rendering them "dead modules" in actual runtime execution.

### 7.3 Security Weakness: Unrestricted Symlink Following
In `fim_monitor.py` (line 86), `baseline.py` (line 55), and `integrity_checker.py` (line 46):
```python
full_path = Path(root) / filename
if full_path.is_file():
    ...
```
In Python 3.10+, `pathlib.Path.is_file()` returns `True` for symbolic links pointing to regular files. Because none of the modules invoke `full_path.is_symlink()`, a malicious actor can place a symlink inside `monitored/` pointing to sensitive external files (e.g., `C:\Windows\System32\drivers\etc\hosts` or `/etc/shadow`), causing Sentinel FIM to audit and hash unauthorized external system assets.

### 7.4 Security Weakness: Vulnerability to Baseline Tampering
`output/baseline.json` is stored as plaintext JSON without cryptographic authentication:
- No HMAC-SHA256 signature or digital signature (`sign_baseline()`).
- No file-system lock or read-only attribute applied after generation.
- An attacker with write permissions on `output/` can silently inject malicious file hashes into `baseline.json`, completely blinding the FIM monitor.

### 7.5 Security Weakness: Permissive Configuration Validation
In `src/fim_monitor.py`:
```python
try:
    with open(config_path, "r", encoding="utf-8") as f:
        user_config = json.load(f)
        defaults.update(user_config)
except Exception as exc:
    print(...)
```
- A broad `except Exception` silently ignores malformed JSON syntax.
- No schema or type validation. If a user sets `"algorithm": "md5"` in `fim_config.json`, the configuration loader accepts it without error, but the monitor hardcodes SHA-256, creating a silent operational discrepancy.

---

## 8. Test Coverage & Execution Results

### 8.1 Actual Test Execution Attempt
Execution of the unit test suite was attempted via PowerShell:
```powershell
python -m unittest tests/test_hasher.py
```

**Result:**
```text
Exit Code: 1
Error Output:
Python was not found; run without arguments to install from the Microsoft Store,
or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.
```

> [!CAUTION]
> In accordance with strict audit instructions (*"Do not report tests as passing unless they have actually been executed"*):
> **NO TESTS ARE CURRENTLY PASSING.**
> The host system's PATH contains only Microsoft Store application execution aliases, not a registered Python runtime. Furthermore, static analysis proves that as soon as Python is executed, `tests/test_hasher.py` will fail with an unhandled `ImportError`.

### 8.2 Test Coverage Deficit Matrix

| Module | Unit Tests Exist? | Integration Tests Exist? | Coverage Level |
| :--- | :---: | :---: | :---: |
| `src/hasher.py` | ⚠️ Incompatible (`test_hasher.py` imports missing symbols) | ❌ None | 0% Functional |
| `src/fim_monitor.py` | ❌ None | ❌ None | 0% |
| `src/baseline.py` | ❌ None | ❌ None | 0% |
| `src/integrity_checker.py`| ❌ None | ❌ None | 0% |
| **Tamper End-to-End** | ❌ None | ❌ None | 0% |

---

## 9. README Accuracy Review

| README Section / Claim | Codebase Reality | Discrepancy Severity |
| :--- | :--- | :---: |
| **Section 2, Item 2**: *"Re-hash current files in 64 KB memory-efficient streams."* | `src/hasher.py` defines `DEFAULT_CHUNK_SIZE = 4096` (4 KB). Section 6 also states 4 KB. | Low (Documentation typo) |
| **Section 3 (Architecture)**: Shows `baseline.py` and `integrity_checker.py` as core functional modules. | `fim_monitor.py` does not import or use either module. Both are dead code. | Medium (Architecture drift) |
| **Section 6**: *"Exit status codes for SIEM/SOAR/CI pipeline automation."* | Exit codes `0` and `1` are returned, but `.github/workflows` does not exist. | Low (No CI configuration) |
| **Section 7**: *"Current Status: Phase 1: Completed"* | Test suite is broken, and TOCTOU descriptor protections are missing. | High (Misleading project status) |

---

## 10. Missing Submission Evidence & Screenshots

The `screenshots/` directory contains only an empty `.gitkeep` file (0 bytes). 

To satisfy standard Week 7 cybersecurity internship portfolio criteria, the following mandatory visual evidence artifacts are missing:
1. `screenshots/01_baseline_generation.png`: Terminal output showing successful baseline generation of `monitored/` target assets.
2. `screenshots/02_tamper_simulation.png`: Execution of file modification, file creation (`malware_dropper.ps1`), and file deletion (`guide.txt`).
3. `screenshots/03_monitor_alerts.png`: Terminal output showing real-time `[ALERT] CREATED:`, `[ALERT] MODIFIED:`, and `[ALERT] DELETED:` alerts.
4. `screenshots/04_unit_tests.png`: Terminal output showing all unit and integration tests passing (`OK`).

---

## 11. Recommended Phase 2 Implementation Scope

Phase 2 development should NOT proceed until the Phase 0/Phase 1 architectural debt is resolved. Once authorized, the Phase 2 scope must encompass:

1. **Re-integrate Descriptor-Bound TOCTOU Security Hashing**:
   - Merge the descriptor-bound safety checks (`os.open` with `O_NOFOLLOW | O_RDONLY`, `os.fstat`, `FileStabilityError`) back into `src/hasher.py`.
   - Ensure `calculate_sha256(filepath, chunk_size=4096)` retains a clean backward-compatible API signature while performing descriptor-bound checks under the hood.
   - Re-export `ScanResult`, `scan_directory`, `FileStabilityError`, and helper functions required by `tests/test_hasher.py`.
2. **Eliminate Duplication & Enforce OOP Design**:
   - Refactor `src/fim_monitor.py` to delegate baseline generation to `BaselineManager` (`src/baseline.py`).
   - Refactor `src/fim_monitor.py` to delegate verification and anomaly detection to `IntegrityChecker` (`src/integrity_checker.py`).
   - Standardize `scan_directory` in `src/hasher.py` as the single authoritative crawler for the entire project.
3. **Symlink & Path Hardening**:
   - Explicitly reject file symlinks (`candidate.is_symlink()`) during directory traversal.
   - Anchor relative paths to the monitored directory rather than the workspace root for true portability.
4. **Baseline Hardening**:
   - Implement HMAC-SHA256 integrity protection for `output/baseline.json` using a local secret or keyfile to prevent unauthorized baseline alteration.
5. **Comprehensive Test Suite Expansion**:
   - Fix `tests/test_hasher.py` to execute and pass.
   - Add `tests/test_fim_monitor.py` (CLI arguments, missing files, alert dispatch).
   - Add `tests/test_baseline.py` and `tests/test_integrity_checker.py`.
   - Add an automated end-to-end integration test (`tests/test_e2e_tamper.py`).
6. **Git Branch Harmonization**:
   - Synchronize `main` and `develop` so that branches remain consistent with internship requirements.

---

## 12. Exact Files Expected to Change in Phase 2

```text
src/
├── hasher.py             # Restore descriptor-bound hashing, FileStabilityError, ScanResult
├── fim_monitor.py        # Refactor to use BaselineManager & IntegrityChecker (eliminate duplicate logic)
├── baseline.py           # Integrate single hasher scan_directory; add HMAC baseline signing
└── integrity_checker.py  # Standardize anomaly reporting data structures

config/
└── fim_config.json       # Add strict validation schema; support chunk_size and hmac_key path

tests/
├── test_hasher.py        # Verify all 262 lines of tests execute cleanly
├── test_baseline.py      # New unit tests for BaselineManager
├── test_integrity_checker.py # New unit tests for IntegrityChecker
└── test_fim_monitor.py   # New CLI & integration tests

README.md                 # Harmonize documentation (64 KB vs 4 KB, Phase 2 status)
screenshots/              # Add the 4 missing evidence PNGs
```

---

## 13. Risks & Regression Prevention Strategy

| Risk Category | Specific Risk | Mitigation Strategy |
| :--- | :--- | :--- |
| **API Regression** | Merging descriptor checks breaks `calculate_sha256(filepath)` signature. | Keep `calculate_sha256(filepath, chunk_size=4096)` as the public facade delegating to `_calculate_sha256_with_size()`. |
| **Platform Incompatibility** | Descriptor checks fail on Windows due to `ctime` nanosecond discrepancies. | Retain platform-specific `_path_and_descriptor_match()` which ignores `st_ctime_ns` on `os.name == 'nt'`. |
| **Git Merge Conflicts** | Divergence between `main` and `develop`. | Checkout `develop`, merge `main` with explicit fast-forward, and push to `origin/develop`. |
| **Test Execution Blindspot** | Tests reported as passing without runtime execution. | Require Python interpreter activation in virtual environment (`.venv/Scripts/python.exe`) before committing. |

---

## 14. Final Recommendation

# **RECOMMENDATION: NO-GO FOR PHASE 2**

### Justification:
1. **Broken Test Suite**: `tests/test_hasher.py` cannot execute due to missing imports in `src/hasher.py`.
2. **Security Regression**: The critical descriptor-bound TOCTOU protection was dropped during the recent Phase 1 overwrite.
3. **Architectural Debt**: Code triplication exists across three separate modules.
4. **Environment Failure**: Python runtime is currently missing from the execution PATH.

### Prerequisite Remediation Steps Before Phase 2:
- [ ] Restore descriptor-bound hashing and required helper functions in `src/hasher.py`.
- [ ] Configure a verified Python runtime in PATH or activate an isolated `.venv`.
- [ ] Execute `tests/test_hasher.py` and achieve 100% test pass rate.
- [ ] Reconcile `main` and `develop` Git branches.
- [ ] Refactor `fim_monitor.py` to eliminate duplicated code and utilize `BaselineManager` and `IntegrityChecker`.

*Audit completed in accordance with strict read-only parameters.*
