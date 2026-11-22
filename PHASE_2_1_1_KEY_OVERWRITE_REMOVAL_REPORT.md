# PHASE 2.1.1 — REMOVE HMAC KEY OVERWRITE CAPABILITY REPORT

**Project**: Sentinel FIM — Lightweight Cryptographic File Integrity Monitor  
**Workspace**: `D:\week-7-cryptographic-hashing-file-integrity-monitor`  
**Git Branch**: `main`  
**Execution Date**: 2026-11-22  
**Audit Reference**: Phase 2.1 Final Safety Review  
**Security Status**: **HARDENED & VERIFIED** (Key Overwrite Capability Permanently Removed)  

---

## 1. Executive Summary

In Phase 2.1.1, the optional key-overwrite parameter (`overwrite: bool = False`) introduced during Phase 2.1 was permanently excised from `src/baseline.py`. 

**Core Security Invariant**: Key generation must **always** and **unconditionally** refuse to overwrite an existing key file. There is no supported parameter, code path, or CLI flag in Sentinel FIM that permits replacing or overwriting an existing HMAC key.

All key-generation write paths now strictly enforce atomic exclusive file creation (`open(dest, "x", encoding="utf-8")` / `O_CREAT | O_EXCL`). If the destination already exists on disk, `generate_hmac_key()` unconditionally raises `FileExistsError`, preserving existing key material and ensuring active cryptographic baselines cannot be silently invalidated.

The automated test suite was expanded to **93 tests** (91 passed, 2 skipped due to unprivileged Windows symlink creation, 0 failures, 0 errors).

---

## 2. Mandatory Safety & Scope Compliance

- **No Git Operations**: 0 commits, 0 pushes, 0 branch switches, 0 merges, 0 resets, 0 rebases, and 0 staging operations executed.
- **Protected Files Preserved**: `README.md`, `screenshots/`, and production database `output/baseline.json` remain untouched.
- **Previous Reports Preserved**: `PHASE_1_SECURITY_AUDIT_REPORT.md`, `PHASE_2_SECURITY_HARDENING_REPORT.md`, `PHASE_2_FINAL_VERIFICATION_REPORT.md`, and `PHASE_2_1_FINAL_CORRECTIONS_REPORT.md` remain unmodified.
- **Migration Backup Safety Preserved**: Pre-migration backup collision protection (`open(backup_path, "x")`) remains fully intact.
- **Zero Key Exposure**: Zero cryptographic keys or secrets were exposed, printed, or committed to Git.
- **Test Isolation**: All tests execute inside ephemeral `tempfile.TemporaryDirectory` instances.

---

## 3. Exact Files Modified

1. `src/baseline.py`:
   - Removed `overwrite` parameter from `generate_hmac_key()`.
   - Removed mode branching (`mode = "w" if overwrite else "x"`); always uses `"x"`.
   - Updated function signature to: `def generate_hmac_key(destination_file: Optional[Union[str, Path]] = None) -> bytes:`.
2. `src/fim_monitor.py`:
   - Verified that CLI orchestrator exposes no `--force` or `--overwrite` flag.
   - Retained explicit `FileExistsError` handling in `run_generate_key()`.
3. `tests/test_baseline.py`:
   - Replaced obsolete `test_generate_hmac_key_explicit_overwrite_supported` with `test_generate_hmac_key_rejects_overwrite_argument` (asserting `TypeError`).
   - Retained and verified all tests for key immutability, key preservation on failure, and repeated generation refusal.
4. `tests/test_fim_monitor.py`:
   - Retained `test_cli_generate_key_refuses_overwrite`.
   - Added `test_cli_rejects_force_and_overwrite_flags` confirming CLI exits with code 2 on unknown flags.

---

## 4. Removed Overwrite Capability & Implementation

### 4.1 Signature & Logic Refactoring (`src/baseline.py`)
```python
def generate_hmac_key(destination_file: Optional[Union[str, Path]] = None) -> bytes:
    """Generate a cryptographically random 256-bit (32-byte) key.

    Optionally saves the hex key string to a file with restrictive permissions.
    Always uses exclusive creation ('x') to strictly refuse overwriting an existing
    key file, preventing accidental key loss or silent baseline invalidation.

    Args:
        destination_file: Optional path where the key should be persisted.

    Returns:
        32 raw bytes of cryptographically random key material.

    Raises:
        FileExistsError: If destination_file already exists on disk.
    """
    key_bytes = secrets.token_bytes(32)
    if destination_file is not None:
        dest = Path(destination_file)
        dest.parent.mkdir(parents=True, exist_ok=True)

        created = False
        try:
            with open(dest, "x", encoding="utf-8") as stream:
                created = True
                stream.write(key_bytes.hex())
                stream.flush()
        except FileExistsError as exc:
            raise FileExistsError(
                f"Cannot generate key: destination key file already exists at '{dest}'. "
                f"Refusing to overwrite existing key material to prevent baseline invalidation."
            ) from exc
        except Exception:
            if created and dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            raise

        try:
            # Set restrictive file permissions (read/write only by owner on POSIX)
            os.chmod(dest, 0o600)
        except OSError:
            # Windows filesystem permission model may not support POSIX octal mode
            pass
    return key_bytes
```

### 4.2 Security Properties Enforced
1. **No Overwrite Code Path**: No branch in `generate_hmac_key()` opens an existing file with mode `"w"`, `"w+"`, `"a"`, or `os.O_TRUNC`.
2. **Atomic Kernel Gate**: Python's `open(..., "x")` sets `O_CREAT | O_EXCL` in the operating system kernel. If `dest` already exists, the kernel immediately fails the open operation without truncating or modifying the target.
3. **API Level Rejection**: Any code attempting to pass `overwrite=True` to `generate_hmac_key()` fails immediately with `TypeError: generate_hmac_key() got an unexpected keyword argument 'overwrite'`.
4. **Preservation of Existing Key Data**: If `generate_hmac_key()` is called with an existing path, the existing file bytes are guaranteed 100% untouched.
5. **Partial Failure Cleanup**: If writing fails after creating a new file (e.g. disk failure during `stream.write()`), `created = True` triggers `dest.unlink()`, ensuring no corrupted or partial key files remain.

---

## 5. Regression Tests Added & Updated

1. **`test_generate_hmac_key_rejects_overwrite_argument`** (`tests/test_baseline.py`):
   - Confirms that `generate_hmac_key(key_path, overwrite=True)` raises `TypeError` ("unexpected keyword argument 'overwrite'").
2. **`test_generate_hmac_key_existing_destination_raises_file_exists`** (`tests/test_baseline.py`):
   - Confirms that calling `generate_hmac_key(existing_path)` unconditionally raises `FileExistsError`.
3. **`test_generate_hmac_key_preserves_existing_key_bytes_on_failure`** (`tests/test_baseline.py`):
   - Confirms that after a failed overwrite attempt, the target file retains its exact pre-existing bytes.
4. **`test_generate_hmac_key_repeated_creation_cannot_replace`** (`tests/test_baseline.py`):
   - Confirms that consecutive calls to `generate_hmac_key` on the same path fail safely on subsequent calls.
5. **`test_generate_hmac_key_new_destination_succeeds`** (`tests/test_baseline.py`):
   - Confirms that generating a key at a non-existent path succeeds and writes 64 lowercase hexadecimal characters (256 bits).
6. **`test_cli_generate_key_refuses_overwrite`** (`tests/test_fim_monitor.py`):
   - Confirms CLI `--mode generate-key --key-file <existing>` prints `Key generation aborted`, exits with code 1, and leaves the file intact.
7. **`test_cli_rejects_force_and_overwrite_flags`** (`tests/test_fim_monitor.py`):
   - Confirms that CLI parser rejects `--force` and `--overwrite` with returncode 2.

---

## 6. Full Automated Test Results

### Command:
```powershell
python -m unittest discover -s tests -v
```

### Output:
```text
Ran 93 tests in 1.420s
OK (skipped=2)
```

- **Total Tests**: 93
- **Passed**: 91
- **Skipped**: 2 (`test_symbolic_link_root_is_rejected_when_supported`, `test_symlinks_are_skipped_when_supported` — skipped due to standard Windows unprivileged elevation restrictions; mocked symlink tests pass 100%)
- **Failed**: 0
- **Errors**: 0

### Module Test Breakdown:
| Test Module | Total Tests | Passed | Skipped | Failed | Errors |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `tests/test_baseline.py` | 34 | 34 | 0 | 0 | 0 |
| `tests/test_fim_monitor.py` | 21 | 21 | 0 | 0 | 0 |
| `tests/test_hasher.py` | 22 | 20 | 2 | 0 | 0 |
| `tests/test_integrity_checker.py` | 16 | 16 | 0 | 0 | 0 |
| **Total Test Suite** | **93** | **91** | **2** | **0** | **0** |

---

## 7. Remaining Platform Limitations

1. **Windows DACLs vs POSIX 0600**: `os.chmod(dest, 0o600)` applies owner-only permissions on POSIX. On Windows, DACL manipulation requires external non-standard libraries (`pywin32`), which violates standard-library constraints. Keys are stored in `config/.baseline.key` outside the monitored directory and excluded in `.gitignore`.
2. **Case-Only Renames (SEC-07 Deferred)**: Evaluated as DELETED + CREATED on case-insensitive filesystems (Windows NTFS); deferred to preserve pure cross-platform POSIX compatibility.
3. **Non-NTFS File Systems**: FAT32 and exFAT volumes do not support NTFS Alternate Data Streams; Win32 stream enumeration gracefully returns empty list on these filesystems.

---

## 8. Git Working Tree State

```text
On branch main
Your branch is up to date with 'origin/main'.

Changes not staged for commit:
  (use "git add <file>..." to update what will be committed)
  (use "git restore <file>..." to discard changes in working directory)
	modified:   .gitignore
	modified:   src/baseline.py
	modified:   src/fim_monitor.py
	modified:   src/hasher.py
	modified:   src/integrity_checker.py
	modified:   tests/test_baseline.py
	modified:   tests/test_fim_monitor.py
	modified:   tests/test_hasher.py
	modified:   tests/test_integrity_checker.py

Untracked files:
  (use "git add <file>..." to include in what will be committed)
	PHASE_1_SECURITY_AUDIT_REPORT.md
	PHASE_2_1_1_KEY_OVERWRITE_REMOVAL_REPORT.md
	PHASE_2_1_FINAL_CORRECTIONS_REPORT.md
	PHASE_2_FINAL_VERIFICATION_REPORT.md
	PHASE_2_SECURITY_HARDENING_REPORT.md
	requirements.txt

no changes added to commit (use "git add" and/or "git commit -a")
```

- **Production baseline (`output/baseline.json`)**: Preserved byte-for-byte.
- **Documentation (`README.md`, `screenshots/`)**: Preserved byte-for-byte.
- **Git operations performed**: 0 commits, 0 pushes.

---

## 9. Conclusion & Stop Condition

The key-overwrite capability has been completely removed from Sentinel FIM. Key persistence is strictly atomic, non-destructive, and fail-closed.

**Phase 2.1.1 Status: COMPLETED. STOPPING.**  
*Awaiting explicit authorization before Phase 3.*
