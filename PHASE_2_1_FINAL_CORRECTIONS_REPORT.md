# PHASE 2.1 — SENTINEL FIM FINAL SAFETY CORRECTIONS REPORT

**Project**: Sentinel FIM — Lightweight Cryptographic File Integrity Monitor  
**Workspace**: `D:\week-7-cryptographic-hashing-file-integrity-monitor`  
**Git Branch**: `main`  
**Execution Date**: 2026-11-22  
**Reference Document**: `PHASE_2_FINAL_VERIFICATION_REPORT.md`  
**Execution Status**: **COMPLETED & VERIFIED** (All Safety Corrections Implemented)  

---

## 1. Executive Summary

Following the independent Phase 2 security verification audit, two narrowly scoped safety corrections were identified and formally implemented in Phase 2.1:
1. **HMAC Key Overwrite Protection**: Prevented accidental destruction or replacement of existing HMAC keys by enforcing kernel-level exclusive file creation (`open(dest, "x")`). Key generation now strictly raises `FileExistsError` if the target destination already exists, preserving existing key material and baseline validity.
2. **Migration Backup Collision Protection**: Enforced atomic exclusive creation (`open(backup_path, "x")`) for pre-migration backups. Migration aborts safely with `FileExistsError` on backup timestamp collisions, guaranteeing that no existing backup file is overwritten and that the original unsigned baseline remains intact.

Eleven (11) new regression tests were added across `tests/test_baseline.py` and `tests/test_fim_monitor.py`. The full automated test suite expanded from **81 tests to 92 tests** (90 passed, 2 skipped due to unprivileged Windows symlink creation, 0 failures, 0 errors).

---

## 2. Mandatory Safety & Scope Compliance

- **No Git Operations**: 0 commits, 0 pushes, 0 branch switches, 0 merges, 0 resets, 0 rebases, and 0 staging operations performed.
- **Protected Files Preserved**: `README.md`, `screenshots/`, and `output/baseline.json` remain 100% untouched and byte-identical to their initial state.
- **Prior Reports Preserved**: `PHASE_1_SECURITY_AUDIT_REPORT.md`, `PHASE_2_SECURITY_HARDENING_REPORT.md`, and `PHASE_2_FINAL_VERIFICATION_REPORT.md` were preserved without modification.
- **Key Safety**: Zero cryptographic keys or secrets were exposed, printed, or committed to Git.
- **Isolated Testing**: All 11 new tests execute within ephemeral `tempfile.TemporaryDirectory` instances and leave zero persistent filesystem remnants.

---

## 3. Initial Repository State

Prior to Phase 2.1 changes, Git working-tree status:
- Branch: `main` (synchronized with `origin/main`).
- Tracked modified files from Phase 2:
  - `.gitignore`
  - `src/baseline.py`
  - `src/fim_monitor.py`
  - `src/hasher.py`
  - `src/integrity_checker.py`
  - `tests/test_baseline.py`
  - `tests/test_fim_monitor.py`
  - `tests/test_hasher.py`
  - `tests/test_integrity_checker.py`
- Untracked files:
  - `PHASE_1_SECURITY_AUDIT_REPORT.md`
  - `PHASE_2_FINAL_VERIFICATION_REPORT.md`
  - `PHASE_2_SECURITY_HARDENING_REPORT.md`
  - `requirements.txt`
- Verified: `output/baseline.json` and `README.md` clean.

---

## 4. Exact Files Modified in Phase 2.1

1. `src/baseline.py`:
   - Updated `generate_hmac_key()` with exclusive file creation mode (`"x"` / `O_CREAT | O_EXCL`), atomic no-overwrite defense, clean rollback of partial writes, and `overwrite` parameter defaulting to `False`.
   - Updated `migrate_legacy_baseline()` with exclusive backup creation (`open(..., "x")`), atomic collision detection, and partial backup cleanup.
2. `src/fim_monitor.py`:
   - Updated `run_generate_key()` to catch `FileExistsError` specifically and report `[ERROR] Key generation aborted`.
   - Updated `run_migrate_baseline()` to catch `FileExistsError` specifically and report `[ERROR] Baseline migration aborted`.
3. `tests/test_baseline.py`:
   - Added 9 unit/regression tests validating key overwrite refusal, key content preservation, collision abortion, and atomic migration safety.
4. `tests/test_fim_monitor.py`:
   - Added 2 CLI regression tests validating `--mode generate-key` refusing overwrite and `--mode migrate-baseline` refusing overwrite on backup collision.

---

## 5. Correction 1: HMAC Key Overwrite Protection

### Problem Identified
In Phase 2, `generate_hmac_key(destination_file)` utilized `Path.write_text()`. If invoked with an existing path (e.g. accidental CLI execution or script re-run), the existing HMAC key would be overwritten with a new random key, silently invalidating the existing baseline and causing all subsequent monitor runs to fail with signature verification errors.

### Implementation Details (`src/baseline.py`)
```python
def generate_hmac_key(
    destination_file: Optional[Union[str, Path]] = None,
    overwrite: bool = False,
) -> bytes:
    """Generate a cryptographically random 256-bit (32-byte) key.

    Optionally saves the hex key string to a file with restrictive permissions.
    By default, strictly refuses to overwrite an existing key file to prevent
    accidental key loss or silent baseline invalidation.

    Args:
        destination_file: Optional path where the key should be persisted.
        overwrite: If True, allows replacing an existing key file. Defaults to False.

    Returns:
        32 raw bytes of cryptographically random key material.

    Raises:
        FileExistsError: If destination_file exists and overwrite is False.
    """
    key_bytes = secrets.token_bytes(32)
    if destination_file is not None:
        dest = Path(destination_file)
        dest.parent.mkdir(parents=True, exist_ok=True)

        mode = "w" if overwrite else "x"
        created = False
        try:
            with open(dest, mode, encoding="utf-8") as stream:
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

### Security Properties Enforced
- **Atomic Kernel Gate**: Standard library `open(..., "x")` maps to kernel `O_CREAT | O_EXCL`, preventing race conditions and ensuring that existing file contents are not opened for truncation.
- **Fail-Closed**: If `dest` already exists, a descriptive `FileExistsError` is raised immediately.
- **Preservation of Existing Secrets**: The existing key file is untouched byte-for-byte.
- **Partial Failure Cleanup**: If writing fails after creating the file (e.g. disk quota exhaustion), `if created and dest.exists(): dest.unlink()` cleans up the partial file.

---

## 6. Correction 2: Migration Backup Collision Protection

### Problem Identified
In Phase 2, `migrate_legacy_baseline()` constructed backup filenames using `datetime.now().strftime("%Y%m%d_%H%M%S")` and opened them with `"w"`. If an existing backup file existed with the same name, or if two migrations were triggered within the same second, `open(..., "w")` would overwrite the pre-existing backup.

### Implementation Details (`src/baseline.py`)
```python
        backup_path: Optional[Path] = None
        if backup:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.baseline_file.with_name(f"{self.baseline_file.name}.legacy.{timestamp}.bak")
            backup_created = False
            try:
                with open(backup_path, "x", encoding="utf-8") as bf:
                    backup_created = True
                    json.dump(raw, bf, indent=4)
                    bf.flush()
                    os.fsync(bf.fileno())
            except FileExistsError as exc:
                raise FileExistsError(
                    f"Migration aborted: backup collision detected at '{backup_path}'. "
                    f"A backup file with this timestamp already exists. Refusing to overwrite existing backup."
                ) from exc
            except Exception:
                if backup_created and backup_path.exists():
                    try:
                        backup_path.unlink()
                    except OSError:
                        pass
                raise
```

### Security Properties Enforced
- **Exclusive Backup Creation**: Uses `open(..., "x")` (`O_CREAT | O_EXCL`) to guarantee atomic creation.
- **Collision Protection**: If a backup file already exists, migration aborts immediately with `FileExistsError`.
- **Original Baseline Intact**: The collision occurs before `save_baseline()` is called; the original unsigned baseline file is 100% byte-for-byte untouched.
- **Existing Backup Intact**: The pre-existing backup file is not truncated or overwritten.
- **Atomic Persistence Preserved**: Subsequent signing uses atomic `.tmp.<pid>` + `fsync` + `os.replace`.

---

## 7. New Regression Tests

Eleven (11) new regression tests were authored:

### Added to `tests/test_baseline.py` (9 tests):
1. `test_generate_hmac_key_new_destination_succeeds`: Validates that generating a key at a non-existent path creates a 64-character hex key file containing 32 bytes of entropy.
2. `test_generate_hmac_key_existing_destination_raises_file_exists`: Validates that generating a key at an existing path raises `FileExistsError` with a clear message.
3. `test_generate_hmac_key_preserves_existing_key_bytes_on_failure`: Validates that the original file bytes remain identical after a failed overwrite attempt.
4. `test_generate_hmac_key_repeated_creation_cannot_replace`: Validates that repeated or concurrent creation calls fail closed and retain the original key.
5. `test_generate_hmac_key_explicit_overwrite_supported`: Validates that passing `overwrite=True` explicitly allows replacing a key file when authorized.
6. `test_migrate_legacy_baseline_backup_collision_fails_and_preserves_backup`: Validates that a backup filename collision raises `FileExistsError` and preserves the existing backup file contents.
7. `test_migrate_legacy_baseline_backup_collision_preserves_original_baseline`: Validates that the original unsigned baseline file is byte-for-byte unchanged after a collision abort.
8. `test_migrate_legacy_baseline_write_failure_preserves_original_baseline`: Validates that simulated disk failure during replace leaves the original baseline intact.
9. `test_migrate_legacy_baseline_repeated_migration_preserves_previous_backups`: Validates that calling migration on an already-migrated baseline fails safely without destroying earlier backups.

### Added to `tests/test_fim_monitor.py` (2 tests):
10. `test_cli_generate_key_refuses_overwrite`: Validates CLI `--mode generate-key` exits with returncode 1, prints an error message, and refuses to overwrite an existing key file.
11. `test_cli_migrate_baseline_backup_collision_fails`: Validates CLI `--mode migrate-baseline` exits with returncode 1, prints a backup collision error, and preserves both files.

---

## 8. Full Automated Test Results

### Command:
```powershell
python -m unittest discover -s tests -v
```

### Result:
```text
Ran 92 tests in 1.123s
OK (skipped=2)
```

- **Total Tests**: 92 (up from 81 tests)
- **Passed**: 90
- **Skipped**: 2 (`test_symbolic_link_root_is_rejected_when_supported`, `test_symlinks_are_skipped_when_supported` due to standard Windows unprivileged elevation restrictions; mocked symlink tests pass 100%)
- **Failed**: 0
- **Errors**: 0

### Breakdown by Module:
| Test Module | Total Tests | Passed | Skipped | Failed | Errors |
| :--- | :---: | :---: | :---: | :---: | :---: |
| `tests/test_baseline.py` | 34 | 34 | 0 | 0 | 0 |
| `tests/test_fim_monitor.py` | 20 | 20 | 0 | 0 | 0 |
| `tests/test_hasher.py` | 22 | 20 | 2 | 0 | 0 |
| `tests/test_integrity_checker.py` | 16 | 16 | 0 | 0 | 0 |
| **Total Test Suite** | **92** | **90** | **2** | **0** | **0** |

---

## 9. Remaining Platform Limitations

1. **Windows DACLs vs POSIX 0600**: `generate_hmac_key()` issues `os.chmod(dest, 0o600)` which enforces owner-only permissions on POSIX. On Windows NTFS, setting ACLs requires non-standard libraries (`pywin32`), which violates standard-library constraints. The file is placed in `config/.baseline.key` outside the monitored directory and ignored in Git.
2. **Case-Only Renames (SEC-07 Deferred)**: On-demand polling evaluates case-only renames on Windows NTFS as DELETED + CREATED. Deferred to maintain strict cross-platform POSIX path compatibility.
3. **Non-NTFS File Systems**: FAT32 and exFAT volumes do not support NTFS Alternate Data Streams. Win32 stream enumeration gracefully returns empty list on these filesystems.

---

## 10. Git Working Tree State

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
	PHASE_2_1_FINAL_CORRECTIONS_REPORT.md
	PHASE_2_FINAL_VERIFICATION_REPORT.md
	PHASE_2_SECURITY_HARDENING_REPORT.md
	requirements.txt

no changes added to commit (use "git add" and/or "git commit -a")
```

- **Production baseline status**: `output/baseline.json` is clean and unmodified.
- **Documentation status**: `README.md` and `screenshots/` are clean and unmodified.
- **Git operations performed**: 0 commits, 0 pushes.

---

## 11. Conclusion & Stop Condition

Phase 2.1 Final Safety Corrections are fully implemented, verified, and backed by 92 automated unit tests.

**Phase 2.1 Execution Status: COMPLETED. STOPPING.**  
*Awaiting explicit authorization before Phase 3.*
