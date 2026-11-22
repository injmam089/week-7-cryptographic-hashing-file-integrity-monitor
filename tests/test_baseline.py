"""Unit and integration tests for Sentinel FIM BaselineManager."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from src.baseline import (
    BaselineAuthenticationError,
    BaselineCorruptionError,
    BaselineManager,
    canonical_baseline_bytes,
    compute_baseline_hmac,
    generate_hmac_key,
    resolve_hmac_key,
    verify_baseline_hmac,
)
from src.hasher import ScanResult, calculate_sha256


class BaselineManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.monitored_dir = self.workspace / "monitored"
        self.monitored_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.workspace / "output" / "baseline.json"
        self.test_key = secrets.token_bytes(32)
        self.manager = BaselineManager(self.monitored_dir, self.baseline_file, hmac_key=self.test_key)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_file(self, relative_path: str, content: bytes) -> Path:
        target = self.monitored_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_init_validates_algorithm(self) -> None:
        mgr = BaselineManager(self.monitored_dir, self.baseline_file, "SHA256")
        self.assertEqual(mgr.algorithm, "sha256")

        for bad_alg in ("md5", "sha1", "sha512", "invalid"):
            with self.assertRaises(ValueError):
                BaselineManager(self.monitored_dir, self.baseline_file, bad_alg)

    def test_normalize_path(self) -> None:
        # Standard POSIX relative path
        self.assertEqual(self.manager.normalize_path("docs/guide.txt"), "docs/guide.txt")
        # Leading ./
        self.assertEqual(self.manager.normalize_path("./docs/guide.txt"), "docs/guide.txt")
        # Windows backslashes
        self.assertEqual(self.manager.normalize_path(r"docs\nested\guide.txt"), "docs/nested/guide.txt")
        # Nested subfolder sharing name with monitored_dir is preserved (SEC-02 fix)
        self.assertEqual(self.manager.normalize_path("monitored/sample.txt"), "monitored/sample.txt")
        self.assertEqual(self.manager.normalize_path(r"monitored\docs\guide.txt"), "monitored/docs/guide.txt")
        # Absolute path within monitored directory resolves relative to root
        abs_file = (self.monitored_dir / "sample.txt").resolve()
        self.assertEqual(self.manager.normalize_path(abs_file), "sample.txt")

    def test_normalize_path_rejects_traversal(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.normalize_path("../outside.txt")
        with self.assertRaises(ValueError):
            self.manager.normalize_path("../../etc/passwd")
        with self.assertRaises(ValueError):
            self.manager.normalize_path("")

    def test_nested_duplicate_path_collision(self) -> None:
        # SEC-02: verify monitored/file.txt and monitored/monitored/file.txt remain distinct
        f1 = self.write_file("file.txt", b"top level file")
        f2 = self.write_file("monitored/file.txt", b"nested duplicate folder file")

        baseline = self.manager.generate_baseline()
        self.assertIn("file.txt", baseline)
        self.assertIn("monitored/file.txt", baseline)
        self.assertNotEqual(baseline["file.txt"], baseline["monitored/file.txt"])
        self.assertEqual(len(baseline), 2)

    def test_generate_baseline_success(self) -> None:
        file1 = self.write_file("sample.txt", b"sample content")
        file2 = self.write_file("nested/guide.txt", b"guide content")

        baseline = self.manager.generate_baseline()

        self.assertIn("sample.txt", baseline)
        self.assertIn("nested/guide.txt", baseline)
        self.assertEqual(baseline["sample.txt"], calculate_sha256(file1))
        self.assertEqual(baseline["nested/guide.txt"], calculate_sha256(file2))
        self.assertEqual(len(baseline), 2)

    def test_generate_baseline_missing_directory(self) -> None:
        missing_dir = self.workspace / "does_not_exist"
        mgr = BaselineManager(missing_dir, self.baseline_file, hmac_key=self.test_key)
        with self.assertRaises(FileNotFoundError):
            mgr.generate_baseline()

    def test_generate_baseline_target_is_file(self) -> None:
        file_target = self.write_file("file.txt", b"not a dir")
        mgr = BaselineManager(file_target, self.baseline_file, hmac_key=self.test_key)
        with self.assertRaises(NotADirectoryError):
            mgr.generate_baseline()

    def test_generate_baseline_aborts_on_scanner_errors(self) -> None:
        mock_result = ScanResult(
            root_directory=str(self.monitored_dir),
            files=[{"relative_path": "ok.txt", "sha256": "a" * 64, "size_bytes": 10}],
            errors=[{"relative_path": "blocked.txt", "error": "Permission denied", "error_type": "PermissionError"}],
            total_files=1,
            total_errors=1,
            success=False,
        )

        with mock.patch("src.baseline.scan_directory", return_value=mock_result):
            with self.assertRaises(RuntimeError) as context:
                self.manager.generate_baseline()
            self.assertIn("scan error(s) detected", str(context.exception))

    def test_save_baseline_atomic_persistence(self) -> None:
        test_hash = hashlib.sha256(b"test").hexdigest()
        data = {"sample.txt": test_hash}

        self.manager.save_baseline(data)

        self.assertTrue(self.baseline_file.is_file())
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            raw_payload = json.load(f)

        self.assertEqual(raw_payload["version"], 1)
        self.assertEqual(raw_payload["algorithm"], "sha256")
        self.assertEqual(raw_payload["auth_mode"], "hmac-sha256")
        self.assertIn("hmac", raw_payload)
        self.assertEqual(raw_payload["files"], data)

        # Check no temporary files were left behind
        tmp_files = list(self.baseline_file.parent.glob("*.tmp.*"))
        self.assertEqual(len(tmp_files), 0)

    def test_save_baseline_rejects_invalid_data(self) -> None:
        with self.assertRaises(BaselineCorruptionError):
            self.manager.save_baseline(["not", "a", "dict"])  # type: ignore[arg-type]

        with self.assertRaises(BaselineCorruptionError):
            self.manager.save_baseline({"": "a" * 64})

        with self.assertRaises(BaselineCorruptionError):
            self.manager.save_baseline({"valid.txt": "short_hash"})

        with self.assertRaises(BaselineCorruptionError):
            self.manager.save_baseline({"valid.txt": "z" * 64})  # Non-hex character

    def test_save_baseline_atomic_cleanup_on_error(self) -> None:
        test_hash = hashlib.sha256(b"test").hexdigest()
        data = {"sample.txt": test_hash}

        with mock.patch("src.baseline.os.replace", side_effect=OSError("Disk failure")):
            with self.assertRaises(OSError):
                self.manager.save_baseline(data)

        # Ensure no temp file leaked
        tmp_files = list(self.baseline_file.parent.glob("*.tmp.*"))
        self.assertEqual(len(tmp_files), 0)

    def test_load_baseline_success(self) -> None:
        test_hash = hashlib.sha256(b"test").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        loaded = self.manager.load_baseline()
        self.assertEqual(loaded, data)

    def test_load_baseline_missing_file(self) -> None:
        missing_file = self.workspace / "missing_baseline.json"
        mgr = BaselineManager(self.monitored_dir, missing_file, hmac_key=self.test_key)
        with self.assertRaises(FileNotFoundError):
            mgr.load_baseline()

    def test_load_baseline_malformed_json(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text("{corrupt: json,", encoding="utf-8")

        with self.assertRaises(BaselineCorruptionError) as context:
            self.manager.load_baseline()
        self.assertIn("Malformed baseline JSON", str(context.exception))

    def test_load_baseline_non_dict_structure(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text('["item1", "item2"]', encoding="utf-8")

        with self.assertRaises(BaselineCorruptionError) as context:
            self.manager.load_baseline()
        self.assertIn("Baseline root must be a JSON object", str(context.exception))

    def test_load_baseline_invalid_digest_format(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        corrupt_files = {"file.txt": "invalid_digest"}
        corrupt_hmac = compute_baseline_hmac(self.test_key, corrupt_files)
        payload = {
            "version": 1,
            "algorithm": "sha256",
            "auth_mode": "hmac-sha256",
            "hmac": corrupt_hmac,
            "files": corrupt_files,
        }
        self.baseline_file.write_text(json.dumps(payload), encoding="utf-8")

        with self.assertRaises(BaselineCorruptionError) as context:
            self.manager.load_baseline()
        self.assertIn("Invalid cryptographic digest", str(context.exception))

    def test_load_baseline_rejects_unsigned_by_default(self) -> None:
        test_hash = hashlib.sha256(b"legacy").hexdigest()
        raw_legacy = {
            "sample.txt": test_hash,
            "docs/guide.txt": test_hash,
        }
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(raw_legacy, f)

        with self.assertRaises(BaselineAuthenticationError) as context:
            self.manager.load_baseline()
        self.assertIn("Unsigned baseline detected", str(context.exception))

    def test_load_baseline_allows_unsigned_explicitly(self) -> None:
        test_hash = hashlib.sha256(b"legacy").hexdigest()
        raw_legacy = {
            "sample.txt": test_hash,
            "docs/guide.txt": test_hash,
        }
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(raw_legacy, f)

        loaded = self.manager.load_baseline(allow_unsigned=True)
        self.assertEqual(loaded, raw_legacy)

    def test_hmac_tamper_detection_modified_content(self) -> None:
        test_hash = hashlib.sha256(b"original").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        # Attacker modifies file hash in baseline
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
        payload["files"]["sample.txt"] = hashlib.sha256(b"tampered").hexdigest()
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        with self.assertRaises(BaselineAuthenticationError) as context:
            self.manager.load_baseline()
        self.assertIn("tampered with", str(context.exception))

    def test_hmac_tamper_detection_modified_signature(self) -> None:
        test_hash = hashlib.sha256(b"original").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        # Attacker alters HMAC hex characters
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
        payload["hmac"] = "0" * 64
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        with self.assertRaises(BaselineAuthenticationError) as context:
            self.manager.load_baseline()
        self.assertIn("tampered with", str(context.exception))

    def test_hmac_tamper_detection_missing_signature(self) -> None:
        test_hash = hashlib.sha256(b"original").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        # Attacker strips HMAC field
        with open(self.baseline_file, "r", encoding="utf-8") as f:
            payload = json.load(f)
        del payload["hmac"]
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(payload, f)

        with self.assertRaises(BaselineAuthenticationError) as context:
            self.manager.load_baseline()
        self.assertIn("missing HMAC", str(context.exception))

    def test_hmac_verification_wrong_key(self) -> None:
        test_hash = hashlib.sha256(b"original").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        wrong_key = secrets.token_bytes(32)
        other_manager = BaselineManager(self.monitored_dir, self.baseline_file, hmac_key=wrong_key)

        with self.assertRaises(BaselineAuthenticationError):
            other_manager.load_baseline()

    def test_hmac_verification_missing_key(self) -> None:
        test_hash = hashlib.sha256(b"original").hexdigest()
        data = {"sample.txt": test_hash}
        self.manager.save_baseline(data)

        unkeyed_manager = BaselineManager(self.monitored_dir, self.baseline_file, hmac_key=None)
        with mock.patch.object(unkeyed_manager, "resolve_key", return_value=None):
            with self.assertRaises(BaselineAuthenticationError) as context:
                unkeyed_manager.load_baseline()
            self.assertIn("HMAC key is required", str(context.exception))

    def test_canonical_baseline_bytes_determinism(self) -> None:
        files_a = {
            "z.txt": "a" * 64,
            "a.txt": "b" * 64,
            "m.txt": "C" * 64,  # uppercase hex
        }
        files_b = {
            "a.txt": "b" * 64,
            "m.txt": "c" * 64,  # lowercase hex
            "z.txt": "a" * 64,
        }

        canonical_a = canonical_baseline_bytes(files_a)
        canonical_b = canonical_baseline_bytes(files_b)

        self.assertEqual(canonical_a, canonical_b)
        self.assertNotIn(b" ", canonical_a)  # Whitespace eliminated
        self.assertIn(b'"algorithm":"sha256"', canonical_a)

    def test_migrate_legacy_baseline_success_and_protection(self) -> None:
        test_hash1 = hashlib.sha256(b"f1").hexdigest()
        test_hash2 = hashlib.sha256(b"f2").hexdigest()
        legacy_data = {
            "doc.txt": test_hash1,
            "sample.txt": test_hash2,
        }
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(legacy_data, f)

        # Perform migration with key
        summary = self.manager.migrate_legacy_baseline(key=self.test_key, backup=True)

        self.assertEqual(summary["migrated_files"], 2)
        self.assertEqual(summary["auth_mode"], "hmac-sha256")
        self.assertIsNotNone(summary["backup_file"])
        self.assertTrue(Path(summary["backup_file"]).is_file())

        # Verify newly saved baseline is authenticated and loads cleanly
        loaded = self.manager.load_baseline()
        self.assertEqual(loaded, legacy_data)

        # Attempting to re-migrate an authenticated baseline must raise ValueError
        with self.assertRaises(ValueError) as context:
            self.manager.migrate_legacy_baseline(key=self.test_key)
        self.assertIn("already authenticated", str(context.exception))

    def test_generate_hmac_key_new_destination_succeeds(self) -> None:
        key_path = self.workspace / "new_keys" / "test.key"
        key_bytes = generate_hmac_key(key_path)
        self.assertEqual(len(key_bytes), 32)
        self.assertTrue(key_path.is_file())
        saved_hex = key_path.read_text(encoding="utf-8").strip()
        self.assertEqual(len(saved_hex), 64)
        self.assertEqual(bytes.fromhex(saved_hex), key_bytes)

    def test_generate_hmac_key_existing_destination_raises_file_exists(self) -> None:
        key_path = self.workspace / "existing.key"
        key_path.write_bytes(b"canary_bytes_must_not_change")
        with self.assertRaises(FileExistsError) as context:
            generate_hmac_key(key_path)
        self.assertIn("already exists", str(context.exception))
        self.assertIn("Refusing to overwrite", str(context.exception))

    def test_generate_hmac_key_preserves_existing_key_bytes_on_failure(self) -> None:
        key_path = self.workspace / "immutable.key"
        original_bytes = b"pre_existing_256bit_key_material_bytes"
        key_path.write_bytes(original_bytes)
        with self.assertRaises(FileExistsError):
            generate_hmac_key(key_path)
        self.assertEqual(key_path.read_bytes(), original_bytes)

    def test_generate_hmac_key_repeated_creation_cannot_replace(self) -> None:
        key_path = self.workspace / "repeat.key"
        key1 = generate_hmac_key(key_path)
        first_hex = key_path.read_text(encoding="utf-8")
        with self.assertRaises(FileExistsError):
            generate_hmac_key(key_path)
        second_hex = key_path.read_text(encoding="utf-8")
        self.assertEqual(first_hex, second_hex)
        self.assertEqual(bytes.fromhex(second_hex), key1)

    def test_generate_hmac_key_rejects_overwrite_argument(self) -> None:
        key_path = self.workspace / "no_overwrite.key"
        with self.assertRaises(TypeError) as context:
            generate_hmac_key(key_path, overwrite=True)  # type: ignore[call-arg]
        self.assertIn("unexpected keyword argument", str(context.exception))

    def test_migrate_legacy_baseline_backup_collision_fails_and_preserves_backup(self) -> None:
        test_hash = hashlib.sha256(b"f1").hexdigest()
        raw_legacy = {"sample.txt": test_hash}
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(raw_legacy), encoding="utf-8")

        fixed_time = datetime(2026, 11, 22, 12, 0, 0)
        ts_str = fixed_time.strftime("%Y%m%d_%H%M%S")
        collision_backup = self.baseline_file.with_name(f"{self.baseline_file.name}.legacy.{ts_str}.bak")
        canary_backup_content = '{"canary": "do_not_overwrite_this_backup"}'
        collision_backup.write_text(canary_backup_content, encoding="utf-8")

        with mock.patch("src.baseline.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            with self.assertRaises(FileExistsError) as context:
                self.manager.migrate_legacy_baseline(key=self.test_key)
            self.assertIn("backup collision detected", str(context.exception))

        # Backup file must be untouched
        self.assertEqual(collision_backup.read_text(encoding="utf-8"), canary_backup_content)

    def test_migrate_legacy_baseline_backup_collision_preserves_original_baseline(self) -> None:
        test_hash = hashlib.sha256(b"f1").hexdigest()
        raw_legacy = {"sample.txt": test_hash}
        raw_legacy_bytes = json.dumps(raw_legacy).encode("utf-8")
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_bytes(raw_legacy_bytes)

        fixed_time = datetime(2026, 11, 22, 12, 0, 0)
        ts_str = fixed_time.strftime("%Y%m%d_%H%M%S")
        collision_backup = self.baseline_file.with_name(f"{self.baseline_file.name}.legacy.{ts_str}.bak")
        collision_backup.write_text("existing", encoding="utf-8")

        with mock.patch("src.baseline.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_time
            with self.assertRaises(FileExistsError):
                self.manager.migrate_legacy_baseline(key=self.test_key)

        # Original baseline must be byte-for-byte unchanged
        self.assertEqual(self.baseline_file.read_bytes(), raw_legacy_bytes)

    def test_migrate_legacy_baseline_write_failure_preserves_original_baseline(self) -> None:
        test_hash = hashlib.sha256(b"f1").hexdigest()
        raw_legacy = {"sample.txt": test_hash}
        raw_legacy_bytes = json.dumps(raw_legacy).encode("utf-8")
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_bytes(raw_legacy_bytes)

        with mock.patch("src.baseline.os.replace", side_effect=OSError("Disk failure during replace")):
            with self.assertRaises(OSError):
                self.manager.migrate_legacy_baseline(key=self.test_key)

        # Original baseline must remain byte-for-byte identical
        self.assertEqual(self.baseline_file.read_bytes(), raw_legacy_bytes)

    def test_migrate_legacy_baseline_repeated_migration_preserves_previous_backups(self) -> None:
        test_hash = hashlib.sha256(b"f1").hexdigest()
        raw_legacy = {"sample.txt": test_hash}
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text(json.dumps(raw_legacy), encoding="utf-8")

        summary = self.manager.migrate_legacy_baseline(key=self.test_key, backup=True)
        backup_file = Path(summary["backup_file"])
        self.assertTrue(backup_file.is_file())
        backup_content_orig = backup_file.read_text(encoding="utf-8")

        # Second attempt raises ValueError and does not alter the backup
        with self.assertRaises(ValueError) as context:
            self.manager.migrate_legacy_baseline(key=self.test_key)
        self.assertIn("already authenticated", str(context.exception))

        self.assertEqual(backup_file.read_text(encoding="utf-8"), backup_content_orig)


if __name__ == "__main__":
    unittest.main()
