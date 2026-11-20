"""Unit and integration tests for Sentinel FIM BaselineManager."""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.baseline import BaselineManager
from src.hasher import ScanResult, calculate_sha256


class BaselineManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.monitored_dir = self.workspace / "monitored"
        self.monitored_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.workspace / "output" / "baseline.json"
        self.manager = BaselineManager(self.monitored_dir, self.baseline_file)

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
        # Legacy monitored_dir folder prefix
        self.assertEqual(self.manager.normalize_path("monitored/sample.txt"), "sample.txt")
        self.assertEqual(self.manager.normalize_path(r"monitored\docs\guide.txt"), "docs/guide.txt")

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
        mgr = BaselineManager(missing_dir, self.baseline_file)
        with self.assertRaises(FileNotFoundError):
            mgr.generate_baseline()

    def test_generate_baseline_target_is_file(self) -> None:
        file_target = self.write_file("file.txt", b"not a dir")
        mgr = BaselineManager(file_target, self.baseline_file)
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
            loaded = json.load(f)
        self.assertEqual(loaded, data)

        # Check no temporary files were left behind
        tmp_files = list(self.baseline_file.parent.glob("*.tmp.*"))
        self.assertEqual(len(tmp_files), 0)

    def test_save_baseline_rejects_invalid_data(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.save_baseline(["not", "a", "dict"])  # type: ignore[arg-type]

        with self.assertRaises(ValueError):
            self.manager.save_baseline({"": "a" * 64})

        with self.assertRaises(ValueError):
            self.manager.save_baseline({"valid.txt": "short_hash"})

        with self.assertRaises(ValueError):
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
        mgr = BaselineManager(self.monitored_dir, missing_file)
        with self.assertRaises(FileNotFoundError):
            mgr.load_baseline()

    def test_load_baseline_malformed_json(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text("{corrupt: json,", encoding="utf-8")

        with self.assertRaises(ValueError) as context:
            self.manager.load_baseline()
        self.assertIn("Malformed baseline JSON", str(context.exception))

    def test_load_baseline_non_dict_structure(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text('["item1", "item2"]', encoding="utf-8")

        with self.assertRaises(ValueError) as context:
            self.manager.load_baseline()
        self.assertIn("Baseline root must be a JSON object", str(context.exception))

    def test_load_baseline_invalid_digest_format(self) -> None:
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        self.baseline_file.write_text('{"file.txt": "invalid_digest"}', encoding="utf-8")

        with self.assertRaises(ValueError) as context:
            self.manager.load_baseline()
        self.assertIn("Invalid cryptographic digest", str(context.exception))

    def test_load_baseline_legacy_path_normalization(self) -> None:
        test_hash = hashlib.sha256(b"legacy").hexdigest()
        # Legacy baseline containing folder name prefix
        raw_legacy = {
            "monitored/sample.txt": test_hash,
            "monitored/docs/guide.txt": test_hash,
        }
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(raw_legacy, f)

        # Loaded with normalization (default)
        loaded = self.manager.load_baseline(normalize_legacy=True)
        self.assertIn("sample.txt", loaded)
        self.assertIn("docs/guide.txt", loaded)
        self.assertEqual(loaded["sample.txt"], test_hash)

        # Loaded without normalization
        loaded_raw = self.manager.load_baseline(normalize_legacy=False)
        self.assertIn("monitored/sample.txt", loaded_raw)

    def test_load_baseline_windows_backslash_normalization(self) -> None:
        test_hash = hashlib.sha256(b"windows").hexdigest()
        raw_windows = {
            r"monitored\nested\sample.txt": test_hash,
        }
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(raw_windows, f)

        loaded = self.manager.load_baseline(normalize_legacy=True)
        self.assertIn("nested/sample.txt", loaded)
        self.assertEqual(loaded["nested/sample.txt"], test_hash)


if __name__ == "__main__":
    unittest.main()
