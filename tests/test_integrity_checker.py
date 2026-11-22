"""Unit and integration tests for Sentinel FIM IntegrityChecker."""

from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.hasher import ScanResult, calculate_sha256
from src.integrity_checker import IntegrityChecker


class IntegrityCheckerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.monitored_dir = self.workspace / "monitored"
        self.monitored_dir.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_file(self, relative_path: str, content: bytes) -> Path:
        target = self.monitored_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_init_validates_algorithm(self) -> None:
        checker = IntegrityChecker(self.monitored_dir, {}, "SHA256")
        self.assertEqual(checker.algorithm, "sha256")

        for bad_alg in ("md5", "sha1", "sha512", "invalid"):
            with self.assertRaises(ValueError):
                IntegrityChecker(self.monitored_dir, {}, bad_alg)

    def test_init_validates_baseline_data_dict(self) -> None:
        with self.assertRaises(ValueError):
            IntegrityChecker(self.monitored_dir, ["not", "a", "dict"])  # type: ignore[arg-type]

    def test_normalize_path(self) -> None:
        checker = IntegrityChecker(self.monitored_dir, {})
        # POSIX path
        self.assertEqual(checker.normalize_path("sample.txt"), "sample.txt")
        # Windows backslashes
        self.assertEqual(checker.normalize_path(r"nested\file.txt"), "nested/file.txt")
        # Leading ./
        self.assertEqual(checker.normalize_path("./sample.txt"), "sample.txt")
        # Preserves nested directory with same name as monitored_dir (SEC-02 fix)
        self.assertEqual(checker.normalize_path("monitored/sample.txt"), "monitored/sample.txt")
        self.assertEqual(checker.normalize_path(r"monitored\nested\file.txt"), "monitored/nested/file.txt")
        # Absolute path within monitored directory
        abs_file = (self.monitored_dir / "sample.txt").resolve()
        self.assertEqual(checker.normalize_path(abs_file), "sample.txt")

    def test_normalize_path_rejects_traversal(self) -> None:
        checker = IntegrityChecker(self.monitored_dir, {})
        with self.assertRaises(ValueError):
            checker.normalize_path("../outside.txt")
        with self.assertRaises(ValueError):
            checker.normalize_path("../../etc/passwd")
        with self.assertRaises(ValueError):
            checker.normalize_path("")

    def test_clean_baseline_no_changes(self) -> None:
        f1 = self.write_file("file1.txt", b"content 1")
        f2 = self.write_file("nested/file2.txt", b"content 2")

        baseline = {
            "file1.txt": calculate_sha256(f1),
            "nested/file2.txt": calculate_sha256(f2),
        }

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertFalse(report["is_compromised"])
        self.assertFalse(report["has_scan_errors"])
        self.assertEqual(report["total_monitored"], 2)
        self.assertEqual(len(report["intact"]), 2)
        self.assertEqual(len(report["created"]), 0)
        self.assertEqual(len(report["modified"]), 0)
        self.assertEqual(len(report["deleted"]), 0)
        self.assertEqual(len(report["errors"]), 0)

    def test_created_file_detection(self) -> None:
        f1 = self.write_file("file1.txt", b"content 1")
        baseline = {"file1.txt": calculate_sha256(f1)}

        # Add rogue file
        f2 = self.write_file("rogue.sh", b"malicious payload")
        rogue_hash = calculate_sha256(f2)

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertTrue(report["is_compromised"])
        self.assertEqual(len(report["created"]), 1)
        self.assertEqual(report["created"][0]["path"], "rogue.sh")
        self.assertEqual(report["created"][0]["current_hash"], rogue_hash)
        self.assertEqual(len(report["intact"]), 1)

    def test_modified_file_detection(self) -> None:
        f1 = self.write_file("sample.txt", b"initial clean content")
        initial_hash = calculate_sha256(f1)
        baseline = {"sample.txt": initial_hash}

        # Modify file
        f1.write_bytes(b"tampered content")
        modified_hash = calculate_sha256(f1)

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertTrue(report["is_compromised"])
        self.assertEqual(len(report["modified"]), 1)
        self.assertEqual(report["modified"][0]["path"], "sample.txt")
        self.assertEqual(report["modified"][0]["baseline_hash"], initial_hash)
        self.assertEqual(report["modified"][0]["current_hash"], modified_hash)

    def test_deleted_file_detection(self) -> None:
        f1 = self.write_file("keep.txt", b"keep content")
        f2 = self.write_file("delete_me.txt", b"delete content")

        baseline = {
            "keep.txt": calculate_sha256(f1),
            "delete_me.txt": calculate_sha256(f2),
        }

        # Delete file from disk
        f2.unlink()

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertTrue(report["is_compromised"])
        self.assertEqual(len(report["deleted"]), 1)
        self.assertEqual(report["deleted"][0]["path"], "delete_me.txt")
        self.assertEqual(report["deleted"][0]["baseline_hash"], baseline["delete_me.txt"])
        self.assertEqual(len(report["intact"]), 1)

    def test_multiple_changes_in_single_scan(self) -> None:
        f_intact = self.write_file("intact.txt", b"intact")
        f_modified = self.write_file("modified.txt", b"before modification")
        f_deleted = self.write_file("deleted.txt", b"to be deleted")

        baseline = {
            "intact.txt": calculate_sha256(f_intact),
            "modified.txt": calculate_sha256(f_modified),
            "deleted.txt": calculate_sha256(f_deleted),
        }

        # Tamper simulation
        f_modified.write_bytes(b"after modification")
        f_deleted.unlink()
        f_created = self.write_file("created.ps1", b"created script")

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertTrue(report["is_compromised"])
        self.assertEqual(len(report["intact"]), 1)
        self.assertEqual(len(report["modified"]), 1)
        self.assertEqual(len(report["deleted"]), 1)
        self.assertEqual(len(report["created"]), 1)

        self.assertEqual(report["intact"][0]["path"], "intact.txt")
        self.assertEqual(report["modified"][0]["path"], "modified.txt")
        self.assertEqual(report["deleted"][0]["path"], "deleted.txt")
        self.assertEqual(report["created"][0]["path"], "created.ps1")

    def test_path_normalization_and_backslash_compatibility(self) -> None:
        f1 = self.write_file("sample.txt", b"clean content")
        f2 = self.write_file("docs/guide.txt", b"guide content")

        baseline = {
            "./sample.txt": calculate_sha256(f1),
            r"docs\guide.txt": calculate_sha256(f2),
        }

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        # Should match cleanly without false alerts
        self.assertFalse(report["is_compromised"])
        self.assertEqual(len(report["intact"]), 2)
        self.assertEqual(len(report["created"]), 0)
        self.assertEqual(len(report["deleted"]), 0)

    def test_alternate_data_stream_detection(self) -> None:
        f1 = self.write_file("normal.txt", b"clean content")
        baseline = {"normal.txt": calculate_sha256(f1)}

        mock_result = ScanResult(
            root_directory=str(self.monitored_dir),
            files=[{
                "relative_path": "normal.txt",
                "sha256": baseline["normal.txt"],
                "size_bytes": 13,
                "alternate_streams": [{"stream_name": ":hidden:$DATA", "size_bytes": 42}],
            }],
            errors=[],
            total_files=1,
            total_errors=0,
            success=True,
        )

        with mock.patch("src.integrity_checker.scan_directory", return_value=mock_result):
            checker = IntegrityChecker(self.monitored_dir, baseline)
            report = checker.check_integrity()

        self.assertTrue(report["is_compromised"])
        self.assertEqual(len(report["suspicious_streams"]), 1)
        self.assertEqual(report["suspicious_streams"][0]["path"], "normal.txt")
        self.assertEqual(
            report["suspicious_streams"][0]["streams"],
            [{"stream_name": ":hidden:$DATA", "size_bytes": 42}],
        )

    def test_nested_duplicate_collision_detection(self) -> None:
        f_top = self.write_file("file.txt", b"top level file")
        f_nested = self.write_file("monitored/file.txt", b"nested subfolder file")

        baseline = {
            "file.txt": calculate_sha256(f_top),
            "monitored/file.txt": calculate_sha256(f_nested),
        }

        checker = IntegrityChecker(self.monitored_dir, baseline)
        report = checker.check_integrity()

        self.assertFalse(report["is_compromised"])
        self.assertEqual(len(report["intact"]), 2)
        self.assertEqual(len(report["created"]), 0)
        self.assertEqual(len(report["deleted"]), 0)

    def test_scanner_errors_surface_and_flag_compromised(self) -> None:
        f1 = self.write_file("valid.txt", b"valid")
        baseline = {"valid.txt": calculate_sha256(f1)}

        # Simulate scanner failure (e.g. unreadable directory or symlink violation)
        mock_result = ScanResult(
            root_directory=str(self.monitored_dir),
            files=[{"relative_path": "valid.txt", "sha256": baseline["valid.txt"], "size_bytes": 5}],
            errors=[{"relative_path": "locked.txt", "error": "Access Denied", "error_type": "PermissionError"}],
            total_files=1,
            total_errors=1,
            success=False,
        )

        with mock.patch("src.integrity_checker.scan_directory", return_value=mock_result):
            checker = IntegrityChecker(self.monitored_dir, baseline)
            report = checker.check_integrity()

        # Incomplete scan MUST flag is_compromised=True and surface errors
        self.assertTrue(report["is_compromised"])
        self.assertTrue(report["has_scan_errors"])
        self.assertEqual(len(report["errors"]), 1)
        self.assertEqual(report["errors"][0]["relative_path"], "locked.txt")

    def test_missing_monitored_directory(self) -> None:
        missing_dir = self.workspace / "missing_dir"
        checker = IntegrityChecker(missing_dir, {})
        with self.assertRaises(FileNotFoundError):
            checker.check_integrity()

    def test_monitored_target_is_file(self) -> None:
        f = self.write_file("file.txt", b"content")
        checker = IntegrityChecker(f, {})
        with self.assertRaises(NotADirectoryError):
            checker.check_integrity()

    def test_public_api_and_return_structure_compatibility(self) -> None:
        f = self.write_file("sample.txt", b"sample")
        checker = IntegrityChecker(self.monitored_dir, {"sample.txt": calculate_sha256(f)})
        report = checker.check_integrity()

        expected_keys = {
            "intact",
            "modified",
            "created",
            "deleted",
            "errors",
            "has_scan_errors",
            "total_monitored",
            "is_compromised",
        }
        self.assertTrue(expected_keys.issubset(set(report.keys())))


if __name__ == "__main__":
    unittest.main()
