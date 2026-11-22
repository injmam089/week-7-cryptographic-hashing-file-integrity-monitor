"""Phase 1 tests for Sentinel FIM hashing and directory scanning."""

import hashlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from src.hasher import (
    DEFAULT_CHUNK_SIZE,
    MAX_STABILITY_RETRIES,
    RETRY_BACKOFF_SECONDS,
    FileHasher,
    FileStabilityError,
    _safe_error_relative_path,
    _validate_chunk_size,
    calculate_sha256,
    get_alternate_data_streams,
    scan_directory,
)


class HasherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def write(self, relative: str, content: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        return path

    def test_known_sha256_vector_and_empty_file(self) -> None:
        vector = self.write("vector.txt", b"abc")
        empty = self.write("empty.bin", b"")
        self.assertEqual(calculate_sha256(vector), hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(calculate_sha256(empty), hashlib.sha256(b"").hexdigest())

    def test_large_file_is_streamed_across_multiple_chunks(self) -> None:
        content = (b"0123456789abcdef" * 1024) + b"tail"
        path = self.write("large.bin", content)
        self.assertEqual(calculate_sha256(path, 4096), hashlib.sha256(content).hexdigest())

    def test_invalid_paths_and_chunk_sizes(self) -> None:
        with self.assertRaises(FileNotFoundError):
            calculate_sha256(self.root / "missing")
        for value in (0, -1, True, False, None, 1.5, "1024"):
            with self.assertRaises(ValueError):
                _validate_chunk_size(value)  # type: ignore[arg-type]

    def test_nested_posix_paths_size_and_sorting(self) -> None:
        self.write("z.txt", b"z")
        self.write("nested/a.txt", b"abcd")
        result = scan_directory(self.root)
        self.assertTrue(result.success)
        self.assertEqual([item["relative_path"] for item in result.files], ["nested/a.txt", "z.txt"])
        self.assertEqual(result.files[0]["size_bytes"], 4)
        self.assertEqual(result.total_files, 2)
        self.assertEqual(result.total_errors, 0)
        self.assertEqual(result.root_directory, str(self.root.resolve()))

    def test_scan_uses_hash_descriptor_size_after_file_replacement(self) -> None:
        path = self.write("replace-during-scan.txt", b"old")
        replacement_content = b"replacement has a different length"
        replacement = self.write("replacement-source.txt", replacement_content)
        original_resolve = Path.resolve
        replaced = False

        def replace_then_resolve(candidate, *args, **kwargs):
            nonlocal replaced
            if candidate == path and not replaced:
                os.replace(replacement, path)
                replaced = True
            return original_resolve(candidate, *args, **kwargs)

        with mock.patch("src.hasher.Path.resolve", new=replace_then_resolve):
            result = scan_directory(self.root)

        record = next(item for item in result.files if item["relative_path"] == "replace-during-scan.txt")
        self.assertEqual(record["sha256"], hashlib.sha256(replacement_content).hexdigest())
        self.assertEqual(record["size_bytes"], len(replacement_content))

    def test_symlinks_are_skipped_when_supported(self) -> None:
        target = self.write("target.txt", b"target")
        link = self.root / "link.txt"
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable in this environment")
        result = scan_directory(self.root)
        self.assertEqual(result.total_files, 1)
        self.assertFalse(result.success)
        self.assertEqual(result.errors[0]["relative_path"], "link.txt")

    def test_symbolic_link_root_is_rejected_when_supported(self) -> None:
        linked_root = self.root.parent / f"{self.root.name}-link"
        try:
            linked_root.symlink_to(self.root, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symbolic links are unavailable in this environment")
        try:
            with self.assertRaises(ValueError):
                scan_directory(linked_root)
        finally:
            linked_root.unlink()

    def test_file_symlink_is_skipped_with_mocked_lstat(self) -> None:
        link = self.write("mock-link.txt", b"placeholder")
        original_lstat = Path.lstat

        def lstat_with_link(path):
            if path == link:
                return SimpleNamespace(st_mode=stat.S_IFLNK)
            return original_lstat(path)

        with mock.patch("src.hasher.Path.lstat", new=lstat_with_link):
            result = scan_directory(self.root)
        self.assertEqual(result.total_files, 0)
        self.assertEqual(result.errors[0]["relative_path"], "mock-link.txt")

    def test_symlink_root_is_rejected_with_mocked_lstat(self) -> None:
        with mock.patch("src.hasher.Path.lstat", return_value=SimpleNamespace(st_mode=stat.S_IFLNK)):
            with self.assertRaises(ValueError):
                scan_directory(self.root)

    def test_unreadable_file_is_reported(self) -> None:
        self.write("blocked.txt", b"secret")
        with mock.patch("src.hasher._calculate_sha256_with_size", side_effect=PermissionError("denied")):
            result = scan_directory(self.root)
        self.assertFalse(result.success)
        self.assertEqual(result.errors[0]["error_type"], "PermissionError")
        self.assertEqual(result.errors[0]["relative_path"], "blocked.txt")

    def test_open_failure_is_reported_without_mocking_hasher(self) -> None:
        self.write("open-fails.txt", b"secret")
        with mock.patch("src.hasher.os.open", side_effect=PermissionError("open denied")):
            result = scan_directory(self.root)
        self.assertFalse(result.success)
        self.assertEqual(result.errors[0]["error_type"], "PermissionError")
        self.assertEqual(result.errors[0]["relative_path"], "open-fails.txt")

    def test_directory_traversal_error_is_reported(self) -> None:
        def broken_walk(root, followlinks, onerror):
            onerror(PermissionError(13, "denied", str(self.root / "private")))
            return iter(())

        with mock.patch("src.hasher.os.walk", side_effect=broken_walk):
            result = scan_directory(self.root)
        self.assertFalse(result.success)
        self.assertEqual(result.errors[0]["relative_path"], "private")
        self.assertEqual(result.errors[0]["error_type"], "PermissionError")

    def test_relative_walk_error_filename_is_preserved(self) -> None:
        self.assertEqual(_safe_error_relative_path("private", self.root), "private")
        self.assertEqual(_safe_error_relative_path("../outside", self.root), ".")

    def test_detects_replacement_between_lstat_and_open(self) -> None:
        path = self.write("replace.txt", b"before")
        replacement = self.write("replacement.txt", b"after")
        actual_open = os.open

        def replace_then_open(file_path, flags):
            os.replace(replacement, path)
            return actual_open(file_path, flags)

        with mock.patch("src.hasher.os.open", side_effect=replace_then_open):
            with self.assertRaises(FileStabilityError):
                calculate_sha256(path)

    def test_detects_metadata_change_during_streaming(self) -> None:
        path = self.write("changing.txt", b"content")
        actual_fstat = os.fstat
        calls = 0

        def altered_fstat(descriptor):
            nonlocal calls
            calls += 1
            value = actual_fstat(descriptor)
            if calls == 2:
                return SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_mode=value.st_mode,
                    st_size=value.st_size + 1,
                    st_mtime_ns=value.st_mtime_ns,
                    st_ctime_ns=value.st_ctime_ns,
                )
            return value

        with mock.patch("src.hasher.os.fstat", side_effect=altered_fstat):
            with self.assertRaises(FileStabilityError):
                calculate_sha256(path)

    def test_detects_permission_change_during_streaming(self) -> None:
        path = self.write("permissions-changing.txt", b"content")
        actual_fstat = os.fstat
        calls = 0

        def altered_fstat(descriptor):
            nonlocal calls
            calls += 1
            value = actual_fstat(descriptor)
            if calls == 2:
                return SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_mode=value.st_mode ^ stat.S_IXUSR,
                    st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns,
                    st_ctime_ns=value.st_ctime_ns,
                )
            return value

        with mock.patch("src.hasher.os.fstat", side_effect=altered_fstat):
            with self.assertRaises(FileStabilityError):
                calculate_sha256(path)

    def test_detects_ctime_change_during_streaming(self) -> None:
        path = self.write("ctime-changing.txt", b"content")
        actual_fstat = os.fstat
        calls = 0

        def altered_fstat(descriptor):
            nonlocal calls
            calls += 1
            value = actual_fstat(descriptor)
            if calls == 2:
                return SimpleNamespace(
                    st_dev=value.st_dev,
                    st_ino=value.st_ino,
                    st_mode=value.st_mode,
                    st_size=value.st_size,
                    st_mtime_ns=value.st_mtime_ns,
                    st_ctime_ns=value.st_ctime_ns + 1,
                )
            return value

        with mock.patch("src.hasher.os.fstat", side_effect=altered_fstat):
            with self.assertRaises(FileStabilityError):
                calculate_sha256(path)

    def test_rejects_non_regular_opened_descriptor(self) -> None:
        path = self.write("ordinary.txt", b"content")
        with mock.patch("src.hasher.os.fstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR)):
            with self.assertRaises(FileStabilityError):
                calculate_sha256(path)

    def test_file_hasher_enforces_sha256_and_delegates(self) -> None:
        path = self.write("wrapped.txt", b"wrapped")
        self.assertEqual(FileHasher("SHA256").calculate_hash(path), hashlib.sha256(b"wrapped").hexdigest())
        self.assertEqual(FileHasher().BUFFER_SIZE, DEFAULT_CHUNK_SIZE)
        for algorithm in ("md5", "sha1", "sha512", None):
            with self.assertRaises(ValueError):
                FileHasher(algorithm)  # type: ignore[arg-type]

    def test_transient_stability_error_retries_and_recovers(self) -> None:
        path = self.write("transient.txt", b"transient data")
        attempts = 0
        expected_digest = hashlib.sha256(b"transient data").hexdigest()

        def flakey_calc(target, chunk_size=DEFAULT_CHUNK_SIZE):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                raise FileStabilityError(f"Transient lock on {target}")
            return (expected_digest, len(b"transient data"))

        with mock.patch("src.hasher._calculate_sha256_with_size_once", side_effect=flakey_calc):
            result = scan_directory(self.root)

        self.assertTrue(result.success)
        self.assertEqual(result.total_errors, 0)
        self.assertEqual(result.total_files, 1)
        self.assertEqual(result.files[0]["sha256"], expected_digest)
        self.assertEqual(attempts, 2)

    def test_persistent_stability_error_fails_after_max_retries(self) -> None:
        path = self.write("permanent_fail.txt", b"failing data")
        attempts = 0

        def always_fail(target, chunk_size=DEFAULT_CHUNK_SIZE):
            nonlocal attempts
            attempts += 1
            raise FileStabilityError(f"Persistent modification on {target}")

        with mock.patch("src.hasher._calculate_sha256_with_size_once", side_effect=always_fail):
            result = scan_directory(self.root)

        self.assertFalse(result.success)
        self.assertEqual(result.total_errors, 1)
        self.assertEqual(result.errors[0]["error_type"], "FileStabilityError")
        # 1 initial attempt + MAX_STABILITY_RETRIES retries
        self.assertEqual(attempts, 1 + MAX_STABILITY_RETRIES)

    def test_alternate_data_streams_enumeration_on_windows(self) -> None:
        path = self.write("ads_test.txt", b"primary data")
        if sys.platform != "win32":
            self.assertEqual(get_alternate_data_streams(path), [])
            return

        ads_path = self.root / "ads_test.txt:hidden_payload"
        try:
            with open(ads_path, "wb") as f:
                f.write(b"secret stream content")
        except OSError:
            self.skipTest("NTFS Alternate Data Streams not supported by filesystem")

        streams = get_alternate_data_streams(path)
        self.assertTrue(any("hidden_payload" in s["stream_name"] for s in streams))

        # Ensure primary ::$DATA is excluded from alternate stream reporting
        self.assertFalse(any(s["stream_name"].lower() == "::$data" for s in streams))



if __name__ == "__main__":
    unittest.main()
