"""Unit and integration tests for Sentinel FIM fim_monitor CLI orchestrator."""

from __future__ import annotations

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from src.fim_monitor import (
    DEFAULT_BASELINE_FILE,
    DEFAULT_MONITORED_DIR,
    _format_display_path,
    load_config,
    main,
    run_baseline,
    run_monitor,
    scan_directory,
)


class FimMonitorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.workspace = Path(self.temp_dir.name)
        self.monitored_dir = self.workspace / "monitored"
        self.monitored_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.workspace / "output" / "baseline.json"
        self.config_file = self.workspace / "config" / "fim_config.json"
        self.config_file.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def write_file(self, relative_path: str, content: bytes) -> Path:
        target = self.monitored_dir / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def test_load_config_defaults_on_missing_file(self) -> None:
        cfg = load_config(self.workspace / "nonexistent.json")
        self.assertEqual(cfg["algorithm"], "sha256")
        self.assertEqual(cfg["monitored_directory"], DEFAULT_MONITORED_DIR)
        self.assertEqual(cfg["baseline_file"], DEFAULT_BASELINE_FILE)

    def test_load_config_valid_file(self) -> None:
        custom_cfg = {
            "algorithm": "sha256",
            "monitored_directory": "custom_monitored",
            "baseline_file": "custom_output/baseline.json",
        }
        self.config_file.write_text(json.dumps(custom_cfg), encoding="utf-8")
        cfg = load_config(self.config_file)
        self.assertEqual(cfg["monitored_directory"], "custom_monitored")
        self.assertEqual(cfg["baseline_file"], "custom_output/baseline.json")

    def test_load_config_malformed_json_fallback(self) -> None:
        self.config_file.write_text("{ broken json", encoding="utf-8")
        with mock.patch("sys.stderr", new=io.StringIO()):
            cfg = load_config(self.config_file)
        self.assertEqual(cfg["algorithm"], "sha256")

    def test_format_display_path(self) -> None:
        mon_dir = Path("monitored")
        self.assertEqual(_format_display_path("sample.txt", mon_dir), "monitored/sample.txt")
        self.assertEqual(_format_display_path("docs/guide.txt", mon_dir), "monitored/docs/guide.txt")
        self.assertEqual(_format_display_path("monitored/sample.txt", mon_dir), "monitored/sample.txt")

    def test_scan_directory_helper(self) -> None:
        self.write_file("file1.txt", b"hello")
        res = scan_directory(self.monitored_dir)
        self.assertIn("file1.txt", res)
        self.assertEqual(len(res["file1.txt"]), 64)

    def test_run_baseline_missing_directory(self) -> None:
        missing_dir = self.workspace / "no_such_dir"
        with mock.patch("sys.stdout", new=io.StringIO()), mock.patch("sys.stderr", new=io.StringIO()):
            code = run_baseline(missing_dir, self.baseline_file)
        self.assertEqual(code, 1)

    def test_run_baseline_success(self) -> None:
        self.write_file("test.txt", b"data")
        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            code = run_baseline(self.monitored_dir, self.baseline_file)
        self.assertEqual(code, 0)
        self.assertTrue(self.baseline_file.is_file())
        output = stdout.getvalue()
        self.assertIn("SENTINEL FIM -- BASELINE SNAPSHOT GENERATION", output)
        self.assertIn("Baseline successfully established", output)

    def test_run_monitor_missing_baseline(self) -> None:
        with mock.patch("sys.stdout", new=io.StringIO()), mock.patch("sys.stderr", new=io.StringIO()):
            code = run_monitor(self.monitored_dir, self.baseline_file)
        self.assertEqual(code, 1)

    def test_run_monitor_clean(self) -> None:
        self.write_file("test.txt", b"data")
        with mock.patch("sys.stdout", new=io.StringIO()):
            run_baseline(self.monitored_dir, self.baseline_file)
        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            code = run_monitor(self.monitored_dir, self.baseline_file)
        self.assertEqual(code, 0)
        output = stdout.getvalue()
        self.assertIn("[STATUS] INTEGRITY VERIFIED", output)
        self.assertIn("[OK] INTACT:", output)

    def test_run_monitor_detects_created_modified_deleted(self) -> None:
        f_mod = self.write_file("modify.txt", b"original")
        f_del = self.write_file("delete.txt", b"to be deleted")
        with mock.patch("sys.stdout", new=io.StringIO()):
            run_baseline(self.monitored_dir, self.baseline_file)

        # Modify
        f_mod.write_bytes(b"tampered")
        # Delete
        f_del.unlink()
        # Create
        self.write_file("rogue.txt", b"malicious")

        stdout = io.StringIO()
        with mock.patch("sys.stdout", new=stdout):
            code = run_monitor(self.monitored_dir, self.baseline_file)
        self.assertEqual(code, 1)
        output = stdout.getvalue()
        self.assertIn("[ALERT] CREATED:", output)
        self.assertIn("rogue.txt", output)
        self.assertIn("[ALERT] MODIFIED:", output)
        self.assertIn("modify.txt", output)
        self.assertIn("[ALERT] DELETED:", output)
        self.assertIn("delete.txt", output)
        self.assertIn("[STATUS] INTEGRITY COMPROMISED: 3 anomaly(ies) detected!", output)

    def test_cli_main_baseline_and_monitor(self) -> None:
        self.write_file("test.txt", b"data")
        test_args_base = [
            "fim_monitor.py",
            "--mode",
            "baseline",
            "--dir",
            str(self.monitored_dir),
            "--baseline",
            str(self.baseline_file),
        ]
        with mock.patch("sys.argv", test_args_base), mock.patch("sys.stdout", new=io.StringIO()):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertEqual(exit_ctx.exception.code, 0)

        test_args_mon = [
            "fim_monitor.py",
            "--mode",
            "monitor",
            "--dir",
            str(self.monitored_dir),
            "--baseline",
            str(self.baseline_file),
        ]
        with mock.patch("sys.argv", test_args_mon), mock.patch("sys.stdout", new=io.StringIO()):
            with self.assertRaises(SystemExit) as exit_ctx:
                main()
            self.assertEqual(exit_ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
