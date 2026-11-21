from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Union

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import calculate_sha256
    from src.baseline import BaselineManager
    from src.integrity_checker import IntegrityChecker
except ImportError:
    from hasher import calculate_sha256  # type: ignore[no-redef]
    from baseline import BaselineManager  # type: ignore[no-redef]
    from integrity_checker import IntegrityChecker  # type: ignore[no-redef]

DEFAULT_CONFIG_PATH = "config/fim_config.json"
DEFAULT_MONITORED_DIR = "monitored"
DEFAULT_BASELINE_FILE = "output/baseline.json"


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from JSON file or fall back to defaults."""
    defaults: Dict[str, Any] = {
        "algorithm": "sha256",
        "monitored_directory": DEFAULT_MONITORED_DIR,
        "baseline_file": DEFAULT_BASELINE_FILE,
    }
    if not config_path.is_file():
        return defaults
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = json.load(f)
            if not isinstance(user_config, dict):
                raise ValueError("Config root must be a JSON object")
            defaults.update(user_config)
    except Exception as exc:
        print(f"[WARN] Failed to parse config file ({exc}). Utilizing standard defaults.", file=sys.stderr)
    return defaults


def scan_directory(directory_path: Union[str, Path]) -> Dict[str, str]:
    """Scan directory and return mapping of relative paths to SHA-256 digests.

    Delegates to BaselineManager for authoritative descriptor-bound scanning.
    """
    manager = BaselineManager(monitored_dir=directory_path, baseline_file=DEFAULT_BASELINE_FILE)
    return manager.generate_baseline()


def _format_display_path(path: str, monitored_dir: Path) -> str:
    """Format file path with monitored directory prefix for clear terminal reporting."""
    posix_path = str(path).replace("\\", "/").strip()
    prefix = monitored_dir.as_posix().strip("./")
    if prefix and not posix_path.startswith(prefix + "/"):
        return f"{prefix}/{posix_path}"
    return posix_path


def run_baseline(monitored_dir: Path, baseline_file: Path) -> int:
    """Generate baseline hashes for monitored directory and save to baseline JSON file."""
    baseline_target_display = baseline_file.as_posix()
    print("=" * 65)
    print(" SENTINEL FIM -- BASELINE SNAPSHOT GENERATION")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir.as_posix()}")
    print(f"[*] Baseline Target     : {baseline_target_display}")
    print(f"[*] Hash Algorithm      : SHA-256 (4096-byte chunk streaming)")
    print("-" * 65)

    if not monitored_dir.exists():
        print(f"[ERROR] Monitored directory '{monitored_dir.as_posix()}' does not exist.", file=sys.stderr)
        return 1

    try:
        manager = BaselineManager(monitored_dir=monitored_dir, baseline_file=baseline_file)
        baseline_data = manager.generate_baseline()
        manager.save_baseline(baseline_data)
    except Exception as exc:
        print(f"[ERROR] Baseline generation failed: {exc}", file=sys.stderr)
        return 1

    for rel_path, digest in baseline_data.items():
        display_path = _format_display_path(rel_path, monitored_dir)
        print(f"[RECORDED] {display_path}")
        print(f"           Hash: {digest}")

    print("-" * 65)
    print(f"[SUCCESS] Baseline successfully established for {len(baseline_data)} file(s).")
    print(f"[SUCCESS] Saved snapshot to: {baseline_target_display}")
    print("=" * 65)
    return 0


def run_monitor(monitored_dir: Path, baseline_file: Path) -> int:
    """Verify live filesystem integrity against recorded baseline snapshot."""
    baseline_target_display = baseline_file.as_posix()
    print("=" * 65)
    print(" SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir.as_posix()}")
    print(f"[*] Reference Baseline  : {baseline_target_display}")
    print("-" * 65)

    if not baseline_file.is_file():
        print(
            f"[ERROR] Baseline database not found: '{baseline_target_display}'.\n"
            f"        Run 'python src/fim_monitor.py --mode baseline' first.",
            file=sys.stderr,
        )
        return 1

    try:
        manager = BaselineManager(monitored_dir=monitored_dir, baseline_file=baseline_file)
        baseline_data = manager.load_baseline()
    except Exception as exc:
        print(f"[ERROR] Failed to load baseline database: {exc}", file=sys.stderr)
        return 1

    try:
        checker = IntegrityChecker(monitored_dir=monitored_dir, baseline_data=baseline_data)
        report = checker.check_integrity()
    except Exception as exc:
        print(f"[ERROR] Integrity audit failed: {exc}", file=sys.stderr)
        return 1

    if report["created"]:
        for item in report["created"]:
            display_path = _format_display_path(item["path"], monitored_dir)
            print(f"[ALERT] CREATED:  {display_path}\n        SHA-256: {item['current_hash']}")

    if report["modified"]:
        for item in report["modified"]:
            display_path = _format_display_path(item["path"], monitored_dir)
            print(
                f"[ALERT] MODIFIED: {display_path}\n"
                f"        Baseline SHA-256: {item['baseline_hash']}\n"
                f"        Current  SHA-256: {item['current_hash']}"
            )

    if report["deleted"]:
        for item in report["deleted"]:
            display_path = _format_display_path(item["path"], monitored_dir)
            print(f"[ALERT] DELETED:  {display_path}\n        Expected SHA-256: {item['baseline_hash']}")

    if report["errors"]:
        for err in report["errors"]:
            display_path = _format_display_path(err.get("relative_path", "."), monitored_dir)
            print(f"[ERROR] SCAN ERROR: {display_path} - {err.get('error')}")

    if report["intact"] and not report["is_compromised"]:
        for item in report["intact"]:
            display_path = _format_display_path(item["path"], monitored_dir)
            print(f"[OK] INTACT:    {display_path}")

    print("-" * 65)
    print("AUDIT SUMMARY:")
    print(f"  Baseline Files : {len(baseline_data)}")
    print(f"  Current Files  : {report['total_monitored']}")
    print(f"  Intact Files   : {len(report['intact'])}")
    print(f"  Created Files  : {len(report['created'])}")
    print(f"  Modified Files : {len(report['modified'])}")
    print(f"  Deleted Files  : {len(report['deleted'])}")
    if report["errors"]:
        print(f"  Scan Errors    : {len(report['errors'])}")
    print("-" * 65)

    if report["is_compromised"]:
        anomaly_count = (
            len(report["created"])
            + len(report["modified"])
            + len(report["deleted"])
            + len(report["errors"])
        )
        print(f"[STATUS] INTEGRITY COMPROMISED: {anomaly_count} anomaly(ies) detected!")
        print("=" * 65)
        return 1
    else:
        print("[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.")
        print("=" * 65)
        return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel FIM -- Lightweight Cryptographic File Integrity Monitor (SHA-256)"
    )
    parser.add_argument("--mode", choices=["baseline", "monitor"], required=True)
    parser.add_argument("--dir", dest="monitored_dir", default=None)
    parser.add_argument("--baseline", dest="baseline_file", default=None)
    parser.add_argument("--config", dest="config_file", default=DEFAULT_CONFIG_PATH)

    args = parser.parse_args()
    cfg = load_config(Path(args.config_file))

    monitored_dir = Path(args.monitored_dir or cfg.get("monitored_directory", DEFAULT_MONITORED_DIR))
    baseline_file = Path(args.baseline_file or cfg.get("baseline_file", DEFAULT_BASELINE_FILE))

    if args.mode == "baseline":
        sys.exit(run_baseline(monitored_dir, baseline_file))
    elif args.mode == "monitor":
        sys.exit(run_monitor(monitored_dir, baseline_file))


if __name__ == "__main__":
    main()
