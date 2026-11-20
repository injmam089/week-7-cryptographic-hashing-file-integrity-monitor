"""Sentinel FIM - Main Orchestration Entry Point & CLI.

Provides command-line interface for File Integrity Monitoring (FIM).
Supports two primary modes:
  --mode baseline: Recursively scans the target directory, hashes all files
                   with SHA-256, and records a trusted baseline snapshot to JSON.
  --mode monitor:  Re-scans the target directory, compares live hashes against
                   the baseline database, and generates real-time security alerts.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

# Ensure project root is in sys.path for direct invocation and package imports
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import calculate_sha256
except ImportError:
    from hasher import calculate_sha256


DEFAULT_CONFIG_PATH = "config/fim_config.json"
DEFAULT_MONITORED_DIR = "monitored"
DEFAULT_BASELINE_FILE = "output/baseline.json"


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from JSON file with fallback defaults.

    Args:
        config_path: Path to fim_config.json.

    Returns:
        Configuration dictionary containing monitored_directory, baseline_file, algorithm.
    """
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
            defaults.update(user_config)
    except Exception as exc:
        print(f"[WARN] Failed to parse config file ({exc}). Utilizing standard defaults.", file=sys.stderr)

    return defaults


def scan_directory(directory_path: Path) -> Dict[str, str]:
    """Recursively traverse a directory and compute SHA-256 hashes for all files.

    Uses POSIX-style relative paths to ensure cross-platform compatibility
    across Windows, Linux, and macOS.

    Args:
        directory_path: Directory to traverse recursively.

    Returns:
        Dictionary mapping normalized relative filepaths to SHA-256 hex digests.
    """
    hashes: Dict[str, str] = {}
    resolved_dir = directory_path.resolve()

    if not directory_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {directory_path}")

    for root, _, files in os.walk(directory_path):
        for filename in sorted(files):
            full_path = Path(root) / filename
            if full_path.is_file():
                # Cross-platform normalized path (forward slashes)
                try:
                    rel_path = full_path.resolve().relative_to(project_root.resolve()).as_posix()
                except ValueError:
                    rel_path = full_path.as_posix()

                file_hash = calculate_sha256(full_path)
                hashes[rel_path] = file_hash

    return dict(sorted(hashes.items()))


def run_baseline(monitored_dir: Path, baseline_file: Path) -> int:
    """Execute baseline mode: scan files, compute hashes, and persist baseline.json.

    Args:
        monitored_dir: Directory containing assets to monitor.
        baseline_file: Target JSON file path where baseline snapshot is saved.

    Returns:
        Exit code (0 for success, 1 for error).
    """
    print("=" * 65)
    print(" SENTINEL FIM -- BASELINE SNAPSHOT GENERATION")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir}")
    print(f"[*] Baseline Target     : {baseline_file}")
    print(f"[*] Hash Algorithm      : SHA-256 (4096-byte chunk streaming)")
    print("-" * 65)

    if not monitored_dir.exists():
        print(f"[ERROR] Monitored directory '{monitored_dir}' does not exist.", file=sys.stderr)
        return 1

    try:
        baseline_data = scan_directory(monitored_dir)
    except Exception as exc:
        print(f"[ERROR] Failed scanning directory: {exc}", file=sys.stderr)
        return 1

    # Ensure output directory exists
    baseline_file.parent.mkdir(parents=True, exist_ok=True)

    with open(baseline_file, "w", encoding="utf-8") as f:
        json.dump(baseline_data, f, indent=4)

    for path, digest in baseline_data.items():
        print(f"[RECORDED] {path}")
        print(f"           Hash: {digest}")

    print("-" * 65)
    print(f"[SUCCESS] Baseline successfully established for {len(baseline_data)} file(s).")
    print(f"[SUCCESS] Saved snapshot to: {baseline_file.as_posix()}")
    print("=" * 65)
    return 0


def run_monitor(monitored_dir: Path, baseline_file: Path) -> int:
    """Execute monitor mode: verify live filesystem state against baseline.json.

    Args:
        monitored_dir: Directory to audit.
        baseline_file: Reference baseline JSON file.

    Returns:
        Exit code (0 if intact, 1 if anomalies detected or error occurred).
    """
    print("=" * 65)
    print(" SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir}")
    print(f"[*] Reference Baseline  : {baseline_file}")
    print("-" * 65)

    if not baseline_file.is_file():
        print(
            f"[ERROR] Baseline database not found: '{baseline_file}'.\n"
            f"        Run 'python src/fim_monitor.py --mode baseline' first to establish trusted state.",
            file=sys.stderr,
        )
        return 1

    # Load baseline
    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline_data: Dict[str, str] = json.load(f)
    except Exception as exc:
        print(f"[ERROR] Failed to load baseline database: {exc}", file=sys.stderr)
        return 1

    # Scan live files
    try:
        current_data = scan_directory(monitored_dir)
    except Exception as exc:
        print(f"[ERROR] Failed during live scan: {exc}", file=sys.stderr)
        return 1

    baseline_files = set(baseline_data.keys())
    current_files = set(current_data.keys())

    created_files = sorted(current_files - baseline_files)
    deleted_files = sorted(baseline_files - current_files)
    common_files = sorted(baseline_files & current_files)

    modified_files = []
    intact_files = []

    for path in common_files:
        if baseline_data[path] == current_data[path]:
            intact_files.append(path)
        else:
            modified_files.append(path)

    # Output security alerts
    anomalies_detected = False

    if created_files:
        anomalies_detected = True
        for path in created_files:
            print(f"[ALERT] CREATED:  {path}")
            print(f"        SHA-256: {current_data[path]}")

    if modified_files:
        anomalies_detected = True
        for path in modified_files:
            print(f"[ALERT] MODIFIED: {path}")
            print(f"        Baseline SHA-256: {baseline_data[path]}")
            print(f"        Current  SHA-256: {current_data[path]}")

    if deleted_files:
        anomalies_detected = True
        for path in deleted_files:
            print(f"[ALERT] DELETED:  {path}")
            print(f"        Expected SHA-256: {baseline_data[path]}")

    if intact_files and not anomalies_detected:
        for path in intact_files:
            print(f"[OK] INTACT:    {path}")

    print("-" * 65)
    print("AUDIT SUMMARY:")
    print(f"  Baseline Files : {len(baseline_files)}")
    print(f"  Current Files  : {len(current_files)}")
    print(f"  Intact Files   : {len(intact_files)}")
    print(f"  Created Files  : {len(created_files)}")
    print(f"  Modified Files : {len(modified_files)}")
    print(f"  Deleted Files  : {len(deleted_files)}")
    print("-" * 65)

    if anomalies_detected:
        total_anomalies = len(created_files) + len(modified_files) + len(deleted_files)
        print(f"[STATUS] INTEGRITY COMPROMISED: {total_anomalies} anomaly(ies) detected!")
        print("=" * 65)
        return 1
    else:
        print("[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.")
        print("=" * 65)
        return 0


def main() -> None:
    """Parse command-line arguments and dispatch FIM workflows."""
    parser = argparse.ArgumentParser(
        description="Sentinel FIM -- Lightweight Cryptographic File Integrity Monitor (SHA-256)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate baseline of monitored directory
  python src/fim_monitor.py --mode baseline

  # Audit monitored directory against established baseline
  python src/fim_monitor.py --mode monitor

  # Custom directory and baseline path
  python src/fim_monitor.py --mode baseline --dir custom_dir --baseline output/custom.json
        """,
    )

    parser.add_argument(
        "--mode",
        choices=["baseline", "monitor"],
        required=True,
        help="Operational mode: 'baseline' to record snapshots, 'monitor' to verify integrity.",
    )
    parser.add_argument(
        "--dir",
        dest="monitored_dir",
        default=None,
        help="Target directory to monitor (overrides fim_config.json).",
    )
    parser.add_argument(
        "--baseline",
        dest="baseline_file",
        default=None,
        help="Path to baseline.json file (overrides fim_config.json).",
    )
    parser.add_argument(
        "--config",
        dest="config_file",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to JSON configuration file (default: {DEFAULT_CONFIG_PATH}).",
    )

    args = parser.parse_args()

    # Load configuration
    cfg = load_config(Path(args.config_file))

    # Resolve target directory and baseline file path
    monitored_dir_str = args.monitored_dir or cfg.get("monitored_directory", DEFAULT_MONITORED_DIR)
    baseline_file_str = args.baseline_file or cfg.get("baseline_file", DEFAULT_BASELINE_FILE)

    monitored_dir = Path(monitored_dir_str)
    baseline_file = Path(baseline_file_str)

    if args.mode == "baseline":
        exit_code = run_baseline(monitored_dir, baseline_file)
    elif args.mode == "monitor":
        exit_code = run_monitor(monitored_dir, baseline_file)
    else:
        parser.print_help()
        exit_code = 1

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
