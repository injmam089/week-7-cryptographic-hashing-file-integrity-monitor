from __future__ import annotations
import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

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
    hashes: Dict[str, str] = {}
    if not directory_path.exists():
        raise FileNotFoundError(f"Target directory does not exist: {directory_path}")
    for root, _, files in os.walk(directory_path):
        for filename in sorted(files):
            full_path = Path(root) / filename
            if full_path.is_file():
                try:
                    rel_path = full_path.resolve().relative_to(project_root.resolve()).as_posix()
                except ValueError:
                    rel_path = full_path.as_posix()
                file_hash = calculate_sha256(full_path)
                hashes[rel_path] = file_hash
    return dict(sorted(hashes.items()))

def run_baseline(monitored_dir: Path, baseline_file: Path) -> int:
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
    print("=" * 65)
    print(" SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir}")
    print(f"[*] Reference Baseline  : {baseline_file}")
    print("-" * 65)
    if not baseline_file.is_file():
        print(f"[ERROR] Baseline database not found: '{baseline_file}'.\n        Run 'python src/fim_monitor.py --mode baseline' first.", file=sys.stderr)
        return 1
    try:
        with open(baseline_file, "r", encoding="utf-8") as f:
            baseline_data: Dict[str, str] = json.load(f)
    except Exception as exc:
        print(f"[ERROR] Failed to load baseline database: {exc}", file=sys.stderr)
        return 1
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
    anomalies_detected = False
    if created_files:
        anomalies_detected = True
        for path in created_files:
            print(f"[ALERT] CREATED:  {path}\n        SHA-256: {current_data[path]}")
    if modified_files:
        anomalies_detected = True
        for path in modified_files:
            print(f"[ALERT] MODIFIED: {path}\n        Baseline SHA-256: {baseline_data[path]}\n        Current  SHA-256: {current_data[path]}")
    if deleted_files:
        anomalies_detected = True
        for path in deleted_files:
            print(f"[ALERT] DELETED:  {path}\n        Expected SHA-256: {baseline_data[path]}")
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
        print(f"[STATUS] INTEGRITY COMPROMISED: {len(created_files) + len(modified_files) + len(deleted_files)} anomaly(ies) detected!")
        print("=" * 65)
        return 1
    else:
        print("[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.")
        print("=" * 65)
        return 0

def main() -> None:
    parser = argparse.ArgumentParser(description="Sentinel FIM -- Lightweight Cryptographic File Integrity Monitor (SHA-256)")
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
