from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional, Union

project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import DEFAULT_CHUNK_SIZE, calculate_sha256
    from src.baseline import (
        BaselineAuthenticationError,
        BaselineCorruptionError,
        BaselineManager,
        generate_hmac_key,
    )
    from src.integrity_checker import IntegrityChecker
except ImportError:
    from hasher import DEFAULT_CHUNK_SIZE, calculate_sha256  # type: ignore[no-redef]
    from baseline import (  # type: ignore[no-redef]
        BaselineAuthenticationError,
        BaselineCorruptionError,
        BaselineManager,
        generate_hmac_key,
    )
    from integrity_checker import IntegrityChecker  # type: ignore[no-redef]

DEFAULT_CONFIG_PATH = "config/fim_config.json"
DEFAULT_MONITORED_DIR = "monitored"
DEFAULT_BASELINE_FILE = "output/baseline.json"


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load configuration from JSON file or fall back to standard defaults.

    Validates schema structure, required keys, types, supported algorithm, and paths.
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
    except Exception as exc:
        print(f"[WARN] Failed to parse config file ({exc}). Utilizing standard defaults.", file=sys.stderr)
        return defaults

    if not isinstance(user_config, dict):
        raise ValueError(f"Config root must be a JSON object (dict), received {type(user_config).__name__}")

    # Validate required keys if present
    for required_key in ("algorithm", "monitored_directory", "baseline_file"):
        if required_key in user_config:
            val = user_config[required_key]
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Configuration key '{required_key}' must be a non-empty string.")
            if "\0" in val:
                raise ValueError(f"Configuration key '{required_key}' contains invalid null bytes.")

    if "algorithm" in user_config:
        alg = user_config["algorithm"].strip().lower()
        if alg != "sha256":
            raise ValueError(f"Unsupported algorithm '{user_config['algorithm']}'. Sentinel FIM supports 'sha256' only.")

    defaults.update(user_config)
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


def run_baseline(
    monitored_dir: Path,
    baseline_file: Path,
    hmac_key: Optional[Union[str, bytes]] = None,
    key_file: Optional[Path] = None,
) -> int:
    """Generate baseline hashes for monitored directory and save authenticated baseline JSON."""
    baseline_target_display = baseline_file.as_posix()
    chunk_mb = DEFAULT_CHUNK_SIZE // (1024 * 1024)
    chunk_display = f"{chunk_mb} MiB" if chunk_mb > 0 else f"{DEFAULT_CHUNK_SIZE} bytes"

    print("=" * 65)
    print(" SENTINEL FIM -- BASELINE SNAPSHOT GENERATION")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir.as_posix()}")
    print(f"[*] Baseline Target     : {baseline_target_display}")
    print(f"[*] Hash Algorithm      : SHA-256 ({chunk_display} chunk streaming)")
    print(f"[*] Authentication      : HMAC-SHA256 (Canonical Sealing)")
    print("-" * 65)

    if not monitored_dir.exists():
        print(f"[ERROR] Monitored directory '{monitored_dir.as_posix()}' does not exist.", file=sys.stderr)
        return 1

    try:
        manager = BaselineManager(
            monitored_dir=monitored_dir,
            baseline_file=baseline_file,
            hmac_key=hmac_key,
            key_file=key_file,
        )
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
    print(f"[SUCCESS] Saved authenticated snapshot to: {baseline_target_display}")
    print("=" * 65)
    return 0


def run_monitor(
    monitored_dir: Path,
    baseline_file: Path,
    hmac_key: Optional[Union[str, bytes]] = None,
    key_file: Optional[Path] = None,
) -> int:
    """Verify live filesystem integrity against recorded authenticated baseline."""
    baseline_target_display = baseline_file.as_posix()
    print("=" * 65)
    print(" SENTINEL FIM -- INTEGRITY VERIFICATION AUDIT")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Monitored Directory : {monitored_dir.as_posix()}")
    print(f"[*] Reference Baseline  : {baseline_target_display}")
    print(f"[*] Authentication      : HMAC-SHA256 Signature Verification")
    print("-" * 65)

    if not baseline_file.is_file():
        print(
            f"[ERROR] Baseline database not found: '{baseline_target_display}'.\n"
            f"        Run 'python -m src.fim_monitor --mode baseline' first.",
            file=sys.stderr,
        )
        return 1

    try:
        manager = BaselineManager(
            monitored_dir=monitored_dir,
            baseline_file=baseline_file,
            hmac_key=hmac_key,
            key_file=key_file,
        )
        baseline_data = manager.load_baseline()
    except BaselineAuthenticationError as exc:
        print(f"[ERROR] Baseline Authentication Failed:\n        {exc}", file=sys.stderr)
        return 1
    except BaselineCorruptionError as exc:
        print(f"[ERROR] Corrupted Baseline Database:\n        {exc}", file=sys.stderr)
        return 1
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

    if report.get("suspicious_streams"):
        for item in report["suspicious_streams"]:
            display_path = _format_display_path(item["path"], monitored_dir)
            for s in item["streams"]:
                print(
                    f"[ALERT] SUSPICIOUS STREAM (ADS): {display_path}\n"
                    f"        Stream Name : {s['stream_name']}\n"
                    f"        Stream Size : {s['size_bytes']} bytes"
                )

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
    if report.get("suspicious_streams"):
        print(f"  ADS Anomalies  : {len(report['suspicious_streams'])}")
    if report["errors"]:
        print(f"  Scan Errors    : {len(report['errors'])}")
    print("-" * 65)

    if report["is_compromised"]:
        anomaly_count = (
            len(report["created"])
            + len(report["modified"])
            + len(report["deleted"])
            + len(report.get("suspicious_streams", []))
            + len(report["errors"])
        )
        print(f"[STATUS] INTEGRITY COMPROMISED: {anomaly_count} anomaly(ies) detected!")
        print("=" * 65)
        return 1
    else:
        print("[STATUS] INTEGRITY VERIFIED: All files match trusted baseline.")
        print("=" * 65)
        return 0


def run_migrate_baseline(
    monitored_dir: Path,
    baseline_file: Path,
    hmac_key: Optional[Union[str, bytes]] = None,
    key_file: Optional[Path] = None,
) -> int:
    """Explicitly migrate an unsigned legacy baseline to HMAC-SHA256 authenticated baseline."""
    print("=" * 65)
    print(" SENTINEL FIM -- BASELINE CRYPTOGRAPHIC MIGRATION")
    print("=" * 65)
    print(f"[*] Timestamp           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Baseline Target     : {baseline_file.as_posix()}")
    print("-" * 65)
    print("[SECURITY NOTICE] Migrating legacy unsigned baseline to HMAC-SHA256 authenticated format.")
    print("[WARNING] Signing an existing baseline cryptographically seals its current state from this")
    print("          point forward, but CANNOT retroactively prove it was authentic before signing.")
    print("-" * 65)

    try:
        manager = BaselineManager(
            monitored_dir=monitored_dir,
            baseline_file=baseline_file,
            hmac_key=hmac_key,
            key_file=key_file,
        )
        summary = manager.migrate_legacy_baseline()
        print(f"[SUCCESS] Migrated {summary['migrated_files']} file record(s) to HMAC-SHA256 baseline.")
        if summary.get("backup_file"):
            print(f"[SUCCESS] Preserved legacy backup snapshot at: {summary['backup_file']}")
        print(f"[SUCCESS] Authenticated baseline written to : {summary['baseline_file']}")
        print("=" * 65)
        return 0
    except FileExistsError as exc:
        print(f"[ERROR] Baseline migration aborted: {exc}", file=sys.stderr)
        print("=" * 65)
        return 1
    except Exception as exc:
        print(f"[ERROR] Baseline migration failed: {exc}", file=sys.stderr)
        print("=" * 65)
        return 1


def run_generate_key(destination_file: Optional[Path] = None) -> int:
    """Generate a 256-bit random HMAC secret key and save to destination path."""
    target_dest = destination_file or Path("config") / ".baseline.key"
    try:
        generate_hmac_key(target_dest)
        print("=" * 65)
        print(" SENTINEL FIM -- HMAC KEY GENERATION")
        print("=" * 65)
        print(f"[SUCCESS] Generated cryptographically random 256-bit HMAC secret key.")
        print(f"[SUCCESS] Saved key material to: {target_dest.as_posix()}")
        print("[NOTICE] Store this key securely outside monitored directories.")
        print("[NOTICE] Restrict file read permissions and do NOT commit key to version control.")
        print("=" * 65)
        return 0
    except FileExistsError as exc:
        print(f"[ERROR] Key generation aborted: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[ERROR] Failed to generate key: {exc}", file=sys.stderr)
        return 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Sentinel FIM -- Lightweight Cryptographic File Integrity Monitor (SHA-256)"
    )
    parser.add_argument(
        "--mode",
        choices=["baseline", "monitor", "migrate-baseline", "generate-key"],
        required=True,
        help="Operational mode",
    )
    parser.add_argument("--dir", dest="monitored_dir", default=None, help="Target monitored directory")
    parser.add_argument("--baseline", dest="baseline_file", default=None, help="Baseline JSON database path")
    parser.add_argument("--config", dest="config_file", default=DEFAULT_CONFIG_PATH, help="Configuration file path")
    parser.add_argument("--key-file", dest="key_file", default=None, help="Path to external HMAC key file")
    parser.add_argument("--key", dest="hmac_key", default=None, help="Explicit HMAC secret key string")

    args = parser.parse_args()

    if args.mode == "generate-key":
        dest = Path(args.key_file) if args.key_file else None
        sys.exit(run_generate_key(dest))

    try:
        cfg = load_config(Path(args.config_file))
    except ValueError as exc:
        print(f"[ERROR] Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)

    monitored_dir = Path(args.monitored_dir or cfg.get("monitored_directory", DEFAULT_MONITORED_DIR))
    baseline_file = Path(args.baseline_file or cfg.get("baseline_file", DEFAULT_BASELINE_FILE))
    key_file_path = Path(args.key_file) if args.key_file else None

    if args.mode == "baseline":
        sys.exit(run_baseline(monitored_dir, baseline_file, hmac_key=args.hmac_key, key_file=key_file_path))
    elif args.mode == "monitor":
        sys.exit(run_monitor(monitored_dir, baseline_file, hmac_key=args.hmac_key, key_file=key_file_path))
    elif args.mode == "migrate-baseline":
        sys.exit(run_migrate_baseline(monitored_dir, baseline_file, hmac_key=args.hmac_key, key_file=key_file_path))


if __name__ == "__main__":
    main()
