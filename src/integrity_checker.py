"""Sentinel FIM - Integrity Checker Module.

Responsible for comparing real-time filesystem states against the recorded baseline
to detect unauthorized modifications, newly introduced rogue files, deleted assets,
or Alternate Data Streams (ADS). Consumes ScanResult from the authoritative
descriptor-bound hasher engine and guarantees that incomplete scans containing
errors never report a clean integrity status.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Union

# Ensure src modules are resolvable
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import ScanResult, scan_directory
except ImportError:
    from hasher import ScanResult, scan_directory  # type: ignore[no-redef]


class IntegrityChecker:
    """Evaluates filesystem integrity against a trusted cryptographic baseline."""

    def __init__(
        self,
        monitored_dir: Union[str, Path],
        baseline_data: Dict[str, str],
        algorithm: str = "sha256",
    ) -> None:
        """Initialize the integrity checker.

        Args:
            monitored_dir: Path to the monitored directory.
            baseline_data: Trusted baseline mapping loaded from baseline.json.
            algorithm: Cryptographic hashing algorithm (default: sha256).

        Raises:
            ValueError: If baseline_data is not a dictionary or algorithm is unsupported.
        """
        self.monitored_dir = Path(monitored_dir)
        self.algorithm = algorithm.lower()

        if self.algorithm != "sha256":
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Sentinel FIM supports 'sha256' only.")

        if not isinstance(baseline_data, dict):
            raise ValueError(f"baseline_data must be a dictionary, received {type(baseline_data).__name__}")

        self.baseline_data = baseline_data

    def normalize_path(self, path: Union[str, Path]) -> str:
        """Normalize a filepath to POSIX forward slashes relative to the monitored directory.

        Does NOT remove legitimate nested directory components. Rejects path traversal
        attempts escaping the root directory.

        Args:
            path: Relative or raw filepath string.

        Returns:
            Normalized POSIX path string relative to the monitored directory.
        """
        raw = str(path).replace("\\", "/").strip()
        if not raw:
            raise ValueError("Path cannot be empty")

        p = Path(raw)
        mon_resolved = self.monitored_dir.resolve(strict=False)

        if p.is_absolute():
            try:
                resolved = p.resolve(strict=False)
                return resolved.relative_to(mon_resolved).as_posix()
            except ValueError:
                raise ValueError(f"Path '{path}' escapes monitored root '{self.monitored_dir}'")

        combined = (self.monitored_dir / p).resolve(strict=False)
        try:
            rel = combined.relative_to(mon_resolved).as_posix()
        except ValueError:
            raise ValueError(f"Path traversal detected: '{path}' escapes monitored root")

        return rel

    def check_integrity(self) -> Dict[str, Any]:
        """Perform integrity verification and report detected anomalies.

        Delegates directory discovery exclusively to scan_directory(). Compares
        the live cryptographic state against the trusted baseline. Explicitly
        captures scanning errors and suspicious alternate data streams to prevent
        false-clean reporting.

        Returns:
            Dictionary containing categorized results:
            - intact: Files whose checksums match baseline
            - modified: Files whose checksums have changed
            - created: Files newly created since baseline
            - deleted: Files present in baseline but missing from disk
            - suspicious_streams: Files detected with alternate data streams (ADS)
            - errors: Traversal or permission errors encountered during scan
            - has_scan_errors: True if scanner reported incomplete scan
            - total_monitored: Total valid files discovered during live scan
            - is_compromised: True if modifications, additions, deletions, ADS, or errors detected
        """
        if not self.monitored_dir.exists():
            raise FileNotFoundError(f"Monitored directory not found: {self.monitored_dir}")
        if not self.monitored_dir.is_dir():
            raise NotADirectoryError(f"Monitored target is not a directory: {self.monitored_dir}")

        scan_result: ScanResult = scan_directory(self.monitored_dir)

        # Normalize baseline dictionary keys and hash formatting
        normalized_baseline: Dict[str, str] = {
            self.normalize_path(k): str(v).lower()
            for k, v in self.baseline_data.items()
        }

        # Extract current state from authoritative ScanResult
        current_state: Dict[str, str] = {
            self.normalize_path(str(entry["relative_path"])): str(entry["sha256"]).lower()
            for entry in scan_result.files
        }

        baseline_files = set(normalized_baseline.keys())
        current_files = set(current_state.keys())

        intact: List[Dict[str, str]] = []
        modified: List[Dict[str, str]] = []
        created: List[Dict[str, str]] = []
        deleted: List[Dict[str, str]] = []
        suspicious_streams: List[Dict[str, Any]] = []

        # Check for Alternate Data Streams (ADS) on scanned files
        for entry in scan_result.files:
            if "alternate_streams" in entry and entry["alternate_streams"]:
                suspicious_streams.append({
                    "path": self.normalize_path(str(entry["relative_path"])),
                    "streams": entry["alternate_streams"],
                })

        # Compare existing common files
        for filepath in sorted(current_files & baseline_files):
            base_hash = normalized_baseline[filepath]
            curr_hash = current_state[filepath]
            if base_hash == curr_hash:
                intact.append({"path": filepath, "hash": curr_hash})
            else:
                modified.append({
                    "path": filepath,
                    "baseline_hash": base_hash,
                    "current_hash": curr_hash,
                })

        # Identify newly created files
        for filepath in sorted(current_files - baseline_files):
            created.append({
                "path": filepath,
                "current_hash": current_state[filepath],
            })

        # Identify deleted files
        for filepath in sorted(baseline_files - current_files):
            deleted.append({
                "path": filepath,
                "baseline_hash": normalized_baseline[filepath],
            })

        has_scan_errors = bool(not scan_result.success or scan_result.errors)
        is_compromised = bool(
            modified or created or deleted or has_scan_errors or suspicious_streams
        )

        return {
            "intact": intact,
            "modified": modified,
            "created": created,
            "deleted": deleted,
            "suspicious_streams": suspicious_streams,
            "errors": scan_result.errors,
            "has_scan_errors": has_scan_errors,
            "total_monitored": len(current_state),
            "is_compromised": is_compromised,
        }
