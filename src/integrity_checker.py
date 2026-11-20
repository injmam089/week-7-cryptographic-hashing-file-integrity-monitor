"""Sentinel FIM - Integrity Checker Module.

Responsible for comparing real-time filesystem states against the recorded baseline
to detect unauthorized modifications, newly introduced rogue files, or deleted assets.
Consumes ScanResult from the authoritative descriptor-bound hasher engine and guarantees
that incomplete scans containing errors never report a clean integrity status.
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
        """Normalize a filepath to POSIX forward slashes and strip legacy folder prefixes.

        Args:
            path: Relative or raw filepath string.

        Returns:
            Normalized POSIX path string relative to the monitored directory.
        """
        posix_path = str(path).replace("\\", "/").strip()
        if posix_path.startswith("./"):
            posix_path = posix_path[2:]

        prefix = f"{self.monitored_dir.name}/"
        if posix_path.startswith(prefix) and len(posix_path) > len(prefix):
            posix_path = posix_path[len(prefix):]

        return posix_path

    def check_integrity(self) -> Dict[str, Any]:
        """Perform integrity verification and report detected anomalies.

        Delegates directory discovery exclusively to scan_directory(). Compares
        the live cryptographic state against the trusted baseline. Explicitly
        captures scanning errors to prevent false-clean reporting.

        Returns:
            Dictionary containing categorized results:
            - intact: Files whose checksums match baseline
            - modified: Files whose checksums have changed
            - created: Files newly created since baseline
            - deleted: Files present in baseline but missing from disk
            - errors: Traversal or permission errors encountered during scan
            - has_scan_errors: True if scanner reported incomplete scan
            - total_monitored: Total valid files discovered during live scan
            - is_compromised: True if modifications, additions, deletions, or errors detected

        Raises:
            FileNotFoundError: If the monitored directory does not exist.
            NotADirectoryError: If the monitored path points to a file.
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
        is_compromised = bool(modified or created or deleted or has_scan_errors)

        return {
            "intact": intact,
            "modified": modified,
            "created": created,
            "deleted": deleted,
            "errors": scan_result.errors,
            "has_scan_errors": has_scan_errors,
            "total_monitored": len(current_state),
            "is_compromised": is_compromised,
        }
