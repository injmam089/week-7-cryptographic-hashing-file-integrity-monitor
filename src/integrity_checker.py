"""Sentinel FIM - Integrity Checker Module.

Responsible for comparing real-time filesystem states against the recorded baseline
to detect unauthorized modifications, newly introduced rogue files, or deleted assets.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List

# Ensure src modules are resolvable
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import calculate_sha256
except ImportError:
    from hasher import calculate_sha256


class IntegrityChecker:
    """Evaluates filesystem integrity against a trusted cryptographic baseline."""

    def __init__(self, monitored_dir: Path, baseline_data: Dict[str, str], algorithm: str = "sha256") -> None:
        """Initialize the integrity checker.

        Args:
            monitored_dir: Path to the monitored directory.
            baseline_data: Trusted baseline mapping loaded from baseline.json.
            algorithm: Cryptographic hashing algorithm (default: sha256).
        """
        self.monitored_dir = Path(monitored_dir)
        self.baseline_data = baseline_data
        self.algorithm = algorithm.lower()

    def _scan_current_state(self) -> Dict[str, str]:
        """Scan the monitored directory and calculate current SHA-256 hashes."""
        current: Dict[str, str] = {}
        if not self.monitored_dir.exists():
            return current

        for root, _, files in os.walk(self.monitored_dir):
            for filename in sorted(files):
                full_path = Path(root) / filename
                if full_path.is_file():
                    try:
                        rel_path = full_path.resolve().relative_to(project_root.resolve()).as_posix()
                    except ValueError:
                        rel_path = full_path.as_posix()
                    current[rel_path] = calculate_sha256(full_path)

        return current

    def check_integrity(self) -> Dict[str, Any]:
        """Perform integrity verification and report detected anomalies.

        Returns:
            Dictionary containing categorized results:
            - intact: Files whose checksums match baseline
            - modified: Files whose checksums have changed
            - created: Files newly created since baseline
            - deleted: Files present in baseline but missing from disk
        """
        current_state = self._scan_current_state()

        baseline_files = set(self.baseline_data.keys())
        current_files = set(current_state.keys())

        intact: List[Dict[str, str]] = []
        modified: List[Dict[str, str]] = []
        created: List[Dict[str, str]] = []
        deleted: List[Dict[str, str]] = []

        # Check existing files
        for filepath in sorted(current_files & baseline_files):
            base_hash = self.baseline_data[filepath]
            curr_hash = current_state[filepath]
            if base_hash == curr_hash:
                intact.append({"path": filepath, "hash": curr_hash})
            else:
                modified.append({
                    "path": filepath,
                    "baseline_hash": base_hash,
                    "current_hash": curr_hash,
                })

        # Check created / added files
        for filepath in sorted(current_files - baseline_files):
            created.append({
                "path": filepath,
                "current_hash": current_state[filepath],
            })

        # Check deleted files
        for filepath in sorted(baseline_files - current_files):
            deleted.append({
                "path": filepath,
                "baseline_hash": self.baseline_data[filepath],
            })

        return {
            "intact": intact,
            "modified": modified,
            "created": created,
            "deleted": deleted,
            "total_monitored": len(current_state),
            "is_compromised": bool(modified or created or deleted),
        }
