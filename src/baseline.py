"""Sentinel FIM - Baseline Manager Module.

Responsible for recording the initial trusted cryptographic state of monitored
files into a JSON baseline database located outside the monitored directory.
All file records use normalized relative paths for cross-platform portability.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure src modules are resolvable
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import calculate_sha256
except ImportError:
    from hasher import calculate_sha256


class BaselineManager:
    """Manages baseline generation, persistence, and loading."""

    def __init__(self, monitored_dir: Path, baseline_file: Path, algorithm: str = "sha256") -> None:
        """Initialize the baseline manager.

        Args:
            monitored_dir: Path to the directory containing files to monitor.
            baseline_file: Destination path for the baseline JSON file (stored in output/).
            algorithm: Hashing algorithm specified in configuration (default: sha256).
        """
        self.monitored_dir = Path(monitored_dir)
        self.baseline_file = Path(baseline_file)
        self.algorithm = algorithm.lower()

        if self.algorithm != "sha256":
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Sentinel FIM supports 'sha256'.")

    def generate_baseline(self) -> Dict[str, str]:
        """Scan monitored directory recursively and generate checksum mapping.

        Returns:
            Dictionary mapping relative filepaths to their SHA-256 hex digests.
        """
        if not self.monitored_dir.exists():
            raise FileNotFoundError(f"Monitored directory not found: {self.monitored_dir}")

        baseline: Dict[str, str] = {}

        for root, _, files in os.walk(self.monitored_dir):
            for filename in sorted(files):
                full_path = Path(root) / filename
                if full_path.is_file():
                    # Normalize relative path to POSIX forward slashes for cross-platform portability
                    try:
                        rel_path = full_path.resolve().relative_to(project_root.resolve()).as_posix()
                    except ValueError:
                        rel_path = full_path.as_posix()
                    baseline[rel_path] = calculate_sha256(full_path)

        return dict(sorted(baseline.items()))

    def save_baseline(self, baseline_data: Dict[str, str]) -> None:
        """Serialize and save baseline records to the output JSON file.

        Args:
            baseline_data: Mapping of filepaths to cryptographic hashes.
        """
        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.baseline_file, "w", encoding="utf-8") as f:
            json.dump(baseline_data, f, indent=4)

    def load_baseline(self) -> Dict[str, str]:
        """Load existing baseline records from the baseline JSON file.

        Returns:
            Dictionary containing previously stored baseline hashes.

        Raises:
            FileNotFoundError: If the baseline JSON file does not exist.
        """
        if not self.baseline_file.exists():
            raise FileNotFoundError(
                f"Baseline file not found at '{self.baseline_file}'. "
                f"Run in '--mode baseline' first to establish trusted state."
            )

        with open(self.baseline_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        return data
