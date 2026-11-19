"""Sentinel FIM - Baseline Manager Module.

Responsible for recording the initial trusted state of monitored files
into a JSON baseline database located outside the monitored directory.
All file records use relative paths for portability and consistent integrity checks.

Phase 0: Architecture skeleton. Full engine implementation scheduled for Phase 1.
"""

from pathlib import Path
from typing import Any, Dict


class BaselineManager:
    """Manages baseline generation, persistence, and loading."""

    def __init__(self, monitored_dir: Path, baseline_file: Path, algorithm: str = "sha256") -> None:
        """Initialize the baseline manager.

        Args:
            monitored_dir: Path to the directory containing files to monitor.
            baseline_file: Destination path for the baseline JSON file (stored in output/).
            algorithm: Hashing algorithm specified in configuration (default: sha256).
        """
        self.monitored_dir = monitored_dir
        self.baseline_file = baseline_file
        self.algorithm = algorithm

    def generate_baseline(self) -> Dict[str, Any]:
        """Scan monitored directory and generate baseline checksum mapping using relative paths.

        Phase 0 placeholder. Implementation will be completed in Phase 1.
        """
        raise NotImplementedError("BaselineManager.generate_baseline will be implemented in Phase 1.")

    def save_baseline(self, baseline_data: Dict[str, Any]) -> None:
        """Serialize and save baseline records to the output JSON file.

        Phase 0 placeholder. Implementation will be completed in Phase 1.
        """
        raise NotImplementedError("BaselineManager.save_baseline will be implemented in Phase 1.")

    def load_baseline(self) -> Dict[str, Any]:
        """Load existing baseline records from the baseline JSON file.

        Phase 0 placeholder. Implementation will be completed in Phase 1.
        """
        raise NotImplementedError("BaselineManager.load_baseline will be implemented in Phase 1.")
