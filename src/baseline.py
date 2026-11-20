"""Sentinel FIM - Baseline Manager Module.

Responsible for recording the initial trusted cryptographic state of monitored
files into a JSON baseline database located outside the monitored directory.
Consumes ScanResult from the authoritative descriptor-bound hasher engine,
guarantees atomic persistence, validates schema and digest integrity, and provides
seamless legacy path normalization.
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional, Union

# Ensure src modules are resolvable
project_root = Path(__file__).resolve().parent.parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

try:
    from src.hasher import ScanResult, scan_directory
except ImportError:
    from hasher import ScanResult, scan_directory  # type: ignore[no-redef]

SHA256_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")


class BaselineManager:
    """Manages baseline generation, persistence, validation, and loading."""

    def __init__(
        self,
        monitored_dir: Union[str, Path],
        baseline_file: Union[str, Path],
        algorithm: str = "sha256",
    ) -> None:
        """Initialize the baseline manager.

        Args:
            monitored_dir: Path to the directory containing files to monitor.
            baseline_file: Destination path for the baseline JSON file (stored in output/).
            algorithm: Hashing algorithm specified in configuration (default: sha256).

        Raises:
            ValueError: If an unsupported hashing algorithm is specified.
        """
        self.monitored_dir = Path(monitored_dir)
        self.baseline_file = Path(baseline_file)
        self.algorithm = algorithm.lower()

        if self.algorithm != "sha256":
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Sentinel FIM supports 'sha256' only.")

    def normalize_path(self, path: Union[str, Path]) -> str:
        """Normalize a filepath to POSIX forward slashes and strip legacy folder prefixes.

        Args:
            path: Relative or raw filepath string.

        Returns:
            Normalized POSIX path string relative to the monitored directory.
        """
        posix_path = str(path).replace("\\", "/").strip()
        # Strip leading ./ if present
        if posix_path.startswith("./"):
            posix_path = posix_path[2:]

        # Strip legacy monitored_dir folder name prefix if present
        prefix = f"{self.monitored_dir.name}/"
        if posix_path.startswith(prefix) and len(posix_path) > len(prefix):
            posix_path = posix_path[len(prefix):]

        return posix_path

    def generate_baseline(self) -> Dict[str, str]:
        """Scan monitored directory using authoritative scanner and produce baseline mapping.

        Consumes ScanResult from src.hasher.scan_directory. Guarantees that an
        incomplete scan containing access errors or symlink violations will never
        produce a baseline.

        Returns:
            Dictionary mapping normalized relative filepaths to SHA-256 hex digests.

        Raises:
            FileNotFoundError: If the monitored directory does not exist.
            NotADirectoryError: If the monitored path points to a file.
            RuntimeError: If directory scanning encountered permission or traversal errors.
        """
        if not self.monitored_dir.exists():
            raise FileNotFoundError(f"Monitored directory not found: {self.monitored_dir}")
        if not self.monitored_dir.is_dir():
            raise NotADirectoryError(f"Monitored target is not a directory: {self.monitored_dir}")

        scan_result: ScanResult = scan_directory(self.monitored_dir)

        if not scan_result.success or scan_result.errors:
            error_details = "; ".join(
                f"{err.get('relative_path')}: {err.get('error')}" for err in scan_result.errors
            )
            raise RuntimeError(
                f"Refusing to generate baseline: {scan_result.total_errors} scan error(s) detected: {error_details}"
            )

        baseline_mapping: Dict[str, str] = {}
        for file_entry in scan_result.files:
            rel_path = self.normalize_path(str(file_entry["relative_path"]))
            digest = str(file_entry["sha256"]).lower()
            baseline_mapping[rel_path] = digest

        return dict(sorted(baseline_mapping.items()))

    def validate_baseline_data(self, data: Any) -> None:
        """Validate JSON baseline structure and SHA-256 digest formats.

        Args:
            data: Parsed JSON data to validate.

        Raises:
            ValueError: If structure is not a dict, or if keys/digests are invalid.
        """
        if not isinstance(data, dict):
            raise ValueError(f"Baseline root must be a JSON object (dict), received {type(data).__name__}")

        for path_key, digest in data.items():
            if not isinstance(path_key, str) or not path_key.strip():
                raise ValueError(f"Invalid path key in baseline record: {path_key!r}")
            if not isinstance(digest, str) or not SHA256_HEX_PATTERN.match(digest.lower()):
                raise ValueError(
                    f"Invalid cryptographic digest for path '{path_key}': {digest!r}. "
                    f"Must be a 64-character lowercase SHA-256 hexadecimal string."
                )

    def save_baseline(self, baseline_data: Dict[str, str]) -> None:
        """Atomically serialize and save baseline records to the output JSON file.

        Writes data to a temporary file in the destination directory and uses
        os.replace() to guarantee atomic persistence. Existing baseline is never
        corrupted if serialization or disk writes fail.

        Args:
            baseline_data: Mapping of normalized relative filepaths to SHA-256 digests.

        Raises:
            ValueError: If baseline_data fails cryptographic validation.
            OSError: If disk operations fail.
        """
        self.validate_baseline_data(baseline_data)

        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.baseline_file.with_name(f"{self.baseline_file.name}.tmp.{os.getpid()}")

        try:
            with open(temp_file, "w", encoding="utf-8") as stream:
                json.dump(baseline_data, stream, indent=4)
                stream.flush()
                os.fsync(stream.fileno())

            os.replace(temp_file, self.baseline_file)
        except Exception:
            if temp_file.exists():
                try:
                    temp_file.unlink()
                except OSError:
                    pass
            raise

    def load_baseline(self, normalize_legacy: bool = True) -> Dict[str, str]:
        """Load and validate existing baseline records from the baseline JSON file.

        Args:
            normalize_legacy: Whether to normalize legacy path prefixes (default: True).

        Returns:
            Dictionary containing verified baseline hashes.

        Raises:
            FileNotFoundError: If the baseline JSON file does not exist.
            ValueError: If JSON is malformed or fails schema/digest validation.
        """
        if not self.baseline_file.is_file():
            raise FileNotFoundError(
                f"Baseline file not found at '{self.baseline_file}'. "
                f"Run Sentinel FIM in '--mode baseline' first to establish trusted state."
            )

        try:
            with open(self.baseline_file, "r", encoding="utf-8") as stream:
                raw_data = json.load(stream)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed baseline JSON in '{self.baseline_file}': {exc}") from exc

        self.validate_baseline_data(raw_data)

        normalized_data: Dict[str, str] = {}
        for path_key, digest in raw_data.items():
            final_key = self.normalize_path(path_key) if normalize_legacy else path_key
            normalized_data[final_key] = digest.lower()

        return dict(sorted(normalized_data.items()))
