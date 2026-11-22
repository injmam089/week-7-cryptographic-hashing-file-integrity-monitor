"""Sentinel FIM - Baseline Manager Module.

Responsible for recording the initial trusted cryptographic state of monitored
files into a JSON baseline database located outside the monitored directory.
Consumes ScanResult from the authoritative descriptor-bound hasher engine,
guarantees atomic persistence, validates schema and digest integrity, provides
hardened path normalization, and enforces HMAC-SHA256 cryptographic baseline
authentication.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import sys
from datetime import datetime
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
DEFAULT_KEY_FILENAME = ".baseline.key"


class BaselineAuthenticationError(RuntimeError):
    """Raised when baseline authentication fails or unauthenticated baseline is loaded."""


class BaselineCorruptionError(ValueError):
    """Raised when baseline structure or cryptographic digests are malformed."""


def canonical_baseline_bytes(
    files_mapping: Dict[str, str],
    version: int = 1,
    algorithm: str = "sha256",
) -> bytes:
    """Produce deterministic, canonical byte representation for HMAC signing.

    Keys are sorted alphabetically and digests are lowercased. JSON is serialized
    without whitespace separators to prevent formatting-based signature mismatches.
    """
    sorted_files = {str(k): str(v).lower() for k, v in sorted(files_mapping.items())}
    payload = {
        "algorithm": algorithm.lower(),
        "files": sorted_files,
        "version": int(version),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def compute_baseline_hmac(
    key: bytes,
    files_mapping: Dict[str, str],
    version: int = 1,
    algorithm: str = "sha256",
) -> str:
    """Calculate HMAC-SHA256 hex digest over canonical baseline representation."""
    canonical_data = canonical_baseline_bytes(files_mapping, version=version, algorithm=algorithm)
    return hmac.new(key, canonical_data, hashlib.sha256).hexdigest()


def verify_baseline_hmac(
    key: bytes,
    stored_hmac: str,
    files_mapping: Dict[str, str],
    version: int = 1,
    algorithm: str = "sha256",
) -> bool:
    """Verify HMAC-SHA256 using constant-time comparison to prevent timing attacks."""
    if not isinstance(stored_hmac, str) or not SHA256_HEX_PATTERN.match(stored_hmac.lower()):
        return False
    expected_hmac = compute_baseline_hmac(key, files_mapping, version=version, algorithm=algorithm)
    return hmac.compare_digest(stored_hmac.lower(), expected_hmac.lower())


def resolve_hmac_key(
    key: Optional[Union[str, bytes]] = None,
    key_file: Optional[Union[str, Path]] = None,
    fallback_file: Optional[Union[str, Path]] = None,
) -> Optional[bytes]:
    """Resolve HMAC key from arguments, file, environment variable, or fallback file.

    Never logs or exposes the key material.
    """
    if key is not None:
        if isinstance(key, bytes):
            return key
        if isinstance(key, str):
            clean = key.strip()
            if len(clean) == 64 and SHA256_HEX_PATTERN.match(clean.lower()):
                try:
                    return bytes.fromhex(clean)
                except ValueError:
                    pass
            return clean.encode("utf-8")

    if key_file is not None:
        kp = Path(key_file)
        if kp.is_file():
            content = kp.read_bytes().strip()
            # If 64-character hex in file, decode to 32 bytes
            if len(content) == 64:
                try:
                    return bytes.fromhex(content.decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    pass
            return content

    env_key = os.environ.get("SENTINEL_HMAC_KEY")
    if env_key:
        clean_env = env_key.strip()
        if len(clean_env) == 64 and SHA256_HEX_PATTERN.match(clean_env.lower()):
            try:
                return bytes.fromhex(clean_env)
            except ValueError:
                pass
        return clean_env.encode("utf-8")

    if fallback_file is not None:
        fp = Path(fallback_file)
        if fp.is_file():
            content = fp.read_bytes().strip()
            if len(content) == 64:
                try:
                    return bytes.fromhex(content.decode("ascii"))
                except (ValueError, UnicodeDecodeError):
                    pass
            return content

    return None


def generate_hmac_key(destination_file: Optional[Union[str, Path]] = None) -> bytes:
    """Generate a cryptographically random 256-bit (32-byte) key.

    Optionally saves the hex key string to a file with restrictive permissions.
    Always uses exclusive creation ('x') to strictly refuse overwriting an existing
    key file, preventing accidental key loss or silent baseline invalidation.

    Args:
        destination_file: Optional path where the key should be persisted.

    Returns:
        32 raw bytes of cryptographically random key material.

    Raises:
        FileExistsError: If destination_file already exists on disk.
    """
    key_bytes = secrets.token_bytes(32)
    if destination_file is not None:
        dest = Path(destination_file)
        dest.parent.mkdir(parents=True, exist_ok=True)

        created = False
        try:
            with open(dest, "x", encoding="utf-8") as stream:
                created = True
                stream.write(key_bytes.hex())
                stream.flush()
        except FileExistsError as exc:
            raise FileExistsError(
                f"Cannot generate key: destination key file already exists at '{dest}'. "
                f"Refusing to overwrite existing key material to prevent baseline invalidation."
            ) from exc
        except Exception:
            if created and dest.exists():
                try:
                    dest.unlink()
                except OSError:
                    pass
            raise

        try:
            # Set restrictive file permissions (read/write only by owner on POSIX)
            os.chmod(dest, 0o600)
        except OSError:
            # Windows filesystem permission model may not support POSIX octal mode
            pass
    return key_bytes


class BaselineManager:
    """Manages baseline generation, persistence, validation, HMAC signing, and loading."""

    def __init__(
        self,
        monitored_dir: Union[str, Path],
        baseline_file: Union[str, Path],
        algorithm: str = "sha256",
        hmac_key: Optional[Union[str, bytes]] = None,
        key_file: Optional[Union[str, Path]] = None,
    ) -> None:
        """Initialize the baseline manager.

        Args:
            monitored_dir: Path to directory containing files to monitor.
            baseline_file: Path for the baseline JSON file (stored in output/).
            algorithm: Hashing algorithm specified in configuration (default: sha256).
            hmac_key: Optional explicit HMAC secret key (bytes or hex string).
            key_file: Optional path to external key file.

        Raises:
            ValueError: If an unsupported hashing algorithm is specified.
        """
        self.monitored_dir = Path(monitored_dir)
        self.baseline_file = Path(baseline_file)
        self.algorithm = algorithm.lower()
        self.raw_key = hmac_key
        self.key_file = Path(key_file) if key_file else None

        if self.algorithm != "sha256":
            raise ValueError(f"Unsupported algorithm '{algorithm}'. Sentinel FIM supports 'sha256' only.")

    def get_default_key_path(self) -> Path:
        """Return the default external key path in the config directory."""
        # Baseline is typically in output/, so parent is workspace root
        workspace = self.baseline_file.parent.parent
        config_dir = workspace / "config"
        if config_dir.is_dir():
            return config_dir / DEFAULT_KEY_FILENAME
        return self.baseline_file.parent / DEFAULT_KEY_FILENAME

    def resolve_key(self) -> Optional[bytes]:
        """Resolve HMAC key using explicit key, key file, environment, or default path."""
        return resolve_hmac_key(
            key=self.raw_key,
            key_file=self.key_file,
            fallback_file=self.get_default_key_path(),
        )

    def normalize_path(self, path: Union[str, Path]) -> str:
        """Normalize a filepath to POSIX forward slashes relative to the monitored directory.

        Does NOT remove legitimate nested directory components (e.g., 'monitored/file.txt'
        inside 'monitored/' is preserved). Rejects path traversal attempts escaping the root.

        Args:
            path: Relative or absolute filepath string or Path.

        Returns:
            Normalized POSIX path string relative to the monitored directory root.

        Raises:
            ValueError: If path is empty or escapes the monitored root directory.
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

        # Combine relative path with monitored root and check boundary
        combined = (self.monitored_dir / p).resolve(strict=False)
        try:
            rel = combined.relative_to(mon_resolved).as_posix()
        except ValueError:
            raise ValueError(f"Path traversal detected: '{path}' escapes monitored root")

        return rel

    def generate_baseline(self) -> Dict[str, str]:
        """Scan monitored directory using authoritative scanner and produce baseline mapping.

        Guarantees that an incomplete scan containing access errors or symlink violations
        will never produce a baseline.

        Returns:
            Dictionary mapping normalized relative filepaths to SHA-256 hex digests.
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
        """Validate baseline mapping structure and SHA-256 digest formats."""
        if not isinstance(data, dict):
            raise BaselineCorruptionError(
                f"Baseline files must be a JSON object (dict), received {type(data).__name__}"
            )

        for path_key, digest in data.items():
            if not isinstance(path_key, str) or not path_key.strip():
                raise BaselineCorruptionError(f"Invalid path key in baseline record: {path_key!r}")
            if not isinstance(digest, str) or not SHA256_HEX_PATTERN.match(digest.lower()):
                raise BaselineCorruptionError(
                    f"Invalid cryptographic digest for path '{path_key}': {digest!r}. "
                    f"Must be a 64-character lowercase SHA-256 hexadecimal string."
                )

    def save_baseline(self, baseline_data: Dict[str, str], key: Optional[bytes] = None) -> None:
        """Atomically serialize and save baseline records with HMAC-SHA256 authentication.

        Args:
            baseline_data: Mapping of normalized relative filepaths to SHA-256 digests.
            key: Optional explicit HMAC secret key (if omitted, resolved automatically).

        Raises:
            BaselineAuthenticationError: If no HMAC key could be resolved or generated.
            BaselineCorruptionError: If baseline data fails schema validation.
        """
        self.validate_baseline_data(baseline_data)

        signing_key = key or self.resolve_key()
        if not signing_key:
            # Auto-provision key in default external location if none specified
            default_key_path = self.get_default_key_path()
            signing_key = generate_hmac_key(default_key_path)
            self.raw_key = signing_key

        hmac_digest = compute_baseline_hmac(
            signing_key, baseline_data, version=1, algorithm=self.algorithm
        )

        payload: Dict[str, Any] = {
            "version": 1,
            "algorithm": self.algorithm,
            "auth_mode": "hmac-sha256",
            "hmac": hmac_digest,
            "created_at": datetime.now().isoformat(),
            "files": dict(sorted(baseline_data.items())),
        }

        self.baseline_file.parent.mkdir(parents=True, exist_ok=True)
        temp_file = self.baseline_file.with_name(f"{self.baseline_file.name}.tmp.{os.getpid()}")

        try:
            with open(temp_file, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, indent=4)
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

    def load_baseline(
        self,
        allow_unsigned: bool = False,
        key: Optional[bytes] = None,
        normalize_legacy: bool = False,
    ) -> Dict[str, str]:
        """Load and cryptographically authenticate baseline records.

        Args:
            allow_unsigned: If True, allows loading legacy unsigned baselines (used ONLY during migration).
            key: Optional explicit HMAC key override.
            normalize_legacy: Whether to normalize legacy paths.

        Returns:
            Dictionary containing verified baseline file-to-hash mappings.

        Raises:
            FileNotFoundError: If baseline file does not exist.
            BaselineAuthenticationError: If HMAC is invalid, missing, or key is absent.
            BaselineCorruptionError: If JSON structure or digests are malformed.
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
            raise BaselineCorruptionError(f"Malformed baseline JSON in '{self.baseline_file}': {exc}") from exc

        if not isinstance(raw_data, dict):
            raise BaselineCorruptionError(
                f"Baseline root must be a JSON object, received {type(raw_data).__name__}"
            )

        # Detect authenticated format vs legacy flat format
        if "auth_mode" in raw_data and raw_data.get("auth_mode") == "hmac-sha256":
            stored_hmac = raw_data.get("hmac")
            if not stored_hmac or not isinstance(stored_hmac, str):
                raise BaselineAuthenticationError("Baseline metadata is missing HMAC signature.")

            files_data = raw_data.get("files")
            if not isinstance(files_data, dict):
                raise BaselineCorruptionError("Authenticated baseline is missing 'files' dictionary.")

            self.validate_baseline_data(files_data)

            verification_key = key or self.resolve_key()
            if not verification_key:
                raise BaselineAuthenticationError(
                    "Baseline authentication failed: HMAC key is required to verify baseline, "
                    "but no key was provided or found. Set SENTINEL_HMAC_KEY or provide --key-file."
                )

            version = int(raw_data.get("version", 1))
            algo = str(raw_data.get("algorithm", self.algorithm))

            if not verify_baseline_hmac(verification_key, stored_hmac, files_data, version=version, algorithm=algo):
                raise BaselineAuthenticationError(
                    "Baseline HMAC verification failed: baseline content or signature has been tampered with."
                )

            target_files = files_data
        else:
            # Unsigned legacy baseline format
            if not allow_unsigned:
                raise BaselineAuthenticationError(
                    f"Unsigned baseline detected at '{self.baseline_file}'. "
                    f"Sentinel FIM requires HMAC-SHA256 authenticated baselines to prevent tampering. "
                    f"Run with '--migrate-baseline' to explicitly authenticate this baseline."
                )
            self.validate_baseline_data(raw_data)
            target_files = raw_data

        normalized_data: Dict[str, str] = {}
        for path_key, digest in target_files.items():
            final_key = self.normalize_path(path_key) if normalize_legacy else path_key
            normalized_data[final_key] = digest.lower()

        return dict(sorted(normalized_data.items()))

    def migrate_legacy_baseline(
        self,
        key: Optional[bytes] = None,
        key_file: Optional[Union[str, Path]] = None,
        backup: bool = True,
    ) -> Dict[str, Any]:
        """Explicitly migrate an unsigned legacy baseline to HMAC-SHA256 authenticated format.

        Requires deliberate operator invocation. Creates a backup copy before signing.

        Args:
            key: Optional explicit HMAC secret key.
            key_file: Optional destination or source key file.
            backup: Whether to create a backup copy of the original baseline.

        Returns:
            Summary dictionary of the migration operation.

        Raises:
            ValueError: If baseline is already authenticated.
        """
        # Inspect raw baseline
        if not self.baseline_file.is_file():
            raise FileNotFoundError(f"Cannot migrate: baseline file '{self.baseline_file}' not found.")

        with open(self.baseline_file, "r", encoding="utf-8") as f:
            raw = json.load(f)

        if isinstance(raw, dict) and raw.get("auth_mode") == "hmac-sha256":
            raise ValueError(f"Baseline '{self.baseline_file}' is already authenticated with HMAC-SHA256.")

        legacy_data = self.load_baseline(allow_unsigned=True, normalize_legacy=False)

        backup_path: Optional[Path] = None
        if backup:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_path = self.baseline_file.with_name(f"{self.baseline_file.name}.legacy.{timestamp}.bak")
            backup_created = False
            try:
                with open(backup_path, "x", encoding="utf-8") as bf:
                    backup_created = True
                    json.dump(raw, bf, indent=4)
                    bf.flush()
                    os.fsync(bf.fileno())
            except FileExistsError as exc:
                raise FileExistsError(
                    f"Migration aborted: backup collision detected at '{backup_path}'. "
                    f"A backup file with this timestamp already exists. Refusing to overwrite existing backup."
                ) from exc
            except Exception:
                if backup_created and backup_path.exists():
                    try:
                        backup_path.unlink()
                    except OSError:
                        pass
                raise

        target_key = key or self.resolve_key()
        if not target_key:
            dest_key_file = key_file or self.key_file or self.get_default_key_path()
            target_key = generate_hmac_key(dest_key_file)
            self.raw_key = target_key

        self.save_baseline(legacy_data, key=target_key)

        return {
            "migrated_files": len(legacy_data),
            "baseline_file": str(self.baseline_file),
            "backup_file": str(backup_path) if backup_path else None,
            "auth_mode": "hmac-sha256",
        }


__all__ = [
    "BaselineAuthenticationError",
    "BaselineCorruptionError",
    "BaselineManager",
    "canonical_baseline_bytes",
    "compute_baseline_hmac",
    "generate_hmac_key",
    "resolve_hmac_key",
    "verify_baseline_hmac",
]
