"""SHA-256 hashing and safe recursive file discovery for Sentinel FIM.

The checks in this module reduce common time-of-check/time-of-use races, but
they cannot make path-based hashing race-free on every operating system. A
privileged concurrent actor may still alter filesystem state between system
calls; callers should treat a :class:`FileStabilityError` as inconclusive.
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional, Union

DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB


class FileStabilityError(RuntimeError):
    """Raised when a file changes identity or metadata while it is hashed."""


@dataclass
class ScanResult:
    """Results of a recursive scan, including individual file failures."""

    root_directory: str
    files: list[dict[str, Union[str, int]]] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    total_files: int = 0
    total_errors: int = 0
    success: bool = True

    def finalize(self) -> "ScanResult":
        self.files.sort(key=lambda item: str(item["relative_path"]))
        self.errors.sort(key=lambda item: (item["relative_path"], item["error_type"], item["error"]))
        self.total_files = len(self.files)
        self.total_errors = len(self.errors)
        self.success = not self.errors
        return self

    def as_dict(self) -> dict[str, Any]:
        """Return a serializable representation for a future baseline layer."""
        return {
            "root_directory": self.root_directory,
            "files": self.files,
            "errors": self.errors,
            "total_files": self.total_files,
            "total_errors": self.total_errors,
            "success": self.success,
        }


def _validate_chunk_size(chunk_size: int) -> int:
    """Validate a streaming chunk size without accepting boolean-like values."""
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")
    return chunk_size


def _metadata_signature(metadata: os.stat_result) -> tuple[int, int, int, int, int, int]:
    """Return metadata that must remain stable for a trustworthy snapshot.

    The complete ``st_mode`` is intentional: permission changes are treated as
    instability too. This can report a benign concurrent ``chmod`` as an
    inconclusive hash, but avoids asserting stability after observed metadata
    changed. ``st_ctime_ns`` captures additional metadata changes where the
    platform exposes it.
    """
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _path_and_descriptor_match(path_metadata: os.stat_result, descriptor_metadata: os.stat_result) -> bool:
    """Compare pathname and descriptor metadata across platform representations.

    Windows can expose a different ``st_ctime_ns`` through ``lstat`` and
    ``fstat`` for the same unchanged file. Therefore ctime is compared between
    descriptor snapshots on every platform, while path/descriptor comparisons
    omit only ctime on Windows to avoid false instability reports.
    """
    path_signature = _metadata_signature(path_metadata)
    descriptor_signature = _metadata_signature(descriptor_metadata)
    if os.name == "nt":
        return path_signature[:-1] == descriptor_signature[:-1]
    return path_signature == descriptor_signature


def _assert_regular(metadata: os.stat_result, file_path: Path) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise FileStabilityError(f"Not a regular file: {file_path}")


def _calculate_sha256_with_size(
    file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE
) -> tuple[str, int]:
    """Hash a stable regular file and return its digest and descriptor size.

    Files are read only through fixed-size binary chunks. Symlinks and
    non-regular files are rejected instead of being followed or interpreted.
    """
    _validate_chunk_size(chunk_size)
    path = Path(file_path)
    initial = path.lstat()
    if stat.S_ISLNK(initial.st_mode):
        raise ValueError(f"Refusing to hash symbolic link: {path}")
    _assert_regular(initial, path)

    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        _assert_regular(opened, path)
        if not _path_and_descriptor_match(initial, opened):
            raise FileStabilityError(f"File changed before hashing: {path}")

        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(chunk_size):
                digest.update(chunk)

        after_stream = os.fstat(descriptor)
        if _metadata_signature(opened) != _metadata_signature(after_stream):
            raise FileStabilityError(f"File changed while hashing: {path}")

        final_path = path.lstat()
        if stat.S_ISLNK(final_path.st_mode) or not _path_and_descriptor_match(final_path, after_stream):
            raise FileStabilityError(f"File path changed while hashing: {path}")
        return digest.hexdigest(), after_stream.st_size
    finally:
        os.close(descriptor)


def calculate_sha256(file_path: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Return a SHA-256 digest after checking file identity and stability.

    Files are read only through fixed-size binary chunks. Symlinks and
    non-regular files are rejected instead of being followed or interpreted.
    """
    return _calculate_sha256_with_size(file_path, chunk_size)[0]


def _relative_path(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _safe_error_relative_path(filename: Optional[str], root: Path) -> str:
    if not filename:
        return "."
    path = Path(filename)
    try:
        return _relative_path(path, root)
    except ValueError:
        # os.walk implementations may report a filename already relative to
        # the walk root. Keep that useful context without accepting traversal.
        if not path.is_absolute() and ".." not in path.parts:
            return path.as_posix()
        return "."


def _record_error(result: ScanResult, relative_path: str, error: BaseException) -> None:
    result.errors.append(
        {
            "relative_path": relative_path,
            "error": str(error),
            "error_type": type(error).__name__,
        }
    )


def scan_directory(directory: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> ScanResult:
    """Recursively hash regular files below *directory* without following links.

    Per-file and traversal failures are captured in ``ScanResult.errors``. Root
    and chunk-size validation failures are raised immediately.
    """
    _validate_chunk_size(chunk_size)
    root = Path(directory)
    root_stat = root.lstat()
    if stat.S_ISLNK(root_stat.st_mode):
        raise ValueError(f"Refusing symbolic-link root: {root}")
    if not stat.S_ISDIR(root_stat.st_mode):
        raise NotADirectoryError(f"Not a directory: {root}")
    resolved_root = root.resolve(strict=True)
    result = ScanResult(root_directory=str(resolved_root))

    def onerror(error: OSError) -> None:
        _record_error(result, _safe_error_relative_path(error.filename, root), error)

    for current_root, directories, filenames in os.walk(root, followlinks=False, onerror=onerror):
        current_path = Path(current_root)
        current_relative = _relative_path(current_path, root)
        try:
            current_stat = current_path.lstat()
            if stat.S_ISLNK(current_stat.st_mode):
                _record_error(result, current_relative, ValueError("Symbolic-link directory skipped"))
                directories[:] = []
                continue
            current_path.resolve(strict=True).relative_to(resolved_root)
        except (OSError, ValueError) as error:
            _record_error(result, current_relative, error)
            directories[:] = []
            continue
        retained_directories = []
        for name in directories:
            candidate = current_path / name
            relative = _relative_path(candidate, root)
            try:
                if candidate.is_symlink():
                    _record_error(result, relative, ValueError("Symbolic-link directory skipped"))
                else:
                    retained_directories.append(name)
            except OSError as error:
                _record_error(result, relative, error)
        directories[:] = retained_directories

        for name in filenames:
            candidate = current_path / name
            relative = _relative_path(candidate, root)
            try:
                candidate_stat = candidate.lstat()
                if stat.S_ISLNK(candidate_stat.st_mode):
                    _record_error(result, relative, ValueError("Symbolic-link file skipped"))
                    continue
                resolved_candidate = candidate.resolve(strict=True)
                try:
                    resolved_candidate.relative_to(resolved_root)
                except ValueError as error:
                    raise FileStabilityError(f"Path escapes monitored root: {candidate}") from error
                _assert_regular(candidate_stat, candidate)
                digest, size_bytes = _calculate_sha256_with_size(candidate, chunk_size)
                result.files.append(
                    {
                        "relative_path": relative,
                        "sha256": digest,
                        "size_bytes": size_bytes,
                    }
                )
            except (OSError, ValueError, FileStabilityError) as error:
                _record_error(result, relative, error)

    return result.finalize()


class FileHasher:
    """Compatibility wrapper for SHA-256 file hashing."""

    DEFAULT_ALGORITHM: str = "sha256"
    BUFFER_SIZE: int = DEFAULT_CHUNK_SIZE

    def __init__(self, algorithm: str = DEFAULT_ALGORITHM, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        if not isinstance(algorithm, str) or algorithm.lower() != self.DEFAULT_ALGORITHM:
            raise ValueError("Sentinel FIM supports SHA-256 only")
        self.algorithm = self.DEFAULT_ALGORITHM
        self.chunk_size = _validate_chunk_size(chunk_size)

    def calculate_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the configured SHA-256 digest for a regular, stable file."""
        return calculate_sha256(file_path, self.chunk_size)


__all__ = [
    "DEFAULT_CHUNK_SIZE",
    "FileHasher",
    "FileStabilityError",
    "ScanResult",
    "calculate_sha256",
    "scan_directory",
    "_calculate_sha256_with_size",
    "_metadata_signature",
    "_path_and_descriptor_match",
    "_safe_error_relative_path",
    "_validate_chunk_size",
]
