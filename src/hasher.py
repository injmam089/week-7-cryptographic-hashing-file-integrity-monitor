"""Sentinel FIM - Cryptographic Hashing Engine.

Provides memory-efficient SHA-256 cryptographic hashing for files
using fixed-size chunk streaming to prevent memory exhaustion on large files.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Union

# Default streaming buffer: 4096 bytes (4 KB) for efficient I/O
DEFAULT_CHUNK_SIZE: int = 4096


def calculate_sha256(filepath: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """Calculate the SHA-256 cryptographic hash of a file reading in chunks.

    Reads the target file in binary chunks (default: 4096 bytes) to ensure
    memory-efficient processing regardless of file size.

    Args:
        filepath: Path to the target file (str or pathlib.Path).
        chunk_size: Number of bytes to read per iteration (default: 4096).

    Returns:
        Hexadecimal SHA-256 digest string (64 characters, lowercase).

    Raises:
        FileNotFoundError: If the target file does not exist.
        IsADirectoryError: If the specified path points to a directory.
        PermissionError: If read permissions are lacking.
        ValueError: If chunk_size is not a positive integer.
    """
    if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
        raise ValueError("chunk_size must be a positive integer")

    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if path.is_dir():
        raise IsADirectoryError(f"Target is a directory, not a file: {path}")

    hasher = hashlib.sha256()

    with open(path, "rb") as stream:
        while chunk := stream.read(chunk_size):
            hasher.update(chunk)

    return hasher.hexdigest()


class FileHasher:
    """Object-oriented wrapper for cryptographic hashing operations."""

    DEFAULT_ALGORITHM: str = "sha256"
    BUFFER_SIZE: int = DEFAULT_CHUNK_SIZE

    def __init__(self, algorithm: str = DEFAULT_ALGORITHM, chunk_size: int = DEFAULT_CHUNK_SIZE) -> None:
        if not isinstance(algorithm, str) or algorithm.lower() != self.DEFAULT_ALGORITHM:
            raise ValueError(f"Sentinel FIM supports SHA-256 only; received '{algorithm}'")
        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            raise ValueError("chunk_size must be a positive integer")
        self.algorithm = self.DEFAULT_ALGORITHM
        self.chunk_size = chunk_size

    def calculate_hash(self, file_path: Union[str, Path]) -> str:
        """Calculate the SHA-256 digest for a given file."""
        return calculate_sha256(file_path, chunk_size=self.chunk_size)
