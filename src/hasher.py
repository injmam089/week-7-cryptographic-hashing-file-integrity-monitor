from __future__ import annotations
import hashlib
from pathlib import Path
from typing import Union

DEFAULT_CHUNK_SIZE: int = 4096

def calculate_sha256(filepath: Union[str, Path], chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
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
        return calculate_sha256(file_path, chunk_size=self.chunk_size)
