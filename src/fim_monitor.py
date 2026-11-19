"""Sentinel FIM - Main Orchestration Entry Point.

Coordinates configuration loading, baseline generation, and file integrity
monitoring workflows. Provides CLI interface for security operations.

Phase 0: Architecture skeleton. Full engine implementation scheduled for Phase 1.
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict


def load_config(config_path: Path) -> Dict[str, Any]:
    """Load and validate the FIM JSON configuration file.

    Args:
        config_path: Path to fim_config.json.

    Returns:
        Dictionary containing parsed configuration parameters.

    Raises:
        FileNotFoundError: If configuration file is missing.
        json.JSONDecodeError: If configuration contains invalid JSON.
    """
    if not config_path.is_file():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    # Basic schema validation
    required_keys = {"algorithm", "monitored_directory", "baseline_file"}
    missing = required_keys - set(config.keys())
    if missing:
        raise ValueError(f"Configuration missing required keys: {missing}")

    return config


def main() -> None:
    """Main CLI entry point for Sentinel FIM.

    Phase 0: Foundation validation and skeleton notice.
    """
    print("=" * 60)
    print(" Sentinel FIM -- File Integrity Monitor (Phase 0)")
    print("=" * 60)
    print("[INFO] Foundation initialized. Ready for Phase 1 implementation.")


if __name__ == "__main__":
    main()
