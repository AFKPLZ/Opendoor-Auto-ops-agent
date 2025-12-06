"""Centralized policy loading and management for auto_ops_agent."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

# Policy file path
POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.json"


def load_policy(path: Path = POLICY_PATH) -> Dict[str, Any]:
    """
    Load policy configuration from JSON file.

    Args:
        path: Path to policy.json file (default: POLICY_PATH)

    Returns:
        Dictionary containing policy configuration

    Raises:
        FileNotFoundError: If policy file doesn't exist
        json.JSONDecodeError: If policy file is malformed
    """
    with path.open("r", encoding="utf-8") as policy_file:
        return json.load(policy_file)


# Global policy instance - loaded once at module import
RAW_POLICY: Dict[str, Any] = load_policy()
