"""Security utilities for prompt injection detection."""
from __future__ import annotations

from typing import List


def detect_prompt_injection(text: str) -> bool:
    patterns: List[str] = [
        "ignore previous",
        "follow my instructions",
        "disregard system",
        "override",
        "as assistant",
        "return this json",
        "tool_call",
        "function_call",
        "i command you",
        "act as",
    ]
    lowered = text.lower()
    return any(p in lowered for p in patterns)
