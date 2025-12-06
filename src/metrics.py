"""Metrics collection for the auto_ops_agent."""
from __future__ import annotations

import time
import uuid
from typing import Any, Dict


class AgentMetrics:
    def __init__(self) -> None:
        self.correlation_id = str(uuid.uuid4())
        self.start_time = time.time()

        # LLM metrics
        self.llm_calls: int = 0
        self.tool_calls: int = 0
        self.tokens_prompt: int = 0
        self.tokens_completion: int = 0

        # Parser metrics
        self.parser_latency_ms: int = 0
        self.fallback_used: bool = False
        self.suspicious_input: bool = False
        self.invalid_scores: bool = False
        self.invalid_system_resource: bool = False

        # Policy engine metrics
        self.policy_decision: str | None = None
        self.decision_reason: str | None = None
        self.policy_latency_ms: int = 0

        # End-to-end metrics
        self.total_latency_ms: int = 0

    @property
    def tokens_total(self) -> int:
        """Calculate total tokens as sum of prompt and completion tokens."""
        return self.tokens_prompt + self.tokens_completion

    def finalize(self) -> Dict[str, Any]:
        """Finalize metrics and return as dictionary with computed fields."""
        self.total_latency_ms = int((time.time() - self.start_time) * 1000)
        result = self.__dict__.copy()
        result["tokens_total"] = self.tokens_total
        return result
