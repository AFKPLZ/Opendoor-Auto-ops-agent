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
        self.tokens_total: int = 0

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

    def finalize(self) -> Dict[str, Any]:
        self.total_latency_ms = int((time.time() - self.start_time) * 1000)
        return self.__dict__
