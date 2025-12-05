"""Deterministic policy enforcement for auto_ops_agent with observability."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

from logging_utils import logger
from metrics import AgentMetrics

POLICY_PATH = Path(__file__).resolve().parent.parent / "policy.json"
Decision = Tuple[str, str | None]


def load_policy(path: Path = POLICY_PATH) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as policy_file:
        return json.load(policy_file)


RAW_POLICY: Dict[str, Any] = load_policy()


def _parse_amount_from_text(text: str | None) -> float | None:
    if not text:
        return None
    match = re.search(r"\$?(\d+(?:\.\d+)?)", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _is_system_allowed(system: str | None, user_groups: List[str], policy: Dict[str, Any]) -> bool:
    if not system:
        return False
    roles = policy.get("roles", {})
    for group in user_groups:
        allowed_systems = roles.get(group, {}).get("allowed_systems", [])
        if system in allowed_systems:
            return True
    return False


def evaluate_request(parsed_intent: Dict[str, Any], user: str, raw_policy: Dict[str, Any], user_groups: List[str] | None = None, metrics: AgentMetrics | None = None) -> Decision:
    """
    Apply deterministic policy logic to LLM/regex parsed intent.

    Returns: (APPROVED | DENIED | MANUAL_REVIEW, reason)
    """
    policy_start = time.time()
    user_groups = user_groups or []
    intent = parsed_intent.get("intent")
    system = parsed_intent.get("system")
    action_type = parsed_intent.get("action_type")
    resource = parsed_intent.get("resource")
    justification = parsed_intent.get("justification")
    risk_score = parsed_intent.get("risk_score", 0.0) or 0.0
    malicious_score = parsed_intent.get("malicious_score", 0.0) or 0.0

    known_systems = set(raw_policy.get("known_systems", []))

    decision: str = "MANUAL_REVIEW"
    reason: str | None = "Unknown or missing system"

    if not system or system not in known_systems:
        decision, reason = "MANUAL_REVIEW", "Unknown or missing system"
    elif intent == "request_admin_access" or action_type == "admin_access":
        decision, reason = "DENIED", "Admin access is forbidden by policy"
    elif not _is_system_allowed(system, user_groups, raw_policy):
        decision, reason = "DENIED", f"User '{user}' lacks system access for '{system}'"
    else:
        sensitive_actions = raw_policy.get("sensitive_actions", {})
        if action_type in sensitive_actions:
            rule = sensitive_actions[action_type].get("rule", "MANUAL_REVIEW")
            if rule == "DENY":
                decision, reason = "DENIED", f"Action '{action_type}' is denied by policy"
            elif rule == "REQUIRES_APPROVAL":
                decision, reason = "MANUAL_REVIEW", f"Action '{action_type}' requires approval"
            else:
                decision, reason = "APPROVED", None
        else:
            system_rules = raw_policy.get("system_specific_rules", {}).get(system, {})
            if system == "slack" and resource in system_rules.get("restricted_channels", []):
                decision, reason = "DENIED", "Channel is restricted"
            elif system == "jira" and resource in system_rules.get("restricted_projects", []):
                decision, reason = "DENIED", "Project is restricted"
            elif malicious_score >= 0.5 or risk_score >= 0.7:
                decision, reason = "MANUAL_REVIEW", "Risk thresholds exceeded"
            elif intent == "request_hardware":
                max_budget = raw_policy.get("hardware_budget", {}).get("max_per_request")
                amount = _parse_amount_from_text(resource) or _parse_amount_from_text(justification)
                if max_budget is not None and amount is not None and amount > max_budget:
                    decision, reason = "DENIED", "Hardware request exceeds budget"
                else:
                    decision, reason = "APPROVED", None
            else:
                decision, reason = "APPROVED", None

    logger.info(
        "Policy evaluation result",
        extra={
            "extra": {
                "correlation_id": metrics.correlation_id if metrics else None,
                "decision": decision,
                "reason": reason,
                "intent": intent,
                "system": system,
                "action_type": action_type,
            }
        },
    )

    if metrics:
        metrics.policy_decision = decision
        metrics.decision_reason = reason
        metrics.policy_latency_ms = int((time.time() - policy_start) * 1000)

    return decision, reason


# Alias for compatibility
evaluate_policy = evaluate_request
