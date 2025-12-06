"""Deterministic policy enforcement for auto_ops_agent with observability."""
from __future__ import annotations

import re
import time
from typing import Any, Dict, List, Tuple

from logging_utils import logger
from metrics import AgentMetrics
from policy import RAW_POLICY

Decision = Tuple[str, str | None]


def _parse_amount_from_text(text: str | None) -> float | None:
    if not text:
        return None
    # First try to match dollar amounts (prioritize $ prefix)
    match = re.search(r"\$(\d+(?:\.\d+)?)", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    # If no dollar sign found, match standalone numbers
    match = re.search(r"\b(\d+(?:\.\d+)?)\b", text)
    if match:
        try:
            return float(match.group(1))
        except ValueError:
            return None
    return None


def _is_system_allowed(system: str | None, user_groups: List[str], policy: Dict[str, Any]) -> bool:
    """Check if user's role allows access to the specified system."""
    if not system:
        return False
    roles = policy.get("roles", {})
    for group in user_groups:
        allowed_systems = roles.get(group, {}).get("allowed_systems", [])
        # Handle wildcard "*" (Security role can access all systems)
        if "*" in allowed_systems:
            return True
        # Case-insensitive system matching
        if system.lower() in [s.lower() for s in allowed_systems]:
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

    # Extract known_systems from roles (no longer at root level)
    known_systems = set()
    for role_config in raw_policy.get("roles", {}).values():
        allowed = role_config.get("allowed_systems", [])
        # Skip wildcard "*" when building known_systems list
        known_systems.update([s for s in allowed if s != "*"])

    decision: str = "MANUAL_REVIEW"
    reason: str | None = "Unknown or missing system"

    # Check for Security role with revoke_access permission
    has_revoke_permission = False
    for group in user_groups:
        role_config = raw_policy.get("roles", {}).get(group, {})
        if role_config.get("can_revoke_access", False):
            has_revoke_permission = True
            break

    # Special handling for revoke_access intent (Security role only)
    if intent == "revoke_access" and not has_revoke_permission:
        decision, reason = "DENIED", "Only Security team can revoke access"
    # Admin access check (highest priority denial)
    elif intent == "request_admin_access" or action_type == "admin_access":
        decision, reason = "DENIED", "Admin access is forbidden by policy"
    # Hardware requests don't require a system, so check them separately
    elif intent == "request_hardware":
        # NEW: Hardware budget is per-role, not global
        max_budget = None
        for group in user_groups:
            role_config = raw_policy.get("roles", {}).get(group, {})
            role_budget = role_config.get("max_hardware_budget")
            if role_budget is not None:
                max_budget = max(max_budget or 0, role_budget)

        amount = _parse_amount_from_text(resource) or _parse_amount_from_text(justification)
        if max_budget is not None and amount is not None and amount > max_budget:
            decision, reason = "DENIED", f"Hardware request (${amount}) exceeds budget (${max_budget})"
        else:
            decision, reason = "APPROVED", None
    # System validation (only for non-hardware requests)
    elif not system or (system.lower() not in [s.lower() for s in known_systems] and not _is_system_allowed(system, user_groups, raw_policy)):
        decision, reason = "MANUAL_REVIEW", "Unknown or missing system"
    elif not _is_system_allowed(system, user_groups, raw_policy):
        decision, reason = "DENIED", f"User '{user}' lacks system access for '{system}'"
    else:
        # NEW: sensitive_actions is now organized by system -> action_type
        sensitive_actions = raw_policy.get("sensitive_actions", {})
        system_sensitive = sensitive_actions.get(system, {}) if system else {}

        if action_type and action_type in system_sensitive:
            rule = system_sensitive[action_type]
            if rule == "DENY":
                decision, reason = "DENIED", f"Action '{action_type}' on {system} is denied by policy"
            elif rule == "REQUIRES_APPROVAL":
                decision, reason = "MANUAL_REVIEW", f"Action '{action_type}' on {system} requires approval"
            else:
                decision, reason = "APPROVED", None
        else:
            system_rules = raw_policy.get("system_specific_rules", {}).get(system, {})
            # Case-insensitive system matching for rules
            if not system_rules and system:
                for sys_key, sys_val in raw_policy.get("system_specific_rules", {}).items():
                    if sys_key.lower() == system.lower():
                        system_rules = sys_val
                        break

            if system and system.lower() == "slack" and resource in system_rules.get("restricted_channels", []):
                decision, reason = "DENIED", "Channel is restricted"
            elif system and system.lower() == "jira" and resource in system_rules.get("restricted_projects", []):
                decision, reason = "DENIED", "Project is restricted"
            elif malicious_score >= 0.5 or risk_score >= 0.7:
                decision, reason = "MANUAL_REVIEW", "Risk thresholds exceeded"
            # Check auto-approve channels for Slack
            elif system and system.lower() == "slack" and resource in system_rules.get("auto_approve_channels", []):
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
