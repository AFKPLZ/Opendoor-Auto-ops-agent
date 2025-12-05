"""Executor that builds structured action payloads without external side effects."""
from __future__ import annotations

from typing import Any, Dict, Optional

DEFAULT_ACTIONS: Dict[str, str] = {
    "grant_access": "AWS_IAM_GRANT",
    "restart_service": "EC2_RESTART",
    "deploy": "CODEDEPLOY_RELEASE",
}


def _resolve_service(resource: str, policies: Optional[Dict[str, Any]]) -> str:
    if not policies:
        return "UNKNOWN"
    return policies.get("resources", {}).get(resource, {}).get("service", "UNKNOWN")


def _resolve_action(intent: str, resource: str, policies: Optional[Dict[str, Any]]) -> str:
    if policies:
        rule = policies.get("resources", {}).get(resource, {})
        action = rule.get("action")
        if action:
            return action
    return DEFAULT_ACTIONS.get(intent, "UNKNOWN_ACTION")


def build_action_payload(
    request_id: int,
    parsed_intent: Dict[str, str],
    status: str,
    reason: Optional[str],
    user: str,
    policies: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    intent = parsed_intent.get("intent", "unknown")
    resource = parsed_intent.get("resource", "unknown")
    justification = parsed_intent.get("justification", "")

    service = _resolve_service(resource, policies)
    action = _resolve_action(intent, resource, policies)

    result: Dict[str, Any] = {
        "request_id": request_id,
        "status": status,
        "service": service,
        "action": action,
        "payload": {
            "intent": intent,
            "resource": resource,
            "requested_by": user,
            "justification": justification,
        },
    }

    if reason:
        result["reason"] = reason

    if status != "APPROVED":
        # Keep payload but signal no external execution performed.
        result.setdefault("payload", {}).update({"executed": False})
    else:
        result.setdefault("payload", {}).update({"executed": True})

    return result
