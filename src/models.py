"""Data models and constants for the auto_ops_agent CLI."""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

ALLOWED_INTENTS: set[str] = {"grant_access", "restart_service", "deploy"}
KNOWN_RESOURCES: set[str] = {"prod-db", "cache-cluster", "service-logs", "frontend-service", "backend-service"}
PolicyStatus = Tuple[str, Optional[str]]


@dataclass
class ParsedIntent:
    intent: str
    resource: str
    justification: str


@dataclass
class RequestRecord:
    id: int
    user: str
    groups: List[str]
    text: str
