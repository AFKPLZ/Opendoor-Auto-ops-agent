"""Data models and constants for the auto_ops_agent CLI."""
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

ALLOWED_INTENTS: set[str] = {"grant_access", "restart_service", "deploy"}
KNOWN_RESOURCES: set[str] = {"prod-db", "cache-cluster", "service-logs", "frontend-service", "backend-service"}
PolicyStatus = Tuple[str, Optional[str]]


@dataclass
class ParsedIntent:
    """Structured intent parsed from raw text."""
    intent: Optional[str]
    action_type: Optional[str]
    system: Optional[str]
    resource: Optional[str]
    justification: Optional[str]
    confidence: float
    risk_score: float
    malicious_score: float


@dataclass
class RequestRecord:
    """User request record with updated schema matching input.json."""
    id: str  # Changed from int to str to handle "req_001" format
    user_email: str  # Changed from 'user' to 'user_email'
    department: str  # Changed from 'groups' (List[str]) to 'department' (str)
    raw_text: str  # Changed from 'text' to 'raw_text'
