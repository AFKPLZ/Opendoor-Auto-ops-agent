"""Pytest configuration and shared fixtures."""
import json
import sys
from pathlib import Path
from typing import Any, Dict
from unittest.mock import Mock, MagicMock

import pytest

# Add src directory to Python path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture
def sample_policy() -> Dict[str, Any]:
    """Sample policy configuration for testing."""
    return {
        "roles": {
            "Engineering": {
                "allowed_systems": ["Slack", "Jira", "GitHub", "AWS"],
                "max_hardware_budget": 3000
            },
            "Finance": {
                "allowed_systems": ["Slack", "Jira", "NetSuite", "Excel"],
                "max_hardware_budget": 2000
            },
            "Interns": {
                "allowed_systems": ["Slack", "Jira"],
                "max_hardware_budget": 1500
            },
            "Security": {
                "allowed_systems": ["*"],
                "can_revoke_access": True,
                "max_hardware_budget": 5000
            }
        },
        "sensitive_actions": {
            "AWS": {
                "write_access": "REQUIRES_APPROVAL",
                "admin_access": "DENY"
            },
            "Okta": {
                "create_user": "REQUIRES_APPROVAL",
                "delete_user": "REQUIRES_APPROVAL",
                "assign_admin": "DENY",
                "admin_access": "DENY"
            }
        },
        "system_specific_rules": {
            "Slack": {
                "auto_approve_channels": ["#general", "#random"],
                "restricted_channels": ["#executive-confidential"]
            }
        }
    }


@pytest.fixture
def sample_request_record():
    """Sample RequestRecord for testing."""
    from models import RequestRecord
    return RequestRecord(
        id="req_001",
        user_email="alice@opendoor.com",
        department="Engineering",
        raw_text="Add me to #general Slack channel"
    )


@pytest.fixture
def sample_parsed_intent() -> Dict[str, Any]:
    """Sample parsed intent for testing."""
    return {
        "intent": "request_channel_access",
        "action_type": "read_access",
        "system": "Slack",
        "resource": "#general",
        "justification": "team collaboration",
        "confidence": 0.85,
        "risk_score": 0.1,
        "malicious_score": 0.0
    }


@pytest.fixture
def mock_llm_response():
    """Mock OpenAI LLM response."""
    mock_response = MagicMock()
    mock_choice = MagicMock()
    mock_message = MagicMock()

    mock_message.content = json.dumps({
        "intent": "request_access",
        "action_type": "read_access",
        "system": "Slack",
        "resource": "#general",
        "justification": "test",
        "confidence": 0.9,
        "risk_score": 0.1,
        "malicious_score": 0.0
    })
    mock_message.tool_calls = None

    mock_choice.message = mock_message
    mock_response.choices = [mock_choice]

    # Add usage stats
    mock_usage = MagicMock()
    mock_usage.prompt_tokens = 100
    mock_usage.completion_tokens = 50
    mock_usage.total_tokens = 150
    mock_response.usage = mock_usage

    return mock_response


@pytest.fixture
def mock_metrics():
    """Mock AgentMetrics for testing."""
    from metrics import AgentMetrics
    return AgentMetrics()
