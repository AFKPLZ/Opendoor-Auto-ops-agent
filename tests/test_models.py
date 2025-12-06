"""Tests for models.py - Data models."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from models import RequestRecord, ParsedIntent


@pytest.mark.unit
class TestRequestRecord:
    """Test RequestRecord data model."""

    def test_create_request_record(self):
        """Test creating a RequestRecord with new schema."""
        record = RequestRecord(
            id="req_001",
            user_email="alice@opendoor.com",
            department="Engineering",
            raw_text="Add me to Slack channel"
        )
        assert record.id == "req_001"
        assert record.user_email == "alice@opendoor.com"
        assert record.department == "Engineering"
        assert record.raw_text == "Add me to Slack channel"

    def test_request_record_string_id(self):
        """Test that ID can be a string."""
        record = RequestRecord(
            id="req_999",
            user_email="test@example.com",
            department="Finance",
            raw_text="test request"
        )
        assert isinstance(record.id, str)
        assert record.id == "req_999"

    def test_request_record_fields(self):
        """Test all fields are accessible."""
        record = RequestRecord(
            id="req_001",
            user_email="user@domain.com",
            department="Security",
            raw_text="Revoke access"
        )
        assert hasattr(record, 'id')
        assert hasattr(record, 'user_email')
        assert hasattr(record, 'department')
        assert hasattr(record, 'raw_text')


@pytest.mark.unit
class TestParsedIntent:
    """Test ParsedIntent data model."""

    def test_create_parsed_intent(self):
        """Test creating a ParsedIntent."""
        intent = ParsedIntent(
            intent="request_access",
            action_type="read_access",
            system="Slack",
            resource="#general",
            justification="team work",
            confidence=0.9,
            risk_score=0.1,
            malicious_score=0.0
        )
        assert intent.intent == "request_access"
        assert intent.action_type == "read_access"
        assert intent.system == "Slack"
        assert intent.resource == "#general"
        assert intent.confidence == 0.9

    def test_parsed_intent_optional_fields(self):
        """Test ParsedIntent with None values."""
        intent = ParsedIntent(
            intent=None,
            action_type=None,
            system=None,
            resource=None,
            justification=None,
            confidence=0.5,
            risk_score=0.3,
            malicious_score=0.1
        )
        assert intent.intent is None
        assert intent.action_type is None
        assert intent.system is None

    def test_parsed_intent_scores(self):
        """Test score fields are present."""
        intent = ParsedIntent(
            intent="test",
            action_type="read_access",
            system="Slack",
            resource="#test",
            justification="testing",
            confidence=0.85,
            risk_score=0.2,
            malicious_score=0.05
        )
        assert 0 <= intent.confidence <= 1
        assert 0 <= intent.risk_score <= 1
        assert 0 <= intent.malicious_score <= 1
