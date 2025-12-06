"""Tests for policy_engine.py - Core policy decision logic."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from policy_engine import evaluate_request, _is_system_allowed, _parse_amount_from_text


class TestParseAmountFromText:
    """Test amount parsing from text."""

    def test_parse_dollar_amount(self):
        assert _parse_amount_from_text("$2500") == 2500.0
        assert _parse_amount_from_text("$1500.50") == 1500.50

    def test_parse_amount_without_dollar(self):
        assert _parse_amount_from_text("3000") == 3000.0
        assert _parse_amount_from_text("2500.99") == 2500.99

    def test_parse_no_amount(self):
        assert _parse_amount_from_text("laptop") is None
        assert _parse_amount_from_text("") is None
        assert _parse_amount_from_text(None) is None


class TestIsSystemAllowed:
    """Test system permission checking."""

    def test_system_allowed_exact_match(self, sample_policy):
        assert _is_system_allowed("Slack", ["Engineering"], sample_policy) is True
        assert _is_system_allowed("AWS", ["Engineering"], sample_policy) is True

    def test_system_allowed_case_insensitive(self, sample_policy):
        assert _is_system_allowed("slack", ["Engineering"], sample_policy) is True
        assert _is_system_allowed("SLACK", ["Engineering"], sample_policy) is True

    def test_system_not_allowed(self, sample_policy):
        assert _is_system_allowed("NetSuite", ["Engineering"], sample_policy) is False
        assert _is_system_allowed("AWS", ["Interns"], sample_policy) is False

    def test_wildcard_system_access(self, sample_policy):
        """Security role has wildcard access to all systems."""
        assert _is_system_allowed("Slack", ["Security"], sample_policy) is True
        assert _is_system_allowed("AWS", ["Security"], sample_policy) is True
        assert _is_system_allowed("AnythingElse", ["Security"], sample_policy) is True

    def test_no_system(self, sample_policy):
        assert _is_system_allowed(None, ["Engineering"], sample_policy) is False
        assert _is_system_allowed("", ["Engineering"], sample_policy) is False


@pytest.mark.unit
class TestEvaluateRequestApproved:
    """Test APPROVED policy decisions."""

    def test_approve_auto_approve_channel(self, sample_policy, mock_metrics):
        """Auto-approve channels should be approved."""
        parsed_intent = {
            "intent": "request_channel_access",
            "action_type": "read_access",
            "system": "Slack",
            "resource": "#general",
            "justification": "team communication",
            "confidence": 0.9,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "APPROVED"
        assert reason is None

    def test_approve_jira_access(self, sample_policy, mock_metrics):
        """Finance user accessing allowed system (Jira)."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "Jira",
            "resource": "SUPPORT-123",
            "justification": "track customer issues",
            "confidence": 0.85,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "bob@opendoor.com", sample_policy, ["Finance"], mock_metrics
        )
        assert decision == "APPROVED"

    def test_approve_security_revoke_access(self, sample_policy, mock_metrics):
        """Security team can revoke access."""
        parsed_intent = {
            "intent": "revoke_access",
            "action_type": "revoke_access",
            "system": "Slack",
            "resource": "user@example.com",
            "justification": "offboarding",
            "confidence": 0.9,
            "risk_score": 0.2,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "security@opendoor.com", sample_policy, ["Security"], mock_metrics
        )
        assert decision == "APPROVED"

    def test_approve_hardware_within_budget(self, sample_policy, mock_metrics):
        """Hardware request within budget should be approved."""
        parsed_intent = {
            "intent": "request_hardware",
            "action_type": None,
            "system": None,
            "resource": "MacBook Pro $2500",
            "justification": "development work",
            "confidence": 0.8,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "APPROVED"
        assert reason is None


@pytest.mark.unit
class TestEvaluateRequestDenied:
    """Test DENIED policy decisions."""

    def test_deny_admin_access_intent(self, sample_policy, mock_metrics):
        """Admin access should always be denied."""
        parsed_intent = {
            "intent": "request_admin_access",
            "action_type": "admin_access",
            "system": "AWS",
            "resource": "prod-db",
            "justification": "emergency",
            "confidence": 0.9,
            "risk_score": 0.5,
            "malicious_score": 0.1
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "DENIED"
        assert "admin access is forbidden" in reason.lower()

    def test_deny_admin_action_type(self, sample_policy, mock_metrics):
        """Admin action_type should be denied."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "admin_access",
            "system": "Okta",
            "resource": "user-management",
            "justification": "user admin",
            "confidence": 0.85,
            "risk_score": 0.6,
            "malicious_score": 0.2
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "DENIED"

    def test_deny_user_lacks_system_permission(self, sample_policy, mock_metrics):
        """User from Finance accessing AWS should be denied."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "AWS",
            "resource": "ec2",
            "justification": "check instances",
            "confidence": 0.9,
            "risk_score": 0.2,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "bob@opendoor.com", sample_policy, ["Finance"], mock_metrics
        )
        assert decision == "DENIED"
        assert "lacks system access" in reason.lower()

    def test_deny_restricted_channel(self, sample_policy, mock_metrics):
        """Accessing restricted Slack channel should be denied."""
        parsed_intent = {
            "intent": "request_channel_access",
            "action_type": "read_access",
            "system": "Slack",
            "resource": "#executive-confidential",
            "justification": "need info",
            "confidence": 0.8,
            "risk_score": 0.3,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "DENIED"
        assert "restricted" in reason.lower()

    def test_deny_hardware_exceeds_budget(self, sample_policy, mock_metrics):
        """Hardware exceeding role budget should be denied."""
        parsed_intent = {
            "intent": "request_hardware",
            "action_type": None,
            "system": None,
            "resource": "MacBook Pro M3 Max $3500",
            "justification": "development",
            "confidence": 0.85,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "charlie@opendoor.com", sample_policy, ["Interns"], mock_metrics
        )
        assert decision == "DENIED"
        assert "exceeds budget" in reason.lower()

    def test_deny_non_security_revoke_access(self, sample_policy, mock_metrics):
        """Non-Security users cannot revoke access."""
        parsed_intent = {
            "intent": "revoke_access",
            "action_type": "revoke_access",
            "system": "Slack",
            "resource": "user@example.com",
            "justification": "user left",
            "confidence": 0.8,
            "risk_score": 0.3,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "DENIED"
        assert "only security team" in reason.lower()


@pytest.mark.unit
class TestEvaluateRequestManualReview:
    """Test MANUAL_REVIEW policy decisions."""

    def test_manual_review_unknown_system(self, sample_policy, mock_metrics):
        """Unknown system should trigger manual review."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "QuantumDB",
            "resource": "database",
            "justification": "research",
            "confidence": 0.7,
            "risk_score": 0.2,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "MANUAL_REVIEW"
        assert "unknown" in reason.lower()

    def test_manual_review_write_access_requires_approval(self, sample_policy, mock_metrics):
        """Write access to AWS requires approval."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "write_access",
            "system": "AWS",
            "resource": "prod-db",
            "justification": "update schema",
            "confidence": 0.85,
            "risk_score": 0.4,
            "malicious_score": 0.1
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "MANUAL_REVIEW"
        assert "requires approval" in reason.lower()

    def test_manual_review_high_risk_score(self, sample_policy, mock_metrics):
        """High risk score triggers manual review."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "AWS",
            "resource": "customer-db",
            "justification": "dump all data",
            "confidence": 0.7,
            "risk_score": 0.8,
            "malicious_score": 0.4
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "MANUAL_REVIEW"
        assert "risk" in reason.lower()

    def test_manual_review_high_malicious_score(self, sample_policy, mock_metrics):
        """High malicious score triggers manual review."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "Slack",
            "resource": "#general",
            "justification": "exfiltrate company secrets",
            "confidence": 0.6,
            "risk_score": 0.6,
            "malicious_score": 0.7
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "MANUAL_REVIEW"
        assert "risk" in reason.lower()


@pytest.mark.unit
class TestCaseInsensitiveMatching:
    """Test case-insensitive system matching."""

    def test_lowercase_system_name(self, sample_policy, mock_metrics):
        """Lowercase system names should work."""
        parsed_intent = {
            "intent": "request_channel_access",
            "action_type": "read_access",
            "system": "slack",
            "resource": "#general",
            "justification": "team work",
            "confidence": 0.9,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "APPROVED"

    def test_uppercase_system_name(self, sample_policy, mock_metrics):
        """Uppercase system names should work."""
        parsed_intent = {
            "intent": "request_access",
            "action_type": "read_access",
            "system": "JIRA",
            "resource": "PROJECT-123",
            "justification": "track tasks",
            "confidence": 0.85,
            "risk_score": 0.1,
            "malicious_score": 0.0
        }
        decision, reason = evaluate_request(
            parsed_intent, "alice@opendoor.com", sample_policy, ["Engineering"], mock_metrics
        )
        assert decision == "APPROVED"
