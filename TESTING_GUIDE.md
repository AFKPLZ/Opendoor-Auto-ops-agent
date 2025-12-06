# Testing Guide for Auto-Ops Agent

## Overview

This guide covers the comprehensive test suite for the Auto-Ops Agent, including unit tests, integration tests, and instructions for running and extending the tests.

## What Was Updated

### 1. Code Changes to Support New Schema

#### Updated Files:
- **src/models.py**: Changed RequestRecord fields from `(id: int, user: str, groups: List[str], text: str)` to `(id: str, user_email: str, department: str, raw_text: str)`
- **src/main.py**: Updated `load_requests()` to map new field names and wrap department in list for policy evaluation
- **src/policy_engine.py**:
  - Rewrote sensitive_actions lookup (now system → action_type instead of flat)
  - Updated hardware budget logic (per-role instead of global)
  - Added Security role handling (wildcard "*" and can_revoke_access)
  - Added case-insensitive system matching
- **src/intent_parser.py**: Extract known_systems from roles only (no root-level field)

#### Enhanced Configuration:
- **policy.json**: Added Operations role, enhanced system_specific_rules for Jira, GitHub, AWS
- **input.json**: Expanded from 6 to 15 requests covering edge cases

### 2. Test Suite Structure

```
tests/
├── __init__.py
├── conftest.py                 # Shared fixtures
├── test_models.py             # Data model tests
├── test_policy_engine.py      # Policy decision logic tests (60+ test cases)
├── test_integration.py        # End-to-end workflow tests
└── fixtures/
```

## Test Coverage

### test_models.py
Tests the data models:
- ✅ RequestRecord creation with new schema
- ✅ String ID handling ("req_001" format)
- ✅ All field accessors
- ✅ ParsedIntent with all required fields
- ✅ Optional field handling (None values)
- ✅ Score validation

### test_policy_engine.py (60+ tests)

**APPROVED Cases:**
- ✅ Auto-approve Slack channels (#general, #random, #fde-team-updates)
- ✅ User accessing allowed systems (Engineering → AWS, Finance → Jira)
- ✅ Security team revoking access
- ✅ Hardware requests within budget
- ✅ Case-insensitive system matching

**DENIED Cases:**
- ✅ Admin access attempts (always denied)
- ✅ Users lacking system permissions (Finance → AWS)
- ✅ Restricted channels (#executive-confidential)
- ✅ Hardware exceeding budget
- ✅ Non-Security users trying to revoke access
- ✅ System-specific sensitive actions (AWS write_access with DENY rule)

**MANUAL_REVIEW Cases:**
- ✅ Unknown systems (QuantumDB)
- ✅ Write access requiring approval (AWS write_access)
- ✅ High risk scores (≥0.7)
- ✅ High malicious scores (≥0.5)
- ✅ Okta user operations (create_user, delete_user)

### test_integration.py

**End-to-End Tests:**
- ✅ Load requests from actual input.json
- ✅ Verify field mapping correctness
- ✅ Test expected decisions for sample requests:
  - req_001: Slack channel → APPROVED
  - req_002: Finance → AWS → DENIED (no permission)
  - req_003: Intern expensive MacBook → DENIED (exceeds $1500)
  - req_006: Prompt injection → DENIED/MANUAL_REVIEW
- ✅ Metrics collection (correlation_id, latency)
- ✅ Unique correlation IDs per request

## Input.json Edge Cases

The expanded input.json now includes 15 requests covering:

1. **req_001**: Normal Slack channel access (auto-approve) → APPROVED
2. **req_002**: Finance user requesting AWS (lacks permission) → DENIED
3. **req_003**: Intern requesting expensive hardware (budget) → DENIED
4. **req_004**: Ambiguous Jira request (no specifics) → APPROVED/MANUAL_REVIEW
5. **req_005**: Security revoking access → APPROVED
6. **req_006**: Prompt injection attack → DENIED/MANUAL_REVIEW
7. **req_007**: Restricted channel access → DENIED
8. **req_008**: Admin access attempt → DENIED
9. **req_009**: Unknown system (QuantumDB) → MANUAL_REVIEW
10. **req_010**: Marketing user requesting AWS (no permission) → DENIED
11. **req_011**: Hardware within budget → APPROVED
12. **req_012**: Multi-system mention → Picks first system
13. **req_013**: Empty/whitespace text → MANUAL_REVIEW
14. **req_014**: Very long urgent request (>500 chars) → Risk-based decision
15. **req_015**: Google Drive request (ambiguous) → Based on Finance permissions

## Running the Tests

### Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- openai>=1.30.0
- pytest>=7.4.0
- pytest-cov>=4.1.0
- pytest-mock>=3.11.1

### Run All Tests

```bash
pytest
```

### Run Specific Test Files

```bash
# Unit tests only
pytest tests/test_models.py tests/test_policy_engine.py -v

# Integration tests only
pytest tests/test_integration.py -v

# With coverage report
pytest --cov=src --cov-report=html
```

### Run Tests by Marker

```bash
# Unit tests
pytest -m unit

# Integration tests
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

## Expected Test Results

### All 15 Input Requests - Expected Decisions

| ID | Description | Expected Decision | Reason |
|----|-------------|------------------|--------|
| req_001 | Slack #fde-team-updates | APPROVED | Auto-approve channel |
| req_002 | Finance → AWS write | DENIED | Finance lacks AWS permission |
| req_003 | Intern MacBook M3 Max | DENIED | Exceeds $1500 budget |
| req_004 | Jira access | APPROVED | Operations has Jira access |
| req_005 | Security revoke | APPROVED | Security has can_revoke_access |
| req_006 | Prompt injection | DENIED | Admin access denied |
| req_007 | #executive-confidential | DENIED | Restricted channel |
| req_008 | AWS admin access | DENIED | Admin access forbidden |
| req_009 | QuantumDB unknown | MANUAL_REVIEW | Unknown system |
| req_010 | Marketing → AWS | DENIED | Marketing lacks AWS |
| req_011 | $2500 laptop (Eng) | APPROVED | Within $3000 budget |
| req_012 | Multi-system | APPROVED | First system (Slack) allowed |
| req_013 | Empty text | MANUAL_REVIEW | No valid intent |
| req_014 | Long urgent request | MANUAL_REVIEW | High risk score likely |
| req_015 | Google Drive | DENIED | Finance lacks GSuite/Google |

## Policy Rules Summary

### Roles

| Role | Allowed Systems | Budget | Special |
|------|----------------|--------|---------|
| Engineering | Slack, Jira, GitHub, AWS | $3000 | - |
| Finance | Slack, Jira, NetSuite, Excel | $2000 | - |
| Interns | Slack, Jira | $1500 | - |
| Operations | Slack, Jira, AWS | $2500 | - |
| Security | * (all) | $5000 | can_revoke_access |

### Sensitive Actions

| System | Action | Rule |
|--------|--------|------|
| AWS | write_access | REQUIRES_APPROVAL |
| AWS | admin_access | DENY |
| Okta | create_user | REQUIRES_APPROVAL |
| Okta | delete_user | REQUIRES_APPROVAL |
| Okta | assign_admin | DENY |
| GitHub | write_access | REQUIRES_APPROVAL |
| NetSuite | write_access | REQUIRES_APPROVAL |

### System-Specific Rules

**Slack:**
- Auto-approve: #general, #random, #social, #announcements, #fde-team-updates
- Restricted: #executive-confidential, #hr-sensitive

**Jira:**
- Auto-approve: HELP, SUPPORT
- Restricted: EXEC, FIN, HR

**GitHub:**
- Auto-approve: docs, wiki, public-examples
- Restricted: prod-infrastructure, secrets-vault

**AWS:**
- Restricted: prod-db, production-rds, master-db

## Writing New Tests

### Adding a Unit Test

```python
# tests/test_policy_engine.py

def test_my_new_scenario(sample_policy, mock_metrics):
    """Test description."""
    parsed_intent = {
        "intent": "request_access",
        "action_type": "read_access",
        "system": "NewSystem",
        "resource": "resource-123",
        "justification": "reason",
        "confidence": 0.85,
        "risk_score": 0.2,
        "malicious_score": 0.0
    }
    decision, reason = evaluate_request(
        parsed_intent, "user@example.com", sample_policy, ["Engineering"], mock_metrics
    )
    assert decision == "EXPECTED_DECISION"
```

### Adding an Integration Test

```python
# tests/test_integration.py

def test_new_request_scenario(mock_parse_intent):
    """Test new request type."""
    with patch('intent_parser.parse_intent', side_effect=mock_parse_intent):
        # Load and process request
        input_path = Path(__file__).parent.parent / "input.json"
        requests = load_requests(input_path)
        results = process_requests(requests[N:N+1])  # Process Nth request

        assert results[0]["policy_decision"] == "EXPECTED"
```

## Troubleshooting

### Common Issues

**Import Errors:**
```bash
# Ensure src/ is in Python path
export PYTHONPATH="${PYTHONPATH}:$(pwd)/src"
```

**Mock Not Working:**
- Check that patch target is correct: `'intent_parser.parse_intent'` not `'src.intent_parser.parse_intent'`
- Ensure mock is applied before importing the tested module

**Tests Failing:**
- Check if policy.json matches expected structure
- Verify input.json field names (user_email, department, raw_text)
- Ensure case-insensitive matching works

## Next Steps

To achieve >80% coverage, consider adding:

1. **test_intent_parser.py**: Test LLM parsing, regex fallback, system detection
2. **test_security.py**: Test prompt injection detection, input validation
3. **test_edge_cases.py**: Test boundary conditions, invalid inputs
4. **Test fixtures**: Add more sample data in tests/fixtures/

## Quick Reference

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=term-missing

# Run specific file
pytest tests/test_policy_engine.py -v

# Run single test
pytest tests/test_policy_engine.py::TestEvaluateRequestApproved::test_approve_auto_approve_channel -v

# Generate HTML coverage report
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## Success Criteria

✅ All code updated to work with new schema
✅ 15 edge-case requests in input.json
✅ Enhanced policy.json with complete rules
✅ 60+ unit tests covering policy decisions
✅ Integration tests for end-to-end flow
✅ Pytest configuration with coverage reporting
✅ Fixtures for reusable test data
