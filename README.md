# Auto-Ops Agent

AI-powered IT operations automation system that converts natural language requests into structured intents, validates them against deterministic policy rules, and returns authorization decisions (APPROVED, DENIED, or MANUAL_REVIEW).

**Key Innovation:** Separates AI inference (intent parsing) from authorization (policy enforcement) - security decisions are never delegated to the LLM.

## 📚 Documentation

- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System design, capabilities, and data flow
- **[TESTING_GUIDE.md](TESTING_GUIDE.md)** - Test suite and coverage
- **[REVIEW.md](REVIEW.md)** - Strengths, weaknesses, and recommendations

## 🚀 Quick Start

### Prerequisites
- Python 3.10+
- OpenAI API key (set as `OPENAI_API_KEY` environment variable)

### Installation

```bash
# 1. Clone repository
git clone <repo-url>
cd auto-ops-agent

# 2. (Optional) Create virtual environment
python -m venv .venv
.venv\Scripts\activate  # Windows
source .venv/bin/activate  # Linux/Mac

# 3. Install dependencies
pip install -r requirements.txt

# 4. Set API key
export OPENAI_API_KEY='your-api-key-here'  # Linux/Mac
set OPENAI_API_KEY=your-api-key-here       # Windows
```

### Run the Agent

```bash
python src/main.py --input input.json
```

**Output:**
- JSON array of results printed to stdout
- Structured logs written to `logs/agent.log` (JSON format)
- Human-readable console output for monitoring

## Testing
Run the comprehensive test suite:
```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=src --cov-report=term-missing

# Run specific tests
pytest tests/test_policy_engine.py -v
```

See **[TESTING_GUIDE.md](TESTING_GUIDE.md)** for complete testing documentation.

## Example input
```
[
  {"id": 1, "user": "alice", "groups": ["Engineering"], "text": "Please add me to #eng-help so I can ask support questions."},
  {"id": 2, "user": "bob", "groups": ["Support"], "text": "Grant admin access to the prod database because I need to debug."}
]
```

## Example output
```
[
  {
    "request_id": 1,
    "parsed_intent": {
      "intent": "request_channel_access",
      "action_type": "read_access",
      "system": "slack",
      "resource": "#eng-help",
      "justification": "ask support questions",
      "confidence": 0.4,
      "risk_score": 0.1,
      "malicious_score": 0.0
    },
    "policy_decision": "APPROVED",
    "reason": null
  },
  {
    "request_id": 2,
    "parsed_intent": {
      "intent": "request_admin_access",
      "action_type": "admin_access",
      "system": "aws",
      "resource": "prod db",
      "justification": "I need to debug",
      "confidence": 0.4,
      "risk_score": 0.1,
      "malicious_score": 0.0
    },
    "policy_decision": "DENIED",
    "reason": "Admin access is forbidden by policy"
  }
]
```

## AI Safety
- LLM is used only for parsing and classification with sanitized policy context; no authorization decisions are delegated to the model.
- Policy engine (`evaluate_request`) is deterministic and enforces restrictions, approvals, and risk thresholds.
- Unknown systems/intents or low-confidence parses fall back to regex parsing and may be sent to manual review.

## Policy format (`policy.json`)
Non-sensitive metadata only:
```
{
  "known_systems": ["aws", "slack", "..."],
  "roles": {"Engineering": {"allowed_systems": ["aws", "github"]}},
  "sensitive_actions": {"admin_access": {"rule": "DENY"}},
  "system_specific_rules": {
    "slack": {"restricted_channels": ["#exec-private"], "auto_approve_channels": ["#eng-help"]}
  },
  "hardware_budget": {"max_per_request": 2500},
  "allowed_intents": [...],
  "resource_types": [...],
  "action_types": [...]
}
```
Only metadata is shared with the LLM; enforcement uses the full policy inside the policy engine.

## Observability
- **Logging**: Configured in [logging_utils.py](src/logging_utils.py)
  - JSON-formatted logs in `logs/agent.log` with correlation IDs
  - Human-readable console output for real-time monitoring
  - Captures timestamps, parsed intents, policy decisions, and metrics
- **Metrics**: `AgentMetrics` tracks LLM calls, token usage, latency, and security flags

## Trade-offs
- Regex fallback favors precision over recall; novel phrasing may land in manual review.
- Risk scoring is coarse; adjust thresholds in the policy engine as needed.
- Tool-based LLM parsing is defensive with a strict schema; low confidence triggers deterministic fallback.

## System Design Highlights

### 1. Architecture: Clean Separation
- **Parser** ([intent_parser.py](src/intent_parser.py)): Extracts semantic meaning using LLM
- **Policy Engine** ([policy_engine.py](src/policy_engine.py)): Makes ALL authorization decisions (deterministic)
- **Guarantee**: LLM never sees full policy rules, only metadata (system names, allowed intents)

### 2. AI Safety: Multi-Layer Defense
- **Prompt injection detection**: Bypasses LLM entirely if malicious patterns detected
- **Schema validation**: LLM output must match strict JSON schema (no `decision` field allowed)
- **Allow-list enforcement**: Intent/system/action validated against known values
- **Hard deny rule**: Admin access always denied ([policy_engine.py:89](src/policy_engine.py#L89))
- **Semantic validation**: Admin claims require supporting evidence in original text
- **Fallback parser**: Deterministic regex parser when LLM confidence < 0.3

### 3. Extensibility: Configuration-Driven
- Add new systems by editing [policy.json](policy.json) (no code changes required)
- Generic RBAC logic works for all systems automatically
- LLM context auto-updates from policy configuration
- Average time to add a new system: **5-10 minutes**

### 4. Code Quality
- **Type hints**: 100% coverage on public APIs
- **Testing**: 38 tests, 775 lines of test code (see [TESTING_GUIDE.md](TESTING_GUIDE.md))
- **Documentation**: Google-style docstrings throughout
- **Pythonic**: dataclasses, pathlib, context managers, list comprehensions

## Authentication & Limitations

### Scope of This Implementation
This prototype demonstrates **policy-based authorization** (what users can access), not **authentication** (verifying user identity). The system assumes:

- Input comes from a trusted source (e.g., authenticated API gateway, internal tool)
- User identity (`user_email`, `department`) is pre-verified before reaching this agent
- This agent makes policy decisions; it does not execute provisioning

### Production Deployment Considerations
For production use, this agent would be deployed behind:

1. **Authentication Layer**: Okta/SSO integration to verify user identity
2. **API Gateway**: HMAC signatures or API keys to authenticate request source
3. **Execution Layer**: Separate service with credentials for AWS/Slack/Jira provisioning
4. **Audit System**: Tracks who requested, who approved, and who executed each decision

### Design Rationale
Separating policy logic from authentication allows:
- Independent testing of policy rules
- Integration with any authentication system (Okta, Auth0, custom SSO)
- Clear separation of concerns: authenticate → parse → authorize → execute 
