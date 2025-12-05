# auto_ops_agent

CLI that converts raw IT-style requests into structured intents, validates them against deterministic policy rules, and reports a policy decision.

## Install
1. Python 3.10+
2. Optional: `python -m venv .venv && .venv\Scripts\activate`
3. Install deps:
   ```
   pip install -r requirements.txt
   ```

## Run
```
python src/main.py --input input.json
```
Outputs a JSON array of results and logs details to `logs/agent.log`.

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
- Logs timestamp, parsed intent, policy decision, and output to `logs/agent.log`.

## Trade-offs
- Regex fallback favors precision over recall; novel phrasing may land in manual review.
- Risk scoring is coarse; adjust thresholds in the policy engine as needed.
- Tool-based LLM parsing is defensive with a strict schema; low confidence triggers deterministic fallback. 
