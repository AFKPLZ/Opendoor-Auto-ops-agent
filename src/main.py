"""CLI orchestrator for auto_ops_agent with observability."""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import List

import intent_parser
from logging_utils import logger
from metrics import AgentMetrics
from models import RequestRecord
from policy import RAW_POLICY
from policy_engine import evaluate_request


def load_requests(path: Path) -> List[RequestRecord]:
    """Load requests from JSON file with updated schema."""
    with path.open("r", encoding="utf-8") as handle:
        raw_requests = json.load(handle)

    requests: List[RequestRecord] = []
    for entry in raw_requests:
        requests.append(
            RequestRecord(
                id=str(entry.get("id")),  # Handle string IDs like "req_001"
                user_email=str(entry.get("user_email", "")).strip(),
                department=str(entry.get("department", "")).strip(),
                raw_text=str(entry.get("raw_text", "")),
            )
        )
    return requests


def process_requests(requests: List[RequestRecord]) -> list[dict]:
    """Process all requests through intent parser and policy engine."""
    results = []

    for req in requests:
        metrics = AgentMetrics()
        logger.info(
            "Processing request",
            extra={"extra": {"correlation_id": metrics.correlation_id, "user_email": req.user_email, "raw_text": req.raw_text}},
        )
        parsed_intent = intent_parser.parse_intent(req.raw_text, metrics)
        # Convert single department string to list for policy evaluation
        decision, reason = evaluate_request(parsed_intent, req.user_email, RAW_POLICY, [req.department], metrics)
        metrics.finalize()
        result = {
            "request_id": req.id,
            "parsed_intent": parsed_intent,
            "policy_decision": decision,
            "reason": reason,
            "metrics": metrics.__dict__,
        }

        logger.info(
            "Final decision",
            extra={
                "extra": {
                    "correlation_id": metrics.correlation_id,
                    "intent": parsed_intent,
                    "decision": decision,
                    "reason": reason,
                    "metrics": metrics.__dict__,
                }
            },
        )

        results.append(result)

    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="auto_ops_agent CLI")
    parser.add_argument("--input", required=True, help="Path to the input JSON file")
    args = parser.parse_args()

    input_path = Path(args.input).resolve()
    start = time.time()
    requests = load_requests(input_path)
    results = process_requests(requests)
    total_latency_ms = int((time.time() - start) * 1000)
    logger.info("Completed batch", extra={"extra": {"total_latency_ms": total_latency_ms, "count": len(results)}})
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
