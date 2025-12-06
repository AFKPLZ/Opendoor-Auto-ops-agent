"""Health check utilities for monitoring system status."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

from logging_utils import logger


@dataclass
class HealthCheck:
    """Individual health check result."""

    name: str
    healthy: bool
    message: str
    latency_ms: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    """Overall health status of the system."""

    healthy: bool
    checks: Dict[str, HealthCheck]
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "healthy": self.healthy,
            "timestamp": self.timestamp,
            "checks": {
                name: {
                    "healthy": check.healthy,
                    "message": check.message,
                    "latency_ms": check.latency_ms,
                    "metadata": check.metadata,
                }
                for name, check in self.checks.items()
            },
        }


def check_policy_file() -> HealthCheck:
    """Check if policy file is readable and valid."""
    start = time.time()

    try:
        from policy_engine import POLICY_PATH, load_policy

        if not POLICY_PATH.exists():
            return HealthCheck(
                name="policy_file",
                healthy=False,
                message=f"Policy file not found: {POLICY_PATH}",
                latency_ms=int((time.time() - start) * 1000),
            )

        policy = load_policy()

        # Basic validation
        required_keys = ["known_systems", "roles", "sensitive_actions"]
        missing_keys = [key for key in required_keys if key not in policy]

        if missing_keys:
            return HealthCheck(
                name="policy_file",
                healthy=False,
                message=f"Policy missing required keys: {missing_keys}",
                latency_ms=int((time.time() - start) * 1000),
            )

        return HealthCheck(
            name="policy_file",
            healthy=True,
            message="Policy file loaded successfully",
            latency_ms=int((time.time() - start) * 1000),
            metadata={
                "known_systems_count": len(policy.get("known_systems", [])),
                "roles_count": len(policy.get("roles", {})),
            },
        )

    except Exception as e:
        return HealthCheck(
            name="policy_file",
            healthy=False,
            message=f"Error loading policy: {str(e)}",
            latency_ms=int((time.time() - start) * 1000),
        )


def check_llm_connection() -> HealthCheck:
    """Check if LLM API is reachable with a minimal test call."""
    start = time.time()

    try:
        import openai

        # Minimal test call
        response = openai.chat.completions.create(
            model="gpt-4.1", messages=[{"role": "user", "content": "ping"}], max_tokens=1, temperature=0
        )

        if not response or not response.choices:
            return HealthCheck(
                name="llm_connection",
                healthy=False,
                message="LLM API returned invalid response",
                latency_ms=int((time.time() - start) * 1000),
            )

        return HealthCheck(
            name="llm_connection",
            healthy=True,
            message="LLM API is reachable",
            latency_ms=int((time.time() - start) * 1000),
            metadata={"model": "gpt-4.1"},
        )

    except Exception as e:
        error_msg = str(e)
        return HealthCheck(
            name="llm_connection",
            healthy=False,
            message=f"LLM API error: {error_msg[:100]}",
            latency_ms=int((time.time() - start) * 1000),
        )


def check_logging() -> HealthCheck:
    """Check if logging system is functional."""
    start = time.time()

    try:
        # Try to write a test log entry
        logger.info("Health check test log", extra={"extra": {"test": True}})

        return HealthCheck(
            name="logging",
            healthy=True,
            message="Logging system is functional",
            latency_ms=int((time.time() - start) * 1000),
        )

    except Exception as e:
        return HealthCheck(
            name="logging",
            healthy=False,
            message=f"Logging error: {str(e)}",
            latency_ms=int((time.time() - start) * 1000),
        )


def check_disk_space() -> HealthCheck:
    """Check if there's sufficient disk space for logs."""
    start = time.time()

    try:
        import shutil

        from logger import LOG_PATH

        # Check available disk space
        stat = shutil.disk_usage(LOG_PATH.parent)
        free_gb = stat.free / (1024**3)
        total_gb = stat.total / (1024**3)
        percent_free = (stat.free / stat.total) * 100

        # Warn if less than 1GB or less than 10% free
        if free_gb < 1.0 or percent_free < 10:
            return HealthCheck(
                name="disk_space",
                healthy=False,
                message=f"Low disk space: {free_gb:.2f}GB free ({percent_free:.1f}%)",
                latency_ms=int((time.time() - start) * 1000),
                metadata={"free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)},
            )

        return HealthCheck(
            name="disk_space",
            healthy=True,
            message=f"Sufficient disk space: {free_gb:.2f}GB free",
            latency_ms=int((time.time() - start) * 1000),
            metadata={"free_gb": round(free_gb, 2), "total_gb": round(total_gb, 2)},
        )

    except Exception as e:
        return HealthCheck(
            name="disk_space",
            healthy=False,
            message=f"Disk space check error: {str(e)}",
            latency_ms=int((time.time() - start) * 1000),
        )


def get_health_status(include_llm_check: bool = False) -> HealthStatus:
    """
    Get overall system health status.

    Args:
        include_llm_check: Whether to include LLM connectivity check (slower)

    Returns:
        HealthStatus with all check results
    """
    checks: Dict[str, HealthCheck] = {}

    # Always run these checks
    checks["policy_file"] = check_policy_file()
    checks["logging"] = check_logging()
    checks["disk_space"] = check_disk_space()

    # Optionally check LLM (slower and may cost money)
    if include_llm_check:
        checks["llm_connection"] = check_llm_connection()

    # Overall health is True only if all checks pass
    overall_healthy = all(check.healthy for check in checks.values())

    return HealthStatus(healthy=overall_healthy, checks=checks)


def health_check_cli() -> int:
    """
    CLI command for health checks.

    Returns:
        0 if healthy, 1 if unhealthy
    """
    import json
    import sys

    # Check if --full flag is provided
    include_llm = "--full" in sys.argv or "-f" in sys.argv

    status = get_health_status(include_llm_check=include_llm)

    # Print JSON output
    print(json.dumps(status.to_dict(), indent=2))

    # Return appropriate exit code
    return 0 if status.healthy else 1


if __name__ == "__main__":
    exit(health_check_cli())
