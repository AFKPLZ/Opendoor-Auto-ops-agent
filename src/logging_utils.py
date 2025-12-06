"""Consolidated structured logging configuration for auto_ops_agent."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

# Log file path
LOG_PATH = Path(__file__).resolve().parent.parent / "logs" / "agent.log"


class JSONFormatter(logging.Formatter):
    """JSON formatter for structured logging with correlation IDs and extra fields."""

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON with structured extra data."""
        log_data = {
            "time": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "extra": getattr(record, "extra", {}),
        }
        return json.dumps(log_data)


def setup_logger(name: str = "auto_ops_agent", level: int = logging.INFO) -> logging.Logger:
    """
    Configure structured logging with both file and console output.

    - File output: JSON-formatted logs to logs/agent.log
    - Console output: Human-readable format for debugging

    Args:
        name: Logger name (default: "auto_ops_agent")
        level: Logging level (default: INFO)

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if already configured
    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    # Ensure log directory exists
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    # File handler with JSON formatting
    file_handler = logging.FileHandler(LOG_PATH, encoding="utf-8")
    file_handler.setFormatter(JSONFormatter())
    logger.addHandler(file_handler)

    # Console handler with human-readable formatting
    console_handler = logging.StreamHandler()
    console_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    return logger


# Initialize global logger instance
logger = setup_logger()
