"""Centralized configuration management for auto_ops_agent."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class LLMConfig:
    """Configuration for LLM provider."""

    model: str = "gpt-4.1"
    temperature: float = 0.0
    max_tool_calls: int = 8
    timeout: int = 30
    max_retries: int = 3
    initial_retry_delay: float = 1.0
    max_tokens: Optional[int] = None

    @classmethod
    def from_env(cls) -> LLMConfig:
        """Load LLM configuration from environment variables."""
        return cls(
            model=os.getenv("LLM_MODEL", "gpt-4.1"),
            temperature=float(os.getenv("LLM_TEMPERATURE", "0.0")),
            max_tool_calls=int(os.getenv("MAX_TOOL_CALLS", "8")),
            timeout=int(os.getenv("LLM_TIMEOUT", "30")),
            max_retries=int(os.getenv("LLM_MAX_RETRIES", "3")),
            max_tokens=int(os.getenv("LLM_MAX_TOKENS")) if os.getenv("LLM_MAX_TOKENS") else None,
        )


@dataclass
class SecurityConfig:
    """Configuration for security parameters."""

    max_text_length: int = 2000
    max_user_length: int = 100
    risk_threshold: float = 0.7
    malicious_threshold: float = 0.5
    min_confidence: float = 0.3
    enable_prompt_injection_detection: bool = True
    enable_normalization: bool = True

    @classmethod
    def from_env(cls) -> SecurityConfig:
        """Load security configuration from environment variables."""
        return cls(
            max_text_length=int(os.getenv("MAX_TEXT_LENGTH", "2000")),
            max_user_length=int(os.getenv("MAX_USER_LENGTH", "100")),
            risk_threshold=float(os.getenv("RISK_THRESHOLD", "0.7")),
            malicious_threshold=float(os.getenv("MALICIOUS_THRESHOLD", "0.5")),
            min_confidence=float(os.getenv("MIN_CONFIDENCE", "0.3")),
            enable_prompt_injection_detection=os.getenv("ENABLE_PROMPT_INJECTION", "true").lower() == "true",
        )


@dataclass
class LoggingConfig:
    """Configuration for logging."""

    log_level: str = "INFO"
    log_path: Path = field(default_factory=lambda: Path("logs/agent.log"))
    json_format: bool = True
    console_output: bool = True

    @classmethod
    def from_env(cls) -> LoggingConfig:
        """Load logging configuration from environment variables."""
        base_dir = Path(__file__).resolve().parent.parent
        return cls(
            log_level=os.getenv("LOG_LEVEL", "INFO"),
            log_path=Path(os.getenv("LOG_PATH", base_dir / "logs" / "agent.log")),
            json_format=os.getenv("LOG_JSON_FORMAT", "true").lower() == "true",
            console_output=os.getenv("LOG_CONSOLE", "true").lower() == "true",
        )


@dataclass
class AppConfig:
    """Main application configuration."""

    policy_path: Path
    llm: LLMConfig
    security: SecurityConfig
    logging: LoggingConfig
    environment: str = "production"

    @classmethod
    def from_env(cls) -> AppConfig:
        """Load complete configuration from environment variables."""
        base_dir = Path(__file__).resolve().parent.parent

        return cls(
            policy_path=Path(os.getenv("POLICY_PATH", base_dir / "policy.json")),
            llm=LLMConfig.from_env(),
            security=SecurityConfig.from_env(),
            logging=LoggingConfig.from_env(),
            environment=os.getenv("ENVIRONMENT", "production"),
        )

    def validate(self) -> None:
        """Validate configuration values."""
        if not self.policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {self.policy_path}")

        if not 0 <= self.llm.temperature <= 2:
            raise ValueError(f"Invalid LLM temperature: {self.llm.temperature}")

        if not 0 <= self.security.min_confidence <= 1:
            raise ValueError(f"Invalid min_confidence: {self.security.min_confidence}")

        if not 0 <= self.security.risk_threshold <= 1:
            raise ValueError(f"Invalid risk_threshold: {self.security.risk_threshold}")


# Global configuration instance
config = AppConfig.from_env()
