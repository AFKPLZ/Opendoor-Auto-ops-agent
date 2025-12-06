"""Enhanced security utilities with improved prompt injection detection."""
from __future__ import annotations

import base64
import re
import unicodedata
from typing import List


def normalize_text(text: str) -> str:
    """
    Normalize text to detect obfuscated attacks.

    Handles:
    - Unicode homoglyphs (e.g., Cyrillic characters)
    - Leetspeak substitutions
    - Multiple whitespace normalization
    """
    # Convert to NFKD normalization form and remove non-ASCII
    normalized = unicodedata.normalize("NFKD", text)
    ascii_text = normalized.encode("ASCII", "ignore").decode("ASCII")

    # Convert to lowercase for case-insensitive matching
    lowered = ascii_text.lower()

    # Remove leetspeak substitutions
    leetspeak_map = {
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "@": "a",
        "$": "s",
    }
    for num, letter in leetspeak_map.items():
        lowered = lowered.replace(num, letter)

    # Normalize whitespace
    lowered = re.sub(r"\s+", " ", lowered)

    return lowered


def detect_encoded_injection(text: str) -> bool:
    """
    Detect prompt injection attempts in encoded content.

    Checks for:
    - Base64 encoded payloads
    - URL encoded payloads
    - Hex encoded payloads
    """
    # Check for base64-like patterns
    base64_pattern = r"[A-Za-z0-9+/]{20,}={0,2}"
    matches = re.findall(base64_pattern, text)

    for match in matches:
        try:
            decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
            if detect_prompt_injection(decoded):
                return True
        except Exception:
            # Not valid base64 or not decodable
            continue

    # Check for URL encoding patterns like %69%67%6e%6f%72%65 (ignore)
    url_encoded_pattern = r"(?:%[0-9a-fA-F]{2})+"
    url_matches = re.findall(url_encoded_pattern, text)

    for match in url_matches:
        try:
            from urllib.parse import unquote

            decoded = unquote(match)
            if detect_prompt_injection(decoded):
                return True
        except Exception:
            continue

    return False


def detect_prompt_injection(text: str) -> bool:
    """
    Enhanced prompt injection detection.

    Uses multiple strategies:
    1. Direct keyword matching
    2. Regex pattern matching
    3. Normalized text matching
    4. Encoded payload detection
    """
    # First check: Direct keyword matching
    suspicious_keywords: List[str] = [
        "ignore previous",
        "disregard system",
        "override",
        "as assistant",
        "return this json",
        "tool_call",
        "function_call",
        "i command you",
        "act as",
        "follow my instructions",
        "disregard instructions",
        "pretend you are",
        "break character",
        "forget everything",
        "new instructions",
        "bypass",
        "jailbreak",
    ]

    lowered = text.lower()
    for keyword in suspicious_keywords:
        if keyword in lowered:
            return True

    # Second check: Regex patterns
    suspicious_patterns: List[str] = [
        r"ignore\s+previous",
        r"disregard\s+(all|system|instructions)",
        r"override\s+(rules|instructions|system)",
        r"you\s+are\s+now",
        r"act\s+as\s+(a\s+)?(?!human)",  # "act as" followed by non-human role
        r"pretend\s+(you|to)\s+are",
        r"return\s+this\s+json",
        r"tool_?call",
        r"function_?call",
        r"system\s*:",  # System prompt injection
        r"assistant\s*:",  # Assistant role injection
    ]

    for pattern in suspicious_patterns:
        if re.search(pattern, lowered, re.IGNORECASE):
            return True

    # Third check: Normalized text (catches obfuscation)
    normalized = normalize_text(text)
    for keyword in suspicious_keywords:
        if keyword in normalized:
            return True

    # Fourth check: Encoded payloads
    if detect_encoded_injection(text):
        return True

    return False


def validate_justification(justification: str | None) -> bool:
    """
    Validate that justification field doesn't contain injection attempts.

    Returns True if justification is safe, False otherwise.
    """
    if not justification:
        return True

    # Check for code-like patterns that shouldn't be in justification
    code_patterns: List[str] = [
        r"\{[^}]*:[^}]*\}",  # JSON-like patterns
        r"<[^>]+>.*</[^>]+>",  # XML/HTML tags
        r"function\s*\(",  # JavaScript function calls
        r"import\s+\w+",  # Python imports
        r"SELECT\s+.*\s+FROM",  # SQL queries
        r"eval\s*\(",  # Eval calls
        r"exec\s*\(",  # Exec calls
        r"__.*__",  # Python dunder methods
    ]

    for pattern in code_patterns:
        if re.search(pattern, justification, re.IGNORECASE):
            return False

    # Check for prompt injection in justification
    if detect_prompt_injection(justification):
        return False

    return True


def validate_user_input(user: str, groups: List[str], text: str) -> tuple[bool, str | None]:
    """
    Comprehensive validation of user input.

    Returns: (is_valid, error_message)
    """
    # Validate user field
    if not user or not isinstance(user, str):
        return False, "User field is required and must be a string"

    if len(user) > 100:
        return False, "User field exceeds maximum length (100 characters)"

    # Validate email format if user looks like an email
    if "@" in user:
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, user):
            return False, "Invalid email format"

    # Validate groups
    if not isinstance(groups, list):
        return False, "Groups must be a list"

    for group in groups:
        if not isinstance(group, str):
            return False, "All groups must be strings"
        if len(group) > 50:
            return False, f"Group name too long: {group}"

    # Validate text
    if not text or not isinstance(text, str):
        return False, "Text field is required and must be a string"

    if not text.strip():
        return False, "Text field cannot be empty or whitespace only"

    if len(text) > 2000:
        return False, "Text exceeds maximum length (2000 characters)"

    # Check for suspicious content in text
    if detect_prompt_injection(text):
        return False, "Suspicious content detected in text (possible prompt injection)"

    return True, None


def sanitize_resource_identifier(resource: str | None) -> str | None:
    """
    Sanitize resource identifier to prevent injection attacks.

    Returns sanitized resource or None if resource is invalid.
    """
    if not resource:
        return None

    # Remove leading/trailing whitespace
    resource = resource.strip()

    # Check length
    if len(resource) > 500:
        return None

    # Remove potentially dangerous characters
    # Allow: alphanumeric, dash, underscore, slash, colon, hash, @, dot
    allowed_pattern = r"^[a-zA-Z0-9\-_/:@#.]+$"
    if not re.match(allowed_pattern, resource):
        # If it contains disallowed characters, try to clean it
        resource = re.sub(r"[^a-zA-Z0-9\-_/:@#.]", "", resource)

    # Additional validation for specific resource types
    # ARN format: arn:aws:service:region:account:resource
    if resource.startswith("arn:"):
        arn_pattern = r"^arn:[a-z0-9\-]+:[a-z0-9\-]+:[a-z0-9\-]*:[0-9]*:.*$"
        if not re.match(arn_pattern, resource, re.IGNORECASE):
            return None

    # Email format
    if "@" in resource:
        email_pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        if not re.match(email_pattern, resource):
            return None

    return resource


def calculate_risk_score(text: str, parsed_intent: dict) -> float:
    """
    Calculate risk score based on request content and intent.

    Returns: Risk score between 0.0 and 1.0
    """
    risk_score = 0.0

    # Check for high-risk keywords in text
    high_risk_keywords = [
        "bypass",
        "exfiltrate",
        "steal",
        "dump",
        "backdoor",
        "breach",
        "exploit",
        "vulnerability",
        "inject",
        "attack",
    ]

    lowered = text.lower()
    for keyword in high_risk_keywords:
        if keyword in lowered:
            risk_score += 0.2

    # Admin-related requests are inherently risky
    if parsed_intent.get("intent") == "request_admin_access" or parsed_intent.get("action_type") == "admin_access":
        risk_score += 0.3

    # Write access is riskier than read
    if parsed_intent.get("action_type") == "write_access":
        risk_score += 0.2

    # Production resources are higher risk
    resource = str(parsed_intent.get("resource", "")).lower()
    if any(prod in resource for prod in ["prod", "production", "master", "main"]):
        risk_score += 0.1

    # Lack of justification is suspicious
    if not parsed_intent.get("justification"):
        risk_score += 0.1

    # Cap at 1.0
    return min(risk_score, 1.0)
