"""Plugin architecture for system-specific resource extraction and validation."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class SystemPlugin(ABC):
    """Base class for system-specific plugins."""

    name: str
    synonyms: List[str]

    @abstractmethod
    def extract_resource(self, text: str) -> Optional[str]:
        """Extract resource identifier from text."""
        pass

    @abstractmethod
    def validate_resource(self, resource: str) -> bool:
        """Validate resource format for this system."""
        pass

    @abstractmethod
    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for a given intent on this system."""
        pass

    def matches(self, text: str) -> bool:
        """Check if text mentions this system."""
        lowered = text.lower()
        if self.name.lower() in lowered:
            return True
        return any(synonym.lower() in lowered for synonym in self.synonyms)


class SlackPlugin(SystemPlugin):
    """Plugin for Slack workspace and channel management."""

    def __init__(self):
        super().__init__(
            name="slack",
            synonyms=["workspace", "channel", "slackapp", "slack workspace"],
        )

    def extract_resource(self, text: str) -> Optional[str]:
        """Extract Slack channel from text."""
        # Try to match #channel-name format
        channel_match = re.search(r"#([a-z0-9-_]+)", text, re.IGNORECASE)
        if channel_match:
            return f"#{channel_match.group(1)}"

        # Try to match channel name without #
        channel_pattern = r"\b([a-z0-9][a-z0-9-_]{2,})\s*(?:channel|workspace)?"
        channel_noprefix = re.search(channel_pattern, text, re.IGNORECASE)
        if channel_noprefix:
            candidate = channel_noprefix.group(1)
            # Verify it's not a common word
            common_words = {"the", "and", "for", "with", "access", "please", "need"}
            if candidate.lower() not in common_words:
                return f"#{candidate}"

        return None

    def validate_resource(self, resource: str) -> bool:
        """Validate Slack channel format."""
        if not resource:
            return False

        # Should start with #
        if not resource.startswith("#"):
            return False

        # Channel name should be alphanumeric with dashes/underscores
        channel_name = resource[1:]
        if not re.match(r"^[a-z0-9][a-z0-9-_]{1,79}$", channel_name, re.IGNORECASE):
            return False

        return True

    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for Slack operations."""
        if intent == "request_channel_access":
            return "read_access"
        elif intent == "request_access":
            return "read_access"
        elif intent == "modify_permissions":
            return "write_access"
        return None


class AWSPlugin(SystemPlugin):
    """Plugin for AWS resource management."""

    def __init__(self):
        super().__init__(
            name="aws", synonyms=["amazon", "ec2", "s3", "lambda", "rds", "cloud", "vpc"]
        )

    def extract_resource(self, text: str) -> Optional[str]:
        """Extract AWS resource identifier from text."""
        # Try to match ARN format
        arn_match = re.search(r"arn:aws:[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]*:[0-9]*:[^\s]+", text)
        if arn_match:
            return arn_match.group(0)

        # Try to match database references
        db_pattern = r"\b(prod|staging|dev|test)[-_\s]?(db|database|rds)\b"
        db_match = re.search(db_pattern, text, re.IGNORECASE)
        if db_match:
            return db_match.group(0).replace(" ", "-").lower()

        # Try to match S3 bucket references
        s3_match = re.search(r"\bs3://([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])", text, re.IGNORECASE)
        if s3_match:
            return s3_match.group(0)

        # Generic AWS resource references
        aws_resource_match = re.search(
            r"\b(prod|staging|dev)[-_]?(vpc|stack|cluster|instance)\b", text, re.IGNORECASE
        )
        if aws_resource_match:
            return aws_resource_match.group(0).replace(" ", "-").lower()

        return None

    def validate_resource(self, resource: str) -> bool:
        """Validate AWS resource identifier."""
        if not resource:
            return False

        # Validate ARN format
        if resource.startswith("arn:"):
            arn_pattern = r"^arn:aws:[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]*:[0-9]*:.+$"
            return bool(re.match(arn_pattern, resource))

        # Validate S3 bucket format
        if resource.startswith("s3://"):
            bucket_pattern = r"^s3://[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]"
            return bool(re.match(bucket_pattern, resource, re.IGNORECASE))

        # Validate general resource name
        if re.search(r"\b(db|database|vpc|stack|cluster|instance)\b", resource, re.IGNORECASE):
            return True

        return False

    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for AWS operations."""
        if intent == "request_admin_access":
            return "admin_access"
        elif intent == "request_access":
            return "read_access"
        elif intent == "modify_permissions":
            return "write_access"
        return None


class JiraPlugin(SystemPlugin):
    """Plugin for Jira project and issue management."""

    def __init__(self):
        super().__init__(name="jira", synonyms=["ticket", "issue", "story", "jira ticket"])

    def extract_resource(self, text: str) -> Optional[str]:
        """Extract Jira project or issue key from text."""
        # Try to match Jira issue key format (e.g., PROJ-123)
        issue_match = re.search(r"\b([A-Z]{2,10}-\d+)\b", text)
        if issue_match:
            return issue_match.group(1)

        # Try to match project name
        project_match = re.search(r"\b([A-Z]{2,10})\s+project\b", text, re.IGNORECASE)
        if project_match:
            return project_match.group(1).upper()

        return None

    def validate_resource(self, resource: str) -> bool:
        """Validate Jira resource format."""
        if not resource:
            return False

        # Validate issue key format (PROJ-123)
        issue_pattern = r"^[A-Z]{2,10}-\d+$"
        if re.match(issue_pattern, resource):
            return True

        # Validate project key format (2-10 uppercase letters)
        project_pattern = r"^[A-Z]{2,10}$"
        if re.match(project_pattern, resource):
            return True

        return False

    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for Jira operations."""
        if intent == "request_access":
            return "read_access"
        elif intent == "modify_permissions":
            return "write_access"
        return None


class GitHubPlugin(SystemPlugin):
    """Plugin for GitHub repository management."""

    def __init__(self):
        super().__init__(name="github", synonyms=["repo", "repository", "pull request", "pr", "gh"])

    def extract_resource(self, text: str) -> Optional[str]:
        """Extract GitHub repository or PR reference from text."""
        # Try to match org/repo format
        repo_match = re.search(r"\b([a-zA-Z0-9_-]+)/([a-zA-Z0-9_.-]+)\b", text)
        if repo_match:
            return repo_match.group(0)

        # Try to match PR number
        pr_match = re.search(r"\bPR\s*#?(\d+)\b", text, re.IGNORECASE)
        if pr_match:
            return f"PR#{pr_match.group(1)}"

        return None

    def validate_resource(self, resource: str) -> bool:
        """Validate GitHub resource format."""
        if not resource:
            return False

        # Validate org/repo format
        repo_pattern = r"^[a-zA-Z0-9_-]+/[a-zA-Z0-9_.-]+$"
        if re.match(repo_pattern, resource):
            return True

        # Validate PR reference
        pr_pattern = r"^PR#\d+$"
        if re.match(pr_pattern, resource, re.IGNORECASE):
            return True

        return False

    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for GitHub operations."""
        if intent == "request_access":
            return "read_access"
        elif intent == "modify_permissions":
            return "write_access"
        return None


class GSuitePlugin(SystemPlugin):
    """Plugin for Google Workspace (GSuite) management."""

    def __init__(self):
        super().__init__(
            name="gsuite", synonyms=["gmail", "gdrive", "google workspace", "google", "google drive"]
        )

    def extract_resource(self, text: str) -> Optional[str]:
        """Extract GSuite resource (email, drive folder, etc.)."""
        # Try to match email address
        email_match = re.search(r"[\w.+-]+@[\w-]+\.[\w.-]+", text)
        if email_match:
            return email_match.group(0)

        # Try to match Google Drive folder/file reference
        drive_match = re.search(r"drive\s+folder\s+([^\s]+)", text, re.IGNORECASE)
        if drive_match:
            return f"drive:{drive_match.group(1)}"

        return None

    def validate_resource(self, resource: str) -> bool:
        """Validate GSuite resource format."""
        if not resource:
            return False

        # Validate email format
        email_pattern = r"^[\w.+-]+@[\w-]+\.[\w.-]+$"
        if re.match(email_pattern, resource):
            return True

        # Validate drive resource
        if resource.startswith("drive:"):
            return True

        return False

    def get_default_action_type(self, intent: str) -> Optional[str]:
        """Get default action type for GSuite operations."""
        if intent == "request_access":
            return "read_access"
        return None


# Plugin registry
SYSTEM_PLUGINS: Dict[str, SystemPlugin] = {
    "slack": SlackPlugin(),
    "aws": AWSPlugin(),
    "jira": JiraPlugin(),
    "github": GitHubPlugin(),
    "gsuite": GSuitePlugin(),
}


def register_plugin(plugin: SystemPlugin) -> None:
    """Register a new system plugin."""
    SYSTEM_PLUGINS[plugin.name.lower()] = plugin


def get_plugin(system: str) -> Optional[SystemPlugin]:
    """Get plugin for a system."""
    return SYSTEM_PLUGINS.get(system.lower())


def detect_system_from_text(text: str) -> Optional[str]:
    """Detect which system is mentioned in text using plugins."""
    for plugin in SYSTEM_PLUGINS.values():
        if plugin.matches(text):
            return plugin.name
    return None


def extract_resource_with_plugin(system: str, text: str) -> Optional[str]:
    """Extract resource using system-specific plugin."""
    plugin = get_plugin(system)
    if plugin:
        return plugin.extract_resource(text)
    return None


def validate_resource_with_plugin(system: str, resource: str) -> bool:
    """Validate resource using system-specific plugin."""
    plugin = get_plugin(system)
    if plugin:
        return plugin.validate_resource(resource)
    return False
