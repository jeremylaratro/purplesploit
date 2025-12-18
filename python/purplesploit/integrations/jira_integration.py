"""
Jira Integration for PurpleSploit

Creates and manages security findings as Jira issues.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging
import base64

from .base import (
    BaseIntegration,
    IntegrationConfig,
    IntegrationStatus,
    NotificationPayload,
    NotificationPriority,
)

logger = logging.getLogger(__name__)

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class JiraConfig(IntegrationConfig):
    """Jira-specific configuration."""
    server_url: str = ""
    username: str = ""
    project_key: str = ""
    issue_type: str = "Bug"
    priority_mapping: Dict[str, str] = field(default_factory=lambda: {
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest",
    })
    custom_fields: Dict[str, str] = field(default_factory=dict)
    labels: List[str] = field(default_factory=lambda: ["security", "purplesploit"])
    assignee: Optional[str] = None


class JiraIntegration(BaseIntegration):
    """
    Jira integration for security finding management.

    Supports:
    - Issue creation from findings
    - Issue updates and transitions
    - Attachment upload (evidence)
    - Custom field mapping
    - Label and component assignment
    - Duplicate detection
    """

    def __init__(self, config: Optional[JiraConfig] = None):
        if config is None:
            config = JiraConfig(name="jira")
        super().__init__(config)
        self.jira_config: JiraConfig = config
        self._issue_cache: Dict[str, str] = {}  # finding_id -> issue_key

    @property
    def _auth_header(self) -> Dict[str, str]:
        """Get authentication header."""
        if self.jira_config.api_key:
            # API token auth (Cloud)
            credentials = f"{self.jira_config.username}:{self.jira_config.api_key}"
            encoded = base64.b64encode(credentials.encode()).decode()
            return {"Authorization": f"Basic {encoded}"}
        return {}

    @property
    def _base_url(self) -> str:
        """Get base API URL."""
        url = self.jira_config.server_url.rstrip("/")
        return f"{url}/rest/api/2"

    def connect(self) -> bool:
        """Verify Jira connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not all([
            self.jira_config.server_url,
            self.jira_config.username,
            self.jira_config.api_key,
        ]):
            self._error_message = "Missing server_url, username, or api_key"
            self.status = IntegrationStatus.ERROR
            return False

        result = self.test_connection()
        if result.get("success"):
            self.status = IntegrationStatus.CONNECTED
            return True
        return False

    def disconnect(self) -> bool:
        """Disconnect from Jira."""
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        """Test Jira connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            response = requests.get(
                f"{self._base_url}/myself",
                headers=self._auth_header,
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "user": data.get("displayName"),
                    "email": data.get("emailAddress"),
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Create or update a Jira issue from notification."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            # Check for existing issue
            if payload.finding_id and payload.finding_id in self._issue_cache:
                result = self._update_issue(
                    self._issue_cache[payload.finding_id],
                    payload,
                )
            else:
                result = self._create_issue(payload)

            self._record_request()
            return result

        except Exception as e:
            return self._handle_error(e)

    def _create_issue(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Create a new Jira issue."""
        # Build issue fields
        fields = {
            "project": {"key": self.jira_config.project_key},
            "summary": payload.title,
            "description": self._build_description(payload),
            "issuetype": {"name": self.jira_config.issue_type},
            "labels": self.jira_config.labels + payload.tags,
        }

        # Map priority
        if payload.severity:
            jira_priority = self.jira_config.priority_mapping.get(
                payload.severity.lower(),
                "Medium",
            )
            fields["priority"] = {"name": jira_priority}

        # Add assignee if configured
        if self.jira_config.assignee:
            fields["assignee"] = {"name": self.jira_config.assignee}

        # Add custom fields
        for field_id, field_value in self.jira_config.custom_fields.items():
            fields[field_id] = field_value

        response = requests.post(
            f"{self._base_url}/issue",
            headers={
                **self._auth_header,
                "Content-Type": "application/json",
            },
            json={"fields": fields},
            timeout=self.config.timeout,
        )

        if response.status_code in (200, 201):
            data = response.json()
            issue_key = data.get("key")

            # Cache the issue for updates
            if payload.finding_id:
                self._issue_cache[payload.finding_id] = issue_key

            return {
                "success": True,
                "issue_key": issue_key,
                "issue_url": f"{self.jira_config.server_url}/browse/{issue_key}",
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
            }

    def _update_issue(
        self,
        issue_key: str,
        payload: NotificationPayload,
    ) -> Dict[str, Any]:
        """Update an existing Jira issue."""
        # Add a comment with the update
        comment = f"*Update from PurpleSploit*\n\n{payload.message}"

        response = requests.post(
            f"{self._base_url}/issue/{issue_key}/comment",
            headers={
                **self._auth_header,
                "Content-Type": "application/json",
            },
            json={"body": comment},
            timeout=self.config.timeout,
        )

        if response.status_code in (200, 201):
            return {
                "success": True,
                "issue_key": issue_key,
                "action": "updated",
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
            }

    def _build_description(self, payload: NotificationPayload) -> str:
        """Build Jira-formatted description."""
        description = f"{payload.message}\n\n"
        description += "h3. Details\n"
        description += "||Field||Value||\n"

        if payload.target:
            description += f"|Target|{payload.target}|\n"
        if payload.severity:
            description += f"|Severity|{payload.severity.upper()}|\n"
        if payload.cvss_score is not None:
            description += f"|CVSS Score|{payload.cvss_score}|\n"
        if payload.finding_id:
            description += f"|Finding ID|{payload.finding_id}|\n"

        description += f"|Source|{payload.source}|\n"
        description += f"|Timestamp|{payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}|\n"

        if payload.extra_data:
            description += "\nh3. Additional Data\n"
            description += "{code:json}\n"
            description += json.dumps(payload.extra_data, indent=2)
            description += "\n{code}\n"

        return description

    def create_finding_issue(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        remediation: Optional[str] = None,
        evidence: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a Jira issue from a security finding.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            target: Affected target
            finding_id: Optional finding ID
            cvss_score: Optional CVSS score
            remediation: Optional remediation guidance
            evidence: Optional list of evidence file paths
            tags: Optional tags/labels

        Returns:
            Result dict with issue_key and URL
        """
        # Build enhanced description
        full_description = description
        if remediation:
            full_description += f"\n\nh3. Remediation\n{remediation}"

        payload = NotificationPayload(
            title=title,
            message=full_description,
            priority=NotificationPriority.HIGH,
            severity=severity,
            target=target,
            finding_id=finding_id,
            cvss_score=cvss_score,
            tags=tags or [],
        )

        result = self.send_notification(payload)

        # Attach evidence files if provided and issue was created
        if result.get("success") and evidence:
            issue_key = result.get("issue_key")
            for evidence_path in evidence:
                self.attach_file(issue_key, evidence_path)

        return result

    def attach_file(self, issue_key: str, file_path: str) -> Dict[str, Any]:
        """
        Attach a file to a Jira issue.

        Args:
            issue_key: Jira issue key (e.g., PROJ-123)
            file_path: Path to file to attach

        Returns:
            Result dict with attachment info
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            with open(file_path, "rb") as f:
                response = requests.post(
                    f"{self._base_url}/issue/{issue_key}/attachments",
                    headers={
                        **self._auth_header,
                        "X-Atlassian-Token": "no-check",
                    },
                    files={"file": f},
                    timeout=self.config.timeout * 2,  # Longer timeout for uploads
                )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "attachments": [a.get("filename") for a in data],
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def transition_issue(
        self,
        issue_key: str,
        transition_name: str,
    ) -> Dict[str, Any]:
        """
        Transition a Jira issue to a new status.

        Args:
            issue_key: Jira issue key
            transition_name: Name of the transition (e.g., "Done", "In Progress")

        Returns:
            Result dict with success status
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Get available transitions
            response = requests.get(
                f"{self._base_url}/issue/{issue_key}/transitions",
                headers=self._auth_header,
                timeout=self.config.timeout,
            )

            if response.status_code != 200:
                return {
                    "success": False,
                    "error": f"Failed to get transitions: {response.text}",
                }

            transitions = response.json().get("transitions", [])
            transition_id = None
            for t in transitions:
                if t.get("name", "").lower() == transition_name.lower():
                    transition_id = t.get("id")
                    break

            if not transition_id:
                return {
                    "success": False,
                    "error": f"Transition '{transition_name}' not found",
                    "available": [t.get("name") for t in transitions],
                }

            # Perform transition
            response = requests.post(
                f"{self._base_url}/issue/{issue_key}/transitions",
                headers={
                    **self._auth_header,
                    "Content-Type": "application/json",
                },
                json={"transition": {"id": transition_id}},
                timeout=self.config.timeout,
            )

            if response.status_code == 204:
                return {"success": True, "transition": transition_name}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def search_issues(
        self,
        jql: Optional[str] = None,
        finding_id: Optional[str] = None,
        target: Optional[str] = None,
        max_results: int = 50,
    ) -> Dict[str, Any]:
        """
        Search for existing issues.

        Args:
            jql: Custom JQL query
            finding_id: Search by finding ID in description
            target: Search by target in description
            max_results: Maximum results to return

        Returns:
            Result dict with matching issues
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            if not jql:
                # Build JQL from parameters
                conditions = [f'project = "{self.jira_config.project_key}"']
                if finding_id:
                    conditions.append(f'description ~ "{finding_id}"')
                if target:
                    conditions.append(f'description ~ "{target}"')
                jql = " AND ".join(conditions)

            response = requests.get(
                f"{self._base_url}/search",
                headers=self._auth_header,
                params={
                    "jql": jql,
                    "maxResults": max_results,
                    "fields": "key,summary,status,priority,created",
                },
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                issues = []
                for issue in data.get("issues", []):
                    fields = issue.get("fields", {})
                    issues.append({
                        "key": issue.get("key"),
                        "summary": fields.get("summary"),
                        "status": fields.get("status", {}).get("name"),
                        "priority": fields.get("priority", {}).get("name"),
                        "created": fields.get("created"),
                    })
                return {
                    "success": True,
                    "total": data.get("total", 0),
                    "issues": issues,
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)
