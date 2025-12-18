"""
GitHub Issues Integration for PurpleSploit

Creates and manages security findings as GitHub Issues.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging

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
class GitHubConfig(IntegrationConfig):
    """GitHub-specific configuration."""
    owner: str = ""
    repo: str = ""
    default_labels: List[str] = field(default_factory=lambda: ["security", "vulnerability"])
    assignees: List[str] = field(default_factory=list)
    severity_labels: Dict[str, str] = field(default_factory=lambda: {
        "critical": "severity:critical",
        "high": "severity:high",
        "medium": "severity:medium",
        "low": "severity:low",
        "info": "severity:info",
    })


class GitHubIssuesIntegration(BaseIntegration):
    """
    GitHub Issues integration for security finding management.

    Supports:
    - Issue creation from findings
    - Issue comments for updates
    - Label-based severity classification
    - Milestone assignment
    - Assignee management
    - Duplicate detection via search
    """

    API_BASE = "https://api.github.com"

    def __init__(self, config: Optional[GitHubConfig] = None):
        if config is None:
            config = GitHubConfig(name="github")
        super().__init__(config)
        self.github_config: GitHubConfig = config
        self._issue_cache: Dict[str, int] = {}  # finding_id -> issue_number

    @property
    def _auth_header(self) -> Dict[str, str]:
        """Get authentication header."""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.github_config.api_key:
            headers["Authorization"] = f"Bearer {self.github_config.api_key}"
        return headers

    @property
    def _repo_url(self) -> str:
        """Get repository API URL."""
        return f"{self.API_BASE}/repos/{self.github_config.owner}/{self.github_config.repo}"

    def connect(self) -> bool:
        """Verify GitHub connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not all([
            self.github_config.owner,
            self.github_config.repo,
            self.github_config.api_key,
        ]):
            self._error_message = "Missing owner, repo, or api_key"
            self.status = IntegrationStatus.ERROR
            return False

        result = self.test_connection()
        if result.get("success"):
            self.status = IntegrationStatus.CONNECTED
            return True
        return False

    def disconnect(self) -> bool:
        """Disconnect from GitHub."""
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        """Test GitHub connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            response = requests.get(
                self._repo_url,
                headers=self._auth_header,
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                return {
                    "success": True,
                    "repo": data.get("full_name"),
                    "private": data.get("private"),
                    "permissions": data.get("permissions"),
                }
            elif response.status_code == 404:
                return {"success": False, "error": "Repository not found"}
            elif response.status_code == 401:
                return {"success": False, "error": "Invalid or missing token"}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Create or update a GitHub issue from notification."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            # Check for existing issue
            if payload.finding_id and payload.finding_id in self._issue_cache:
                result = self._add_comment(
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
        """Create a new GitHub issue."""
        # Build labels
        labels = list(self.github_config.default_labels)
        if payload.severity:
            severity_label = self.github_config.severity_labels.get(
                payload.severity.lower()
            )
            if severity_label:
                labels.append(severity_label)
        labels.extend(payload.tags)

        # Build issue body
        body = self._build_issue_body(payload)

        issue_data = {
            "title": payload.title,
            "body": body,
            "labels": labels,
        }

        if self.github_config.assignees:
            issue_data["assignees"] = self.github_config.assignees

        response = requests.post(
            f"{self._repo_url}/issues",
            headers=self._auth_header,
            json=issue_data,
            timeout=self.config.timeout,
        )

        if response.status_code == 201:
            data = response.json()
            issue_number = data.get("number")

            # Cache for updates
            if payload.finding_id:
                self._issue_cache[payload.finding_id] = issue_number

            return {
                "success": True,
                "issue_number": issue_number,
                "issue_url": data.get("html_url"),
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
            }

    def _add_comment(
        self,
        issue_number: int,
        payload: NotificationPayload,
    ) -> Dict[str, Any]:
        """Add a comment to an existing issue."""
        comment_body = f"**Update from PurpleSploit**\n\n{payload.message}"
        comment_body += f"\n\n_Timestamp: {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}_"

        response = requests.post(
            f"{self._repo_url}/issues/{issue_number}/comments",
            headers=self._auth_header,
            json={"body": comment_body},
            timeout=self.config.timeout,
        )

        if response.status_code == 201:
            return {
                "success": True,
                "issue_number": issue_number,
                "action": "commented",
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
            }

    def _build_issue_body(self, payload: NotificationPayload) -> str:
        """Build GitHub-formatted issue body."""
        body = f"{payload.message}\n\n"
        body += "## Details\n\n"
        body += "| Field | Value |\n"
        body += "|-------|-------|\n"

        if payload.target:
            body += f"| Target | `{payload.target}` |\n"
        if payload.severity:
            severity_emoji = {
                "critical": ":red_circle:",
                "high": ":orange_circle:",
                "medium": ":yellow_circle:",
                "low": ":green_circle:",
                "info": ":blue_circle:",
            }.get(payload.severity.lower(), "")
            body += f"| Severity | {severity_emoji} {payload.severity.upper()} |\n"
        if payload.cvss_score is not None:
            body += f"| CVSS Score | {payload.cvss_score} |\n"
        if payload.finding_id:
            body += f"| Finding ID | {payload.finding_id} |\n"

        body += f"| Source | {payload.source} |\n"
        body += f"| Timestamp | {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')} |\n"

        if payload.extra_data:
            body += "\n## Additional Data\n\n"
            body += "```json\n"
            body += json.dumps(payload.extra_data, indent=2)
            body += "\n```\n"

        body += "\n---\n_Created by PurpleSploit_"

        return body

    def create_finding_issue(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        remediation: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Create a GitHub issue from a security finding.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            target: Affected target
            finding_id: Optional finding ID
            cvss_score: Optional CVSS score
            remediation: Optional remediation guidance
            tags: Optional labels

        Returns:
            Result dict with issue_number and URL
        """
        full_description = description
        if remediation:
            full_description += f"\n\n## Remediation\n\n{remediation}"

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

        return self.send_notification(payload)

    def close_issue(
        self,
        issue_number: int,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Close a GitHub issue.

        Args:
            issue_number: Issue number to close
            comment: Optional closing comment

        Returns:
            Result dict with success status
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Add closing comment if provided
            if comment:
                requests.post(
                    f"{self._repo_url}/issues/{issue_number}/comments",
                    headers=self._auth_header,
                    json={"body": comment},
                    timeout=self.config.timeout,
                )

            # Close the issue
            response = requests.patch(
                f"{self._repo_url}/issues/{issue_number}",
                headers=self._auth_header,
                json={"state": "closed"},
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                return {"success": True, "issue_number": issue_number, "state": "closed"}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def search_issues(
        self,
        query: Optional[str] = None,
        finding_id: Optional[str] = None,
        target: Optional[str] = None,
        state: str = "open",
        labels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Search for existing issues.

        Args:
            query: Search query string
            finding_id: Search by finding ID
            target: Search by target
            state: Issue state (open, closed, all)
            labels: Filter by labels

        Returns:
            Result dict with matching issues
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            # Build search query
            q_parts = [f"repo:{self.github_config.owner}/{self.github_config.repo}"]
            q_parts.append(f"is:issue")
            q_parts.append(f"state:{state}")

            if query:
                q_parts.append(query)
            if finding_id:
                q_parts.append(f'"{finding_id}"')
            if target:
                q_parts.append(f'"{target}"')
            if labels:
                for label in labels:
                    q_parts.append(f'label:"{label}"')

            response = requests.get(
                f"{self.API_BASE}/search/issues",
                headers=self._auth_header,
                params={"q": " ".join(q_parts)},
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                data = response.json()
                issues = []
                for item in data.get("items", []):
                    issues.append({
                        "number": item.get("number"),
                        "title": item.get("title"),
                        "state": item.get("state"),
                        "url": item.get("html_url"),
                        "created_at": item.get("created_at"),
                        "labels": [l.get("name") for l in item.get("labels", [])],
                    })
                return {
                    "success": True,
                    "total": data.get("total_count", 0),
                    "issues": issues,
                }
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def add_labels(
        self,
        issue_number: int,
        labels: List[str],
    ) -> Dict[str, Any]:
        """
        Add labels to an issue.

        Args:
            issue_number: Issue number
            labels: Labels to add

        Returns:
            Result dict with success status
        """
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            response = requests.post(
                f"{self._repo_url}/issues/{issue_number}/labels",
                headers=self._auth_header,
                json={"labels": labels},
                timeout=self.config.timeout,
            )

            if response.status_code == 200:
                return {"success": True, "labels": labels}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)
