"""
Microsoft Teams Integration for PurpleSploit

Sends notifications to Microsoft Teams channels via webhooks.
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
    WebhookMixin,
)

logger = logging.getLogger(__name__)

# Optional requests import
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False


@dataclass
class TeamsConfig(IntegrationConfig):
    """Teams-specific configuration."""
    webhook_url: str = ""
    mention_users_on_critical: List[str] = field(default_factory=list)


class TeamsIntegration(BaseIntegration, WebhookMixin):
    """
    Microsoft Teams integration for sending security notifications.

    Supports:
    - Incoming Webhook notifications
    - Adaptive Card formatting
    - Severity-based coloring
    - Action buttons for quick response
    """

    def __init__(self, config: Optional[TeamsConfig] = None):
        if config is None:
            config = TeamsConfig(name="teams")
        super().__init__(config)
        self.teams_config: TeamsConfig = config

    def connect(self) -> bool:
        """Verify Teams webhook connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not self.teams_config.webhook_url:
            self._error_message = "No webhook_url configured"
            self.status = IntegrationStatus.ERROR
            return False

        self.status = IntegrationStatus.CONNECTED
        return True

    def disconnect(self) -> bool:
        """Disconnect from Teams."""
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        """Test Teams webhook connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        # Teams webhooks don't have a test endpoint
        # Just verify the URL format
        if "webhook.office.com" in self.teams_config.webhook_url or \
           "outlook.office.com" in self.teams_config.webhook_url:
            return {"success": True, "method": "webhook"}

        return {"success": True, "method": "webhook", "warning": "Non-standard webhook URL"}

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send notification to Teams."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            teams_payload = self._build_adaptive_card(payload)

            response = requests.post(
                self.teams_config.webhook_url,
                headers={"Content-Type": "application/json"},
                json=teams_payload,
                timeout=self.config.timeout,
            )

            self._record_request()

            if response.status_code == 200:
                return {"success": True}
            else:
                return {
                    "success": False,
                    "error": f"HTTP {response.status_code}: {response.text}",
                }

        except Exception as e:
            return self._handle_error(e)

    def _build_adaptive_card(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Build Teams Adaptive Card payload."""
        color = self._get_teams_color(payload.severity)

        # Build facts for the card
        facts = []
        if payload.target:
            facts.append({"title": "Target", "value": payload.target})
        if payload.severity:
            facts.append({"title": "Severity", "value": payload.severity.upper()})
        if payload.cvss_score is not None:
            facts.append({"title": "CVSS Score", "value": str(payload.cvss_score)})
        if payload.finding_id:
            facts.append({"title": "Finding ID", "value": payload.finding_id})
        if payload.tags:
            facts.append({"title": "Tags", "value": ", ".join(payload.tags)})

        # Build the Adaptive Card
        card = {
            "type": "message",
            "attachments": [
                {
                    "contentType": "application/vnd.microsoft.card.adaptive",
                    "contentUrl": None,
                    "content": {
                        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                        "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [
                            {
                                "type": "Container",
                                "style": "emphasis" if payload.priority == NotificationPriority.CRITICAL else "default",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "size": "Large",
                                        "weight": "Bolder",
                                        "text": payload.title,
                                        "color": "Attention" if payload.severity in ["critical", "high"] else "Default",
                                    }
                                ],
                            },
                            {
                                "type": "TextBlock",
                                "text": payload.message,
                                "wrap": True,
                            },
                            {
                                "type": "FactSet",
                                "facts": facts,
                            },
                            {
                                "type": "TextBlock",
                                "text": f"_Reported by PurpleSploit at {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}_",
                                "size": "Small",
                                "isSubtle": True,
                            },
                        ],
                    },
                }
            ],
        }

        # Add critical warning if needed
        if payload.priority == NotificationPriority.CRITICAL:
            warning_block = {
                "type": "TextBlock",
                "text": "⚠️ CRITICAL SECURITY FINDING DETECTED",
                "weight": "Bolder",
                "color": "Attention",
                "size": "Medium",
            }
            card["attachments"][0]["content"]["body"].insert(0, warning_block)

        return card

    def _get_teams_color(self, severity: Optional[str]) -> str:
        """Get Teams theme color for severity."""
        colors = {
            "critical": "attention",
            "high": "warning",
            "medium": "accent",
            "low": "good",
            "info": "default",
        }
        return colors.get(severity.lower() if severity else "info", "default")

    def send_finding(
        self,
        title: str,
        description: str,
        severity: str,
        target: str,
        finding_id: Optional[str] = None,
        cvss_score: Optional[float] = None,
        tags: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Send a finding notification to Teams.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level
            target: Affected target
            finding_id: Optional finding ID
            cvss_score: Optional CVSS score
            tags: Optional tags

        Returns:
            Result dict with success status
        """
        priority_map = {
            "critical": NotificationPriority.CRITICAL,
            "high": NotificationPriority.HIGH,
            "medium": NotificationPriority.MEDIUM,
            "low": NotificationPriority.LOW,
            "info": NotificationPriority.LOW,
        }

        payload = NotificationPayload(
            title=title,
            message=description,
            priority=priority_map.get(severity.lower(), NotificationPriority.MEDIUM),
            severity=severity,
            target=target,
            finding_id=finding_id,
            cvss_score=cvss_score,
            tags=tags or [],
        )

        return self.send_notification(payload)

    def send_scan_complete(
        self,
        scan_name: str,
        target: str,
        findings_count: int,
        critical_count: int = 0,
        high_count: int = 0,
    ) -> Dict[str, Any]:
        """
        Send scan completion notification.

        Args:
            scan_name: Name of the completed scan
            target: Target that was scanned
            findings_count: Total findings count
            critical_count: Critical findings count
            high_count: High findings count

        Returns:
            Result dict with success status
        """
        message = f"Scan completed for {target}\n\n"
        message += f"**Total Findings:** {findings_count}\n"
        if critical_count > 0:
            message += f"🔴 **Critical:** {critical_count}\n"
        if high_count > 0:
            message += f"🟠 **High:** {high_count}"

        priority = NotificationPriority.MEDIUM
        severity = "info"
        if critical_count > 0:
            priority = NotificationPriority.CRITICAL
            severity = "critical"
        elif high_count > 0:
            priority = NotificationPriority.HIGH
            severity = "high"

        payload = NotificationPayload(
            title=f"Scan Complete: {scan_name}",
            message=message,
            priority=priority,
            severity=severity,
            target=target,
            extra_data={
                "findings_count": findings_count,
                "critical_count": critical_count,
                "high_count": high_count,
            },
        )

        return self.send_notification(payload)
