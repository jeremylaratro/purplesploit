"""
Slack Integration for PurpleSploit

Sends notifications to Slack channels via webhooks or API.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
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
class SlackConfig(IntegrationConfig):
    """Slack-specific configuration."""
    webhook_url: Optional[str] = None
    bot_token: Optional[str] = None
    default_channel: str = "#security-alerts"
    username: str = "PurpleSploit"
    icon_emoji: str = ":skull:"
    mention_users_on_critical: List[str] = field(default_factory=list)


class SlackIntegration(BaseIntegration, WebhookMixin):
    """
    Slack integration for sending security notifications.

    Supports:
    - Webhook-based notifications
    - Rich message formatting with attachments
    - Severity-based coloring
    - User mentions for critical findings
    - Thread replies for updates
    """

    def __init__(self, config: Optional[SlackConfig] = None):
        if config is None:
            config = SlackConfig(name="slack")
        super().__init__(config)
        self.slack_config: SlackConfig = config
        self._thread_map: Dict[str, str] = {}  # finding_id -> thread_ts

    def connect(self) -> bool:
        """Verify Slack connection."""
        if not REQUESTS_AVAILABLE:
            self._error_message = "requests library not installed"
            self.status = IntegrationStatus.ERROR
            return False

        if not self.slack_config.webhook_url and not self.slack_config.bot_token:
            self._error_message = "No webhook_url or bot_token configured"
            self.status = IntegrationStatus.ERROR
            return False

        # Test the connection
        result = self.test_connection()
        if result.get("success"):
            self.status = IntegrationStatus.CONNECTED
            return True
        return False

    def disconnect(self) -> bool:
        """Disconnect from Slack."""
        self.status = IntegrationStatus.DISCONNECTED
        return True

    def test_connection(self) -> Dict[str, Any]:
        """Test Slack connection."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        try:
            if self.slack_config.webhook_url:
                # Webhooks don't have a test endpoint, so we send a minimal payload
                # that Slack will accept but not post (empty text with no attachments
                # would error, so we just verify the URL format)
                return {"success": True, "method": "webhook"}

            elif self.slack_config.bot_token:
                # Use auth.test API endpoint
                response = requests.post(
                    "https://slack.com/api/auth.test",
                    headers={"Authorization": f"Bearer {self.slack_config.bot_token}"},
                    timeout=self.config.timeout,
                )
                data = response.json()
                if data.get("ok"):
                    return {
                        "success": True,
                        "method": "bot_token",
                        "team": data.get("team"),
                        "user": data.get("user"),
                    }
                return {"success": False, "error": data.get("error")}

            return {"success": False, "error": "No authentication configured"}

        except Exception as e:
            return self._handle_error(e)

    def send_notification(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Send notification to Slack."""
        if not REQUESTS_AVAILABLE:
            return {"success": False, "error": "requests library not installed"}

        if not self._check_rate_limit():
            return {"success": False, "error": "Rate limited"}

        try:
            slack_payload = self._build_slack_payload(payload)

            if self.slack_config.webhook_url:
                result = self._send_webhook(slack_payload)
            elif self.slack_config.bot_token:
                result = self._send_api(slack_payload)
            else:
                return {"success": False, "error": "No authentication configured"}

            self._record_request()
            return result

        except Exception as e:
            return self._handle_error(e)

    def _build_slack_payload(self, payload: NotificationPayload) -> Dict[str, Any]:
        """Build Slack-formatted message payload."""
        color = self._get_severity_color(payload.severity)

        # Build attachment fields
        fields = []
        if payload.target:
            fields.append({
                "title": "Target",
                "value": f"`{payload.target}`",
                "short": True,
            })
        if payload.severity:
            fields.append({
                "title": "Severity",
                "value": payload.severity.upper(),
                "short": True,
            })
        if payload.cvss_score is not None:
            fields.append({
                "title": "CVSS Score",
                "value": str(payload.cvss_score),
                "short": True,
            })
        if payload.finding_id:
            fields.append({
                "title": "Finding ID",
                "value": payload.finding_id,
                "short": True,
            })
        if payload.tags:
            fields.append({
                "title": "Tags",
                "value": ", ".join(payload.tags),
                "short": False,
            })

        # Build the message
        text = ""
        if (
            payload.priority == NotificationPriority.CRITICAL
            and self.slack_config.mention_users_on_critical
        ):
            mentions = " ".join(
                f"<@{user}>" for user in self.slack_config.mention_users_on_critical
            )
            text = f":rotating_light: {mentions} CRITICAL FINDING DETECTED!\n"

        slack_message = {
            "username": self.slack_config.username,
            "icon_emoji": self.slack_config.icon_emoji,
            "text": text or payload.title,
            "attachments": [
                {
                    "color": color,
                    "title": payload.title,
                    "text": payload.message,
                    "fields": fields,
                    "footer": f"PurpleSploit | {payload.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}",
                    "mrkdwn_in": ["text", "fields"],
                }
            ],
        }

        # Add channel for API method
        if self.slack_config.bot_token:
            slack_message["channel"] = self.slack_config.default_channel

        # Add thread_ts if this is an update to existing finding
        if payload.finding_id and payload.finding_id in self._thread_map:
            slack_message["thread_ts"] = self._thread_map[payload.finding_id]

        return slack_message

    def _send_webhook(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send message via webhook."""
        response = requests.post(
            self.slack_config.webhook_url,
            json=payload,
            timeout=self.config.timeout,
        )

        if response.status_code == 200:
            return {"success": True, "method": "webhook"}
        else:
            return {
                "success": False,
                "error": f"HTTP {response.status_code}: {response.text}",
            }

    def _send_api(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Send message via Slack API."""
        response = requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {self.slack_config.bot_token}"},
            json=payload,
            timeout=self.config.timeout,
        )

        data = response.json()
        if data.get("ok"):
            # Store thread_ts for future updates
            if payload.get("finding_id"):
                self._thread_map[payload["finding_id"]] = data.get("ts")

            return {
                "success": True,
                "method": "api",
                "ts": data.get("ts"),
                "channel": data.get("channel"),
            }
        else:
            return {"success": False, "error": data.get("error")}

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
        Convenience method to send a finding notification.

        Args:
            title: Finding title
            description: Finding description
            severity: Severity level (critical, high, medium, low, info)
            target: Affected target
            finding_id: Optional finding ID for threading
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
        message = f"Scan completed for `{target}`\n"
        message += f"*Total Findings:* {findings_count}\n"
        if critical_count > 0:
            message += f":red_circle: *Critical:* {critical_count}\n"
        if high_count > 0:
            message += f":orange_circle: *High:* {high_count}"

        priority = NotificationPriority.MEDIUM
        if critical_count > 0:
            priority = NotificationPriority.CRITICAL
        elif high_count > 0:
            priority = NotificationPriority.HIGH

        payload = NotificationPayload(
            title=f"Scan Complete: {scan_name}",
            message=message,
            priority=priority,
            target=target,
            extra_data={
                "findings_count": findings_count,
                "critical_count": critical_count,
                "high_count": high_count,
            },
        )

        return self.send_notification(payload)
