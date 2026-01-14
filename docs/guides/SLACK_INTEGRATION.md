# Slack Integration Guide

Comprehensive guide for integrating PurpleSploit with Slack for real-time security notifications and finding alerts.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [Slack App Setup](#slack-app-setup)
- [Webhook Configuration](#webhook-configuration)
- [Bot Token Configuration](#bot-token-configuration)
- [Configuration Options](#configuration-options)
- [Integration Usage](#integration-usage)
- [Notification Types](#notification-types)
- [Customization](#customization)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## Overview

The Slack integration allows PurpleSploit to send real-time notifications about security findings, scan completions, and critical vulnerabilities directly to your Slack workspace. This enables immediate awareness and response to security issues discovered during testing.

### Features

- Real-time finding notifications
- Rich message formatting with severity colors
- Threaded replies for finding updates
- User mentions for critical findings
- Scan completion summaries
- Multiple notification channels
- Rate limiting protection
- Two authentication methods: Webhooks and Bot Tokens

### Notification Flow

```
PurpleSploit Scan
    |
    v
Finding Detected
    |
    v
SlackIntegration.send_notification()
    |
    v
Slack Channel (with formatting, colors, mentions)
```

## Prerequisites

### Requirements

- Slack workspace with admin permissions
- PurpleSploit installation with `requests` library
- Network access to Slack API endpoints

### Install Dependencies

```bash
# Install requests if not already available
pip install requests
```

### Verify Installation

```python
from purplesploit.integrations.slack import SlackIntegration

# Verify module loads
print("Slack integration available")
```

## Slack App Setup

### Option 1: Incoming Webhooks (Recommended for Simple Use)

Incoming Webhooks are the easiest way to get started. They allow posting messages to a specific channel without complex app configuration.

#### Step 1: Create Slack App

1. Go to https://api.slack.com/apps
2. Click "Create New App"
3. Choose "From scratch"
4. Enter App Name: "PurpleSploit Security Alerts"
5. Select your workspace
6. Click "Create App"

#### Step 2: Enable Incoming Webhooks

1. In your app settings, click "Incoming Webhooks"
2. Toggle "Activate Incoming Webhooks" to ON
3. Click "Add New Webhook to Workspace"
4. Select the channel for notifications (e.g., #security-alerts)
5. Click "Allow"
6. Copy the Webhook URL (starts with `https://hooks.slack.com/services/`)

#### Step 3: Test Webhook

```bash
# Test with curl
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Hello from PurpleSploit!"}' \
  YOUR_WEBHOOK_URL
```

### Option 2: Bot Token (Advanced Features)

Bot tokens enable advanced features like threading, reactions, and message updates.

#### Step 1: Create Slack App

Same as Option 1, steps 1-6

#### Step 2: Configure Bot Scopes

1. In app settings, click "OAuth & Permissions"
2. Scroll to "Scopes" section
3. Add the following Bot Token Scopes:
   - `chat:write` - Post messages
   - `chat:write.public` - Post to public channels without joining
   - `files:write` - Upload files (optional, for evidence)
   - `channels:read` - List channels (optional)

#### Step 3: Install App to Workspace

1. Scroll up to "OAuth Tokens for Your Workspace"
2. Click "Install to Workspace"
3. Review permissions and click "Allow"
4. Copy the "Bot User OAuth Token" (starts with `xoxb-`)

#### Step 4: Add Bot to Channel

1. Open the Slack channel for notifications
2. Type `/invite @PurpleSploit Security Alerts`
3. The bot can now post to this channel

## Webhook Configuration

### Basic Webhook Setup

```python
from purplesploit.integrations.slack import SlackIntegration, SlackConfig

# Create configuration
config = SlackConfig(
    name="slack",
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    default_channel="#security-alerts",  # Only for display, webhook is tied to channel
    username="PurpleSploit",
    icon_emoji=":skull:"
)

# Initialize integration
slack = SlackIntegration(config)

# Test connection
result = slack.test_connection()
print(result)  # {'success': True, 'method': 'webhook'}
```

### Configuration File

Create `config/slack.json`:

```json
{
  "name": "slack",
  "enabled": true,
  "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
  "default_channel": "#security-alerts",
  "username": "PurpleSploit",
  "icon_emoji": ":skull:",
  "mention_users_on_critical": ["U1234567890"],
  "timeout": 30,
  "rate_limit": 60
}
```

Load configuration:

```python
import json
from purplesploit.integrations.slack import SlackIntegration, SlackConfig

# Load from file
with open('config/slack.json', 'r') as f:
    config_dict = json.load(f)

config = SlackConfig(**config_dict)
slack = SlackIntegration(config)
```

## Bot Token Configuration

### Basic Bot Token Setup

```python
from purplesploit.integrations.slack import SlackIntegration, SlackConfig

# Create configuration with bot token
config = SlackConfig(
    name="slack",
    bot_token="xoxb-YOUR-BOT-TOKEN",
    default_channel="#security-alerts",
    username="PurpleSploit",
    icon_emoji=":skull:"
)

# Initialize and connect
slack = SlackIntegration(config)

if slack.connect():
    print("Connected successfully")
    print(slack.test_connection())
    # {
    #   'success': True,
    #   'method': 'bot_token',
    #   'team': 'Your Workspace',
    #   'user': 'purplesploit_bot'
    # }
```

### Environment Variables

Store sensitive tokens in environment variables:

```bash
# Set in .env file
export SLACK_BOT_TOKEN="xoxb-YOUR-BOT-TOKEN"
export SLACK_CHANNEL="#security-alerts"
```

```python
import os
from purplesploit.integrations.slack import SlackIntegration, SlackConfig

config = SlackConfig(
    name="slack",
    bot_token=os.getenv("SLACK_BOT_TOKEN"),
    default_channel=os.getenv("SLACK_CHANNEL", "#security-alerts"),
    username="PurpleSploit",
    icon_emoji=":skull:"
)

slack = SlackIntegration(config)
```

## Configuration Options

### SlackConfig Parameters

```python
@dataclass
class SlackConfig(IntegrationConfig):
    """Slack-specific configuration"""

    # Authentication (choose one)
    webhook_url: Optional[str] = None              # Webhook URL
    bot_token: Optional[str] = None                # Bot token (xoxb-)

    # Channel Settings
    default_channel: str = "#security-alerts"      # Default channel

    # Message Appearance
    username: str = "PurpleSploit"                 # Bot display name
    icon_emoji: str = ":skull:"                    # Bot icon emoji

    # Mentions
    mention_users_on_critical: List[str] = []      # User IDs to mention
                                                    # Format: ["U1234567890"]

    # Base Integration Settings (inherited)
    timeout: int = 30                              # Request timeout (seconds)
    rate_limit: int = 60                           # Max requests per minute
    retry_count: int = 3                           # Retry failed requests
```

### Complete Configuration Example

```python
config = SlackConfig(
    name="slack",
    enabled=True,

    # Authentication
    bot_token="xoxb-1234567890-1234567890-abc123def456",

    # Channel
    default_channel="#security-critical",

    # Appearance
    username="PurpleSploit Security Scanner",
    icon_emoji=":shield:",

    # Critical Alerts
    mention_users_on_critical=[
        "U1234567890",  # @security-lead
        "U0987654321",  # @incident-response
    ],

    # API Settings
    timeout=30,
    rate_limit=60,
    retry_count=3
)
```

## Integration Usage

### Initialize Integration

```python
from purplesploit.integrations.slack import SlackIntegration, SlackConfig

# Create and connect
config = SlackConfig(
    name="slack",
    webhook_url="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
)

slack = SlackIntegration(config)

# Connect (validates configuration)
if slack.connect():
    print("Slack integration ready")
else:
    print(f"Connection failed: {slack._error_message}")
```

### Send Basic Notification

```python
from purplesploit.integrations.base import NotificationPayload, NotificationPriority

# Create payload
payload = NotificationPayload(
    title="SQL Injection Detected",
    message="Found SQL injection vulnerability in login form",
    priority=NotificationPriority.HIGH,
    severity="high",
    target="https://example.com/login",
    finding_id="FINDING-001"
)

# Send notification
result = slack.send_notification(payload)

if result.get("success"):
    print("Notification sent")
else:
    print(f"Failed: {result.get('error')}")
```

### Send Finding

Convenience method for security findings:

```python
result = slack.send_finding(
    title="Command Injection in API Endpoint",
    description="The /api/execute endpoint is vulnerable to command injection...",
    severity="critical",
    target="https://api.example.com/execute",
    finding_id="VULN-2024-001",
    cvss_score=9.8,
    tags=["injection", "rce", "api"]
)

print(result)
# {'success': True, 'method': 'webhook'}
```

### Send Scan Complete

Notify when scans complete:

```python
result = slack.send_scan_complete(
    scan_name="Full Application Scan",
    target="https://example.com",
    findings_count=15,
    critical_count=2,
    high_count=5
)

# Automatically mentions users if critical_count > 0
```

## Notification Types

### 1. Finding Notifications

Security vulnerabilities and findings:

```python
slack.send_finding(
    title="XSS Vulnerability",
    description="Reflected XSS in search parameter",
    severity="high",
    target="https://example.com/search?q=<script>",
    cvss_score=7.5,
    tags=["xss", "web", "client-side"]
)
```

**Slack Output:**
```
[HIGH] XSS Vulnerability

Reflected XSS in search parameter

Target: https://example.com/search?q=<script>
Severity: HIGH
CVSS Score: 7.5
Tags: xss, web, client-side

PurpleSploit | 2024-01-15 14:30:00 UTC
```

### 2. Critical Alerts

Mentions security team:

```python
# Configure mentions
config.mention_users_on_critical = ["U1234567890"]

slack.send_finding(
    title="Remote Code Execution",
    description="Unauthenticated RCE via file upload",
    severity="critical",
    target="https://example.com/upload",
    cvss_score=10.0
)
```

**Slack Output:**
```
:rotating_light: @security-lead CRITICAL FINDING DETECTED!

[CRITICAL] Remote Code Execution

Unauthenticated RCE via file upload

Target: https://example.com/upload
Severity: CRITICAL
CVSS Score: 10.0

PurpleSploit | 2024-01-15 14:30:00 UTC
```

### 3. Scan Completion

Summary of scan results:

```python
slack.send_scan_complete(
    scan_name="Nmap Full Scan",
    target="192.168.1.0/24",
    findings_count=45,
    critical_count=0,
    high_count=3
)
```

**Slack Output:**
```
Scan Complete: Nmap Full Scan

Scan completed for 192.168.1.0/24
Total Findings: 45
:orange_circle: High: 3
```

### 4. Custom Notifications

Send custom messages:

```python
from purplesploit.integrations.base import NotificationPayload

payload = NotificationPayload(
    title="Scan Started",
    message="Beginning comprehensive security assessment of production environment",
    priority=NotificationPriority.MEDIUM,
    extra_data={
        "scan_type": "comprehensive",
        "duration_estimate": "4 hours",
        "modules": ["web", "network", "api"]
    }
)

slack.send_notification(payload)
```

## Customization

### Custom Icons

```python
# Use different emojis
config.icon_emoji = ":lock:"      # Lock
config.icon_emoji = ":warning:"   # Warning sign
config.icon_emoji = ":shield:"    # Shield
config.icon_emoji = ":fire:"      # Fire
config.icon_emoji = ":skull:"     # Skull (default)

# Use custom image
config.icon_emoji = None
# Configure icon_url in Slack webhook settings
```

### Custom Username

```python
config.username = "Security Scanner"
config.username = "PurpleSploit Alert Bot"
config.username = "Vulnerability Detector"
```

### Severity Colors

Colors are automatically applied based on severity:

- **Critical**: Red (#FF0000)
- **High**: Orange (#FF6600)
- **Medium**: Yellow (#FFCC00)
- **Low**: Green (#00CC00)
- **Info**: Blue (#0066FF)

### Message Formatting

Slack uses mrkdwn formatting:

```python
payload = NotificationPayload(
    title="*Bold Title*",
    message="""
    Normal text
    *Bold text*
    _Italic text_
    `Code text`
    ```
    Code block
    ```
    >Quote text
    """,
    priority=NotificationPriority.MEDIUM
)
```

## Advanced Features

### Threaded Updates

When using bot tokens, updates to the same finding are posted as thread replies:

```python
# Initial finding
slack.send_finding(
    title="SQL Injection",
    description="Initial detection",
    severity="high",
    target="https://example.com",
    finding_id="VULN-001"  # Important: Same ID for threading
)

# Update (posted as reply in thread)
slack.send_finding(
    title="SQL Injection - Confirmed",
    description="Exploitation confirmed, data extraction possible",
    severity="critical",
    target="https://example.com",
    finding_id="VULN-001"  # Same ID = thread reply
)
```

### Rate Limiting

Automatic rate limiting prevents API abuse:

```python
config.rate_limit = 60  # 60 requests per minute

# Send many notifications
for i in range(100):
    result = slack.send_notification(payload)

    if not result.get("success"):
        if "Rate limited" in result.get("error", ""):
            print("Rate limited, waiting...")
            time.sleep(60)
```

### Error Handling

```python
result = slack.send_notification(payload)

if result.get("success"):
    print("Sent successfully")
else:
    error = result.get("error")

    if "Rate limited" in error:
        # Handle rate limit
        pass
    elif "HTTP 404" in error:
        # Webhook URL invalid
        pass
    elif "HTTP 403" in error:
        # Permission denied
        pass
    else:
        # Other error
        print(f"Error: {error}")
```

### Integration Status

```python
status = slack.get_status()
print(status)
# {
#   'name': 'slack',
#   'enabled': True,
#   'status': 'connected',
#   'error': None,
#   'request_count': 15
# }
```

## Troubleshooting

### Common Issues

#### 1. "requests library not installed"

```bash
pip install requests
```

#### 2. "No webhook_url or bot_token configured"

Verify configuration:

```python
print(config.webhook_url)  # Should not be None
# or
print(config.bot_token)    # Should not be None
```

#### 3. "HTTP 404: Not Found"

Webhook URL is invalid or deleted. Create a new webhook in Slack app settings.

#### 4. "HTTP 403: Forbidden"

- Webhook: Webhook was revoked
- Bot: Bot doesn't have `chat:write` permission or isn't in the channel

#### 5. "Rate limited"

Too many requests. Adjust `rate_limit` or add delays:

```python
config.rate_limit = 30  # Reduce to 30/minute

# Or add delay between notifications
import time
slack.send_notification(payload1)
time.sleep(2)  # 2 second delay
slack.send_notification(payload2)
```

#### 6. Messages not appearing

- Verify channel name format: `#channel-name`
- For bot tokens: Ensure bot is invited to channel
- Check Slack app is installed to workspace

### Debug Mode

Enable logging:

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("purplesploit.integrations.slack")
logger.setLevel(logging.DEBUG)

# Now see detailed logs
slack.send_notification(payload)
```

### Test Connection

```python
result = slack.test_connection()

if result.get("success"):
    print(f"Connected via {result.get('method')}")

    if result.get("method") == "bot_token":
        print(f"Team: {result.get('team')}")
        print(f"User: {result.get('user')}")
else:
    print(f"Connection failed: {result.get('error')}")
```

## Security Considerations

### Protecting Webhook URLs

Webhook URLs are sensitive and should be protected:

```python
# Bad: Hardcoded in code
webhook_url = "https://hooks.slack.com/services/ABC/DEF/123"

# Good: Environment variable
import os
webhook_url = os.getenv("SLACK_WEBHOOK_URL")

# Good: Configuration file (with restricted permissions)
# chmod 600 config/slack.json
```

### Protecting Bot Tokens

Bot tokens are highly sensitive:

```python
# Bad: Hardcoded
bot_token = "xoxb-1234567890-abc123"

# Good: Environment variable
bot_token = os.getenv("SLACK_BOT_TOKEN")

# Good: Secrets management (e.g., AWS Secrets Manager, HashiCorp Vault)
from secrets_manager import get_secret
bot_token = get_secret("slack/bot_token")
```

### Limiting Information Disclosure

Be careful about what you send to Slack:

```python
# Bad: Sending passwords
slack.send_finding(
    title="Found password",
    description=f"Password is: {actual_password}"  # Don't do this!
)

# Good: Redacting sensitive data
slack.send_finding(
    title="Found credential",
    description="Found hardcoded credential in source code (redacted in alert)"
)
```

### User ID Privacy

User IDs for mentions are not PII, but document who will be mentioned:

```python
# Document in team configuration
config.mention_users_on_critical = [
    "U1234567890",  # Security Lead (john@company.com)
    "U0987654321",  # Incident Response (ir@company.com)
]
```

### Network Security

- Use HTTPS for all Slack communication (default)
- Consider IP allowlisting if using Slack Enterprise
- Monitor integration logs for anomalies

### Audit Trail

Log all notifications:

```python
def send_with_logging(slack, payload):
    """Send notification with audit logging"""
    result = slack.send_notification(payload)

    # Log to audit system
    audit_log = {
        "timestamp": datetime.utcnow().isoformat(),
        "integration": "slack",
        "title": payload.title,
        "severity": payload.severity,
        "target": payload.target,
        "success": result.get("success")
    }

    with open("audit.log", "a") as f:
        f.write(json.dumps(audit_log) + "\n")

    return result
```

## Example: Complete Integration

```python
"""
Complete Slack integration example for PurpleSploit
"""

import os
from purplesploit.integrations.slack import SlackIntegration, SlackConfig
from purplesploit.integrations.base import NotificationPayload, NotificationPriority


def setup_slack_integration():
    """Setup Slack integration"""
    config = SlackConfig(
        name="slack",
        webhook_url=os.getenv("SLACK_WEBHOOK_URL"),
        default_channel="#security-alerts",
        username="PurpleSploit Scanner",
        icon_emoji=":shield:",
        mention_users_on_critical=[
            os.getenv("SLACK_SECURITY_LEAD_ID"),
        ],
        timeout=30,
        rate_limit=60
    )

    slack = SlackIntegration(config)

    if not slack.connect():
        raise Exception(f"Failed to connect: {slack._error_message}")

    return slack


def notify_finding(slack, finding):
    """Send finding to Slack"""
    result = slack.send_finding(
        title=finding["title"],
        description=finding["description"],
        severity=finding["severity"],
        target=finding["target"],
        finding_id=finding.get("id"),
        cvss_score=finding.get("cvss_score"),
        tags=finding.get("tags", [])
    )

    if not result.get("success"):
        print(f"Failed to send: {result.get('error')}")

    return result


def main():
    """Main integration workflow"""
    # Setup
    slack = setup_slack_integration()

    # Example finding
    finding = {
        "id": "VULN-2024-001",
        "title": "SQL Injection in Login Form",
        "description": "The login form is vulnerable to SQL injection...",
        "severity": "critical",
        "target": "https://example.com/login",
        "cvss_score": 9.8,
        "tags": ["injection", "sqli", "authentication"]
    }

    # Send notification
    notify_finding(slack, finding)

    # Send scan complete
    slack.send_scan_complete(
        scan_name="Full Application Scan",
        target="https://example.com",
        findings_count=15,
        critical_count=1,
        high_count=4
    )


if __name__ == "__main__":
    main()
```

## Conclusion

The Slack integration provides real-time visibility into security findings discovered by PurpleSploit. Proper configuration ensures your security team is immediately aware of critical vulnerabilities, enabling rapid response and remediation.

### Key Points

1. Choose webhook or bot token based on your needs
2. Protect sensitive tokens and URLs
3. Configure user mentions for critical findings
4. Customize appearance and formatting
5. Handle rate limiting and errors gracefully
6. Monitor integration health and logs
7. Follow security best practices

For additional help, refer to:
- Slack API documentation: https://api.slack.com
- PurpleSploit documentation: `docs/API.md`
- Integration base class: `docs/guides/INTEGRATION_DEVELOPMENT.md`
