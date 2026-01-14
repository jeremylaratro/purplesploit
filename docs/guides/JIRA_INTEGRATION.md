# JIRA Integration Guide

Comprehensive guide for integrating PurpleSploit with Atlassian JIRA to automatically create, track, and manage security findings as JIRA issues.

## Table of Contents

- [Overview](#overview)
- [Prerequisites](#prerequisites)
- [JIRA API Authentication](#jira-api-authentication)
- [Basic Configuration](#basic-configuration)
- [Field Mapping](#field-mapping)
- [Issue Creation Workflow](#issue-creation-workflow)
- [Custom Fields](#custom-fields)
- [Priority Mapping](#priority-mapping)
- [Usage Examples](#usage-examples)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [Security Best Practices](#security-best-practices)

## Overview

The JIRA integration enables automatic creation and management of security findings as JIRA issues. This provides structured tracking, assignment, and remediation workflow for vulnerabilities discovered during security testing.

### Features

- Automatic issue creation from findings
- Custom field mapping
- Priority and severity mapping
- Attachment upload for evidence
- Issue updates and comments
- Issue state transitions
- Duplicate detection via search
- Support for JIRA Cloud and Server

### Workflow

```
PurpleSploit Finding
    |
    v
JiraIntegration.create_finding_issue()
    |
    v
JIRA Issue Created (with fields, priority, labels)
    |
    v
Evidence Attached (screenshots, logs)
    |
    v
Issue Assigned to Security Team
```

## Prerequisites

### Requirements

- JIRA Cloud or Server instance
- Admin or project admin permissions
- API token or password authentication
- PurpleSploit with `requests` library
- Network access to JIRA instance

### Install Dependencies

```bash
pip install requests
```

### JIRA Versions Supported

- JIRA Cloud (API v2)
- JIRA Server 7.x, 8.x (API v2)
- JIRA Data Center

## JIRA API Authentication

### For JIRA Cloud

JIRA Cloud uses API tokens for authentication.

#### Step 1: Generate API Token

1. Log into JIRA Cloud
2. Go to Account Settings: https://id.atlassian.com/manage-profile/security/api-tokens
3. Click "Create API token"
4. Enter label: "PurpleSploit Integration"
5. Click "Create"
6. Copy the token (shown once)

#### Step 2: Get User Email

Your JIRA email address serves as the username:

```
username: john.doe@company.com
api_token: ATB...xyz123
```

#### Step 3: Get Server URL

JIRA Cloud URL format:

```
https://your-company.atlassian.net
```

### For JIRA Server/Data Center

JIRA Server can use API tokens (if configured) or password authentication.

#### Option 1: API Token (Recommended)

Same as Cloud - generate a personal access token:

1. Go to Profile > Personal Access Tokens
2. Create token with appropriate scopes
3. Use as api_key in configuration

#### Option 2: Password Authentication

Use JIRA password (less secure, not recommended):

```python
# Not recommended - use API tokens instead
config = JiraConfig(
    server_url="https://jira.company.com",
    username="john.doe",
    api_key="your_jira_password"  # Password auth
)
```

#### Get Server URL

JIRA Server URL format:

```
https://jira.company.com
http://jira.internal.local:8080
```

### Test Authentication

```bash
# Test with curl
curl -u john.doe@company.com:ATB...xyz123 \
  https://your-company.atlassian.net/rest/api/2/myself
```

Should return your user profile JSON.

## Basic Configuration

### Minimal Configuration

```python
from purplesploit.integrations.jira_integration import JiraIntegration, JiraConfig

# Create configuration
config = JiraConfig(
    name="jira",
    server_url="https://your-company.atlassian.net",
    username="john.doe@company.com",
    api_key="ATB...xyz123",
    project_key="SEC"  # Your project key
)

# Initialize integration
jira = JiraIntegration(config)

# Connect and test
if jira.connect():
    print("JIRA integration ready")
    print(jira.test_connection())
else:
    print(f"Connection failed: {jira._error_message}")
```

### Configuration File

Create `config/jira.json`:

```json
{
  "name": "jira",
  "enabled": true,
  "server_url": "https://your-company.atlassian.net",
  "username": "john.doe@company.com",
  "api_key": "ATB...xyz123",
  "project_key": "SEC",
  "issue_type": "Security Bug",
  "assignee": "security-lead",
  "labels": ["security", "purplesploit", "vulnerability"],
  "timeout": 30
}
```

Load configuration:

```python
import json
from purplesploit.integrations.jira_integration import JiraIntegration, JiraConfig

with open('config/jira.json', 'r') as f:
    config_dict = json.load(f)

config = JiraConfig(**config_dict)
jira = JiraIntegration(config)
```

### Environment Variables

```bash
# .env file
export JIRA_SERVER_URL="https://your-company.atlassian.net"
export JIRA_USERNAME="john.doe@company.com"
export JIRA_API_TOKEN="ATB...xyz123"
export JIRA_PROJECT_KEY="SEC"
```

```python
import os
from purplesploit.integrations.jira_integration import JiraIntegration, JiraConfig

config = JiraConfig(
    name="jira",
    server_url=os.getenv("JIRA_SERVER_URL"),
    username=os.getenv("JIRA_USERNAME"),
    api_key=os.getenv("JIRA_API_TOKEN"),
    project_key=os.getenv("JIRA_PROJECT_KEY")
)

jira = JiraIntegration(config)
```

## Field Mapping

### Standard JIRA Fields

PurpleSploit automatically maps to these standard JIRA fields:

```python
{
    "project": {"key": "SEC"},                    # Project key
    "summary": "SQL Injection in Login",          # Issue title
    "description": "Detailed description...",     # Full description
    "issuetype": {"name": "Bug"},                 # Issue type
    "priority": {"name": "High"},                 # Priority level
    "labels": ["security", "purplesploit"],       # Labels/tags
    "assignee": {"name": "security-lead"}         # Assigned user
}
```

### Default Mapping

| PurpleSploit Field | JIRA Field | Notes |
|-------------------|------------|-------|
| Finding Title | Summary | Issue title |
| Description | Description | Full description with details table |
| Severity | Priority | Mapped via priority_mapping |
| Tags | Labels | Array of labels |
| Target | Description | Included in details table |
| CVSS Score | Description | Included in details table |
| Finding ID | Description | Included in details table |

### Priority Mapping

Configure how PurpleSploit severities map to JIRA priorities:

```python
config = JiraConfig(
    # ... other config ...
    priority_mapping={
        "critical": "Highest",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Lowest"
    }
)
```

Common JIRA priority names:
- Highest / Blocker
- High / Critical
- Medium
- Low
- Lowest / Trivial

### Issue Type Mapping

Set the appropriate issue type for security findings:

```python
config.issue_type = "Security Bug"
config.issue_type = "Bug"
config.issue_type = "Vulnerability"
config.issue_type = "Security Finding"
```

Available issue types depend on your JIRA configuration.

## Issue Creation Workflow

### Basic Issue Creation

```python
# Create finding issue
result = jira.create_finding_issue(
    title="SQL Injection in User Search",
    description="The user search functionality is vulnerable to SQL injection...",
    severity="high",
    target="https://app.example.com/search",
    finding_id="VULN-2024-001",
    cvss_score=8.5,
    tags=["injection", "sqli", "web"]
)

if result.get("success"):
    print(f"Created issue: {result['issue_key']}")
    print(f"View at: {result['issue_url']}")
else:
    print(f"Failed: {result.get('error')}")
```

### Issue with Remediation

```python
result = jira.create_finding_issue(
    title="Cross-Site Scripting (XSS) in Profile",
    description="Reflected XSS vulnerability in user profile display name field",
    severity="medium",
    target="https://app.example.com/profile",
    cvss_score=6.1,
    remediation="""
    Recommended fixes:
    1. Implement output encoding for all user-controlled data
    2. Use Content Security Policy (CSP) headers
    3. Validate and sanitize input on the server side
    4. Consider using a templating engine with auto-escaping
    """,
    tags=["xss", "web", "client-side"]
)
```

### Issue with Evidence

```python
result = jira.create_finding_issue(
    title="Broken Authentication",
    description="Session tokens are predictable and can be guessed",
    severity="critical",
    target="https://api.example.com/auth",
    cvss_score=9.1,
    evidence=[
        "/path/to/screenshot1.png",
        "/path/to/burp_log.txt",
        "/path/to/exploit_poc.py"
    ],
    tags=["authentication", "session", "api"]
)

# Evidence files are automatically attached
```

### Complete Workflow Example

```python
def process_finding(finding_data):
    """Process a finding and create JIRA issue"""

    # Check for duplicate
    existing = jira.search_issues(
        finding_id=finding_data["id"]
    )

    if existing.get("issues"):
        print(f"Duplicate found: {existing['issues'][0]['key']}")
        return existing['issues'][0]

    # Create new issue
    result = jira.create_finding_issue(
        title=finding_data["title"],
        description=finding_data["description"],
        severity=finding_data["severity"],
        target=finding_data["target"],
        finding_id=finding_data["id"],
        cvss_score=finding_data.get("cvss_score"),
        remediation=finding_data.get("remediation"),
        evidence=finding_data.get("evidence_files", []),
        tags=finding_data.get("tags", [])
    )

    if result.get("success"):
        issue_key = result["issue_key"]

        # Transition to appropriate state
        if finding_data["severity"] == "critical":
            jira.transition_issue(issue_key, "In Progress")

        print(f"Created {issue_key}: {result['issue_url']}")

    return result
```

## Custom Fields

### Adding Custom Fields

JIRA custom fields have specific IDs (e.g., `customfield_10001`).

#### Step 1: Find Custom Field ID

```bash
# Get field information
curl -u email@company.com:token \
  https://your-company.atlassian.net/rest/api/2/field \
  | jq '.[] | select(.name=="Custom Field Name")'
```

Or in JIRA admin:
1. Settings > Issues > Custom fields
2. Click on the field
3. URL contains ID: `/secure/admin/EditCustomField!default.jspa?id=10001`

#### Step 2: Configure Custom Fields

```python
config = JiraConfig(
    # ... other config ...
    custom_fields={
        "customfield_10001": "Production",           # Environment (select)
        "customfield_10002": 8.5,                    # Risk Score (number)
        "customfield_10003": "Web Application",      # Application Type (text)
        "customfield_10004": {                       # Complex field (object)
            "value": "External Pentest"
        }
    }
)
```

### Custom Field Types

```python
# Text field
custom_fields["customfield_10001"] = "Value"

# Number field
custom_fields["customfield_10002"] = 42

# Select field (single)
custom_fields["customfield_10003"] = {"value": "Option1"}

# Select field (multiple)
custom_fields["customfield_10004"] = [
    {"value": "Option1"},
    {"value": "Option2"}
]

# User picker
custom_fields["customfield_10005"] = {"name": "username"}

# Date field
custom_fields["customfield_10006"] = "2024-12-31"

# URL field
custom_fields["customfield_10007"] = "https://example.com"
```

### Dynamic Custom Fields

Set custom fields programmatically:

```python
def create_issue_with_custom_fields(jira, finding, environment):
    """Create issue with dynamic custom fields"""

    # Clone config
    config = jira.jira_config

    # Set custom fields based on finding
    config.custom_fields = {
        "customfield_10001": environment,           # Environment
        "customfield_10002": finding["cvss_score"], # Risk Score
        "customfield_10003": finding["category"],   # Category
    }

    # Create issue
    return jira.create_finding_issue(
        title=finding["title"],
        description=finding["description"],
        severity=finding["severity"],
        target=finding["target"]
    )
```

## Usage Examples

### Example 1: Simple Integration

```python
"""Simple JIRA integration"""

from purplesploit.integrations.jira_integration import JiraIntegration, JiraConfig

# Configure
config = JiraConfig(
    name="jira",
    server_url="https://company.atlassian.net",
    username="john@company.com",
    api_key="ATB...xyz",
    project_key="SEC"
)

# Connect
jira = JiraIntegration(config)
jira.connect()

# Create issue
jira.create_finding_issue(
    title="SQL Injection Found",
    description="Found SQL injection in login form",
    severity="high",
    target="https://app.example.com/login"
)
```

### Example 2: Batch Processing

```python
"""Process multiple findings"""

def batch_create_issues(jira, findings):
    """Create JIRA issues for all findings"""

    results = {
        "created": [],
        "failed": [],
        "duplicates": []
    }

    for finding in findings:
        # Check for duplicate
        existing = jira.search_issues(finding_id=finding["id"])

        if existing.get("issues"):
            results["duplicates"].append(finding["id"])
            continue

        # Create issue
        result = jira.create_finding_issue(
            title=finding["title"],
            description=finding["description"],
            severity=finding["severity"],
            target=finding["target"],
            finding_id=finding["id"],
            cvss_score=finding.get("cvss_score"),
            tags=finding.get("tags", [])
        )

        if result.get("success"):
            results["created"].append(result["issue_key"])
        else:
            results["failed"].append({
                "finding_id": finding["id"],
                "error": result.get("error")
            })

    return results


# Usage
findings = [
    {"id": "V001", "title": "XSS", "severity": "medium", ...},
    {"id": "V002", "title": "SQLi", "severity": "high", ...},
]

results = batch_create_issues(jira, findings)
print(f"Created: {len(results['created'])}")
print(f"Failed: {len(results['failed'])}")
print(f"Duplicates: {len(results['duplicates'])}")
```

### Example 3: Complete Workflow

```python
"""Complete vulnerability management workflow"""

from purplesploit.integrations.jira_integration import JiraIntegration, JiraConfig
import os


class VulnerabilityManager:
    """Manage vulnerabilities in JIRA"""

    def __init__(self):
        config = JiraConfig(
            name="jira",
            server_url=os.getenv("JIRA_SERVER_URL"),
            username=os.getenv("JIRA_USERNAME"),
            api_key=os.getenv("JIRA_API_TOKEN"),
            project_key="SEC",
            issue_type="Security Bug",
            priority_mapping={
                "critical": "Highest",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
                "info": "Lowest"
            },
            labels=["security", "automated", "purplesploit"],
            assignee="security-team"
        )

        self.jira = JiraIntegration(config)
        self.jira.connect()

    def report_vulnerability(self, vuln):
        """Report a new vulnerability"""

        # Search for existing issue
        existing = self.jira.search_issues(
            finding_id=vuln["id"],
            target=vuln["target"]
        )

        if existing.get("issues"):
            issue_key = existing["issues"][0]["key"]
            print(f"Vulnerability already reported: {issue_key}")

            # Add update comment
            self._update_vulnerability(issue_key, vuln)
            return issue_key

        # Create new issue
        result = self.jira.create_finding_issue(
            title=vuln["title"],
            description=vuln["description"],
            severity=vuln["severity"],
            target=vuln["target"],
            finding_id=vuln["id"],
            cvss_score=vuln.get("cvss_score"),
            remediation=vuln.get("remediation"),
            evidence=vuln.get("evidence", []),
            tags=vuln.get("tags", [])
        )

        if result.get("success"):
            issue_key = result["issue_key"]
            print(f"Created issue: {issue_key}")

            # Handle critical vulns
            if vuln["severity"] == "critical":
                self._escalate_critical(issue_key)

            return issue_key
        else:
            print(f"Failed to create issue: {result.get('error')}")
            return None

    def _update_vulnerability(self, issue_key, vuln):
        """Update existing vulnerability"""
        from purplesploit.integrations.base import NotificationPayload

        payload = NotificationPayload(
            title=f"Update: {vuln['title']}",
            message=f"Vulnerability re-detected in scan.\n\nDetails: {vuln['description']}"
        )

        self.jira.send_notification(payload)

    def _escalate_critical(self, issue_key):
        """Escalate critical vulnerabilities"""
        # Move to In Progress
        self.jira.transition_issue(issue_key, "In Progress")
        print(f"Escalated {issue_key} to In Progress")


# Usage
manager = VulnerabilityManager()

vuln = {
    "id": "VULN-2024-001",
    "title": "Remote Code Execution in Upload",
    "description": "Unauthenticated RCE via file upload...",
    "severity": "critical",
    "target": "https://app.example.com/upload",
    "cvss_score": 10.0,
    "remediation": "Implement file type validation...",
    "evidence": ["/tmp/exploit_poc.py"],
    "tags": ["rce", "upload", "unauthenticated"]
}

manager.report_vulnerability(vuln)
```

## Advanced Features

### Issue Search

Find existing issues to avoid duplicates:

```python
# Search by finding ID
results = jira.search_issues(finding_id="VULN-2024-001")

# Search by target
results = jira.search_issues(target="https://app.example.com")

# Custom JQL
results = jira.search_issues(
    jql='project = SEC AND status = Open AND labels = "security"'
)

# Process results
if results.get("success"):
    for issue in results["issues"]:
        print(f"{issue['key']}: {issue['summary']} [{issue['status']}]")
```

### Issue Transitions

Move issues through workflow:

```python
# Get available transitions
result = jira.transition_issue("SEC-123", "In Progress")

if not result.get("success"):
    # Show available transitions
    print(f"Available: {result.get('available')}")

# Common transitions
jira.transition_issue("SEC-123", "In Progress")
jira.transition_issue("SEC-123", "Resolved")
jira.transition_issue("SEC-123", "Closed")
jira.transition_issue("SEC-123", "Reopen")
```

### File Attachments

Attach evidence files:

```python
# Create issue
result = jira.create_finding_issue(
    title="XSS Vulnerability",
    description="XSS found in search",
    severity="medium",
    target="https://example.com"
)

issue_key = result["issue_key"]

# Attach evidence files
jira.attach_file(issue_key, "/path/to/screenshot.png")
jira.attach_file(issue_key, "/path/to/request_log.txt")
jira.attach_file(issue_key, "/path/to/exploit.html")
```

### Issue Updates

Update existing issues with new information:

```python
from purplesploit.integrations.base import NotificationPayload

# Create update payload
payload = NotificationPayload(
    title="Vulnerability Confirmed",
    message="Exploitation confirmed. Data exfiltration is possible.",
    finding_id="VULN-2024-001"  # Links to existing issue
)

# Send update (adds comment)
jira.send_notification(payload)
```

## Troubleshooting

### Common Issues

#### 1. Authentication Failures

```
HTTP 401: Unauthorized
```

**Solutions:**
- Verify username (email) is correct
- Regenerate API token
- Check token hasn't expired
- Verify user has project access

```python
# Test auth
result = jira.test_connection()
if not result.get("success"):
    print(f"Auth failed: {result.get('error')}")
```

#### 2. Project Not Found

```
HTTP 404: Project 'SEC' not found
```

**Solutions:**
- Verify project key is correct
- Check user has project permissions
- Ensure project exists

```bash
# List accessible projects
curl -u email:token \
  https://company.atlassian.net/rest/api/2/project
```

#### 3. Invalid Issue Type

```
Error: Issue type 'Security Bug' not found
```

**Solutions:**
- List available issue types for project
- Use correct issue type name

```python
# Get project details including issue types
# Manual check via JIRA UI: Project Settings > Issue Types
```

#### 4. Custom Field Errors

```
Error: Field 'customfield_10001' not found
```

**Solutions:**
- Verify custom field ID
- Check field is available in project
- Ensure field type matches value format

#### 5. Rate Limiting

```
HTTP 429: Too Many Requests
```

**Solutions:**
- Reduce request rate
- Implement backoff strategy
- Batch operations

```python
config.rate_limit = 30  # Reduce to 30/minute

# Or add delays
import time
time.sleep(2)  # 2 second delay between requests
```

### Debug Mode

```python
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("purplesploit.integrations.jira_integration")
logger.setLevel(logging.DEBUG)

# Detailed logs
jira.create_finding_issue(...)
```

### Verify Configuration

```python
# Test connection
result = jira.test_connection()
print(f"Connected: {result.get('success')}")
print(f"User: {result.get('user')}")
print(f"Email: {result.get('email')}")

# Check status
status = jira.get_status()
print(f"Status: {status}")
```

## Security Best Practices

### Protect API Tokens

```python
# Bad: Hardcoded
api_key = "ATB...xyz123"

# Good: Environment variable
api_key = os.getenv("JIRA_API_TOKEN")

# Better: Secrets manager
from secrets_manager import get_secret
api_key = get_secret("jira/api_token")
```

### Restrict Permissions

Create dedicated service account:
1. Create user: purplesploit@company.com
2. Grant minimum permissions:
   - Project: Create issues, add comments, attach files
   - Browse project
3. Generate API token for service account only

### Audit Trail

Log all JIRA operations:

```python
def create_with_audit(jira, finding):
    """Create issue with audit logging"""

    result = jira.create_finding_issue(**finding)

    # Audit log
    audit_entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": "create_issue",
        "finding_id": finding.get("id"),
        "issue_key": result.get("issue_key"),
        "success": result.get("success")
    }

    with open("audit.log", "a") as f:
        f.write(json.dumps(audit_entry) + "\n")

    return result
```

### Sensitive Data

Avoid including sensitive data in issues:

```python
# Bad: Including actual credentials
description = f"Found password: {actual_password}"

# Good: Redacted
description = "Found hardcoded credential (see attached evidence)"
```

### Network Security

- Use HTTPS for all JIRA communication
- Implement certificate validation
- Use VPN for on-premise JIRA access

```python
# Verify SSL (default: True)
config.verify_ssl = True

# For testing only (not recommended)
config.verify_ssl = False
```

## Conclusion

The JIRA integration provides robust vulnerability tracking and management. Proper configuration ensures security findings are systematically documented, assigned, and remediated through your existing JIRA workflows.

### Key Takeaways

1. Use API tokens for authentication
2. Map priorities and fields appropriately
3. Implement duplicate detection
4. Attach evidence files for validation
5. Use custom fields for additional metadata
6. Follow security best practices
7. Monitor and audit integration activity

### Resources

- JIRA REST API: https://developer.atlassian.com/cloud/jira/platform/rest/v2/
- PurpleSploit docs: `docs/API.md`
- Integration examples: `examples/integrations/jira_example.py`
