# SIEM Integration Guide

Comprehensive guide for integrating PurpleSploit with Security Information and Event Management (SIEM) platforms including Splunk, Elasticsearch, and generic SIEM systems.

## Table of Contents

- [Overview](#overview)
- [Supported SIEM Platforms](#supported-siem-platforms)
- [Generic SIEM Webhook](#generic-siem-webhook)
- [Splunk Integration](#splunk-integration)
- [Elasticsearch Integration](#elasticsearch-integration)
- [Event Formats](#event-formats)
- [Event Types](#event-types)
- [Configuration Examples](#configuration-examples)
- [Event Correlation](#event-correlation)
- [Advanced Features](#advanced-features)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)

## Overview

SIEM integrations enable PurpleSploit to send security findings and scan events to your SIEM platform for centralized logging, correlation, alerting, and long-term analysis.

### Benefits

- Centralized security event logging
- Correlation with other security data
- Long-term data retention and analysis
- Automated alerting and response
- Compliance and audit trails
- Dashboard and visualization

### Architecture

```
PurpleSploit
    |
    v
SIEM Integration Module
    |
    +-- Generic Webhook --> Any SIEM (HTTP POST)
    +-- Splunk HEC -------> Splunk
    +-- Elasticsearch ----> Elastic Stack
    |
    v
SIEM Platform (Indexed Events)
    |
    v
Dashboards, Alerts, Reports
```

## Supported SIEM Platforms

### Built-in Support

1. **Generic SIEM Webhook** - Any SIEM accepting HTTP POST with JSON
2. **Splunk HTTP Event Collector (HEC)** - Native Splunk integration
3. **Elasticsearch** - Direct indexing to Elasticsearch

### Compatible SIEMs

These work with the Generic Webhook integration:

- **QRadar** - IBM Security QRadar
- **ArcSight** - Micro Focus ArcSight
- **Sentinel** - Microsoft Azure Sentinel
- **LogRhythm** - LogRhythm SIEM
- **AlienVault** - AT&T Cybersecurity USM
- **Elastic SIEM** - Via Elasticsearch integration
- **Graylog** - Open source log management
- **Any HTTP-based collector**

## Generic SIEM Webhook

### Overview

The generic webhook integration sends JSON-formatted events to any HTTP endpoint. This works with most SIEM platforms that accept HTTP input.

### Basic Configuration

```python
from purplesploit.integrations.siem import SIEMWebhook, SIEMConfig

# Configure
config = SIEMConfig(
    name="siem_webhook",
    webhook_url="https://siem.company.com/api/events",
    source_type="purplesploit",
    index="security",
    verify_ssl=True
)

# Initialize
siem = SIEMWebhook(config)

# Connect
if siem.connect():
    print("SIEM webhook ready")
```

### Custom Headers

Add authentication headers:

```python
config = SIEMConfig(
    name="siem",
    webhook_url="https://siem.company.com/api/events",
    custom_headers={
        "Authorization": "Bearer your-token-here",
        "X-API-Key": "your-api-key",
        "X-Source": "purplesploit"
    }
)
```

### Send Events

```python
# Send finding
result = siem.send_finding(
    title="SQL Injection Detected",
    description="SQL injection in login form",
    severity="high",
    target="https://app.example.com/login",
    finding_id="VULN-2024-001",
    cvss_score=8.5,
    tags=["injection", "sqli", "web"]
)

if result.get("success"):
    print(f"Event sent: {result.get('status_code')}")
```

### Event Format

Events are sent as JSON:

```json
{
  "event_type": "security_finding",
  "source": "purplesploit",
  "sourcetype": "purplesploit",
  "timestamp": "2024-01-15T14:30:00.000000",
  "title": "SQL Injection Detected",
  "message": "SQL injection in login form",
  "severity": "high",
  "priority": "high",
  "target": "https://app.example.com/login",
  "finding_id": "VULN-2024-001",
  "cvss_score": 8.5,
  "tags": ["injection", "sqli", "web"],
  "extra_data": {}
}
```

### Configuration Options

```python
@dataclass
class SIEMConfig(IntegrationConfig):
    """SIEM configuration"""

    webhook_url: str = ""              # SIEM webhook/collector URL
    source_type: str = "purplesploit"  # Source type identifier
    index: str = "security"            # Index/destination
    verify_ssl: bool = True            # Verify SSL certificates
    custom_headers: Dict[str, str] = {}  # Custom HTTP headers

    # Inherited from IntegrationConfig
    timeout: int = 30                  # Request timeout (seconds)
    rate_limit: int = 60               # Max requests per minute
    retry_count: int = 3               # Retry failed requests
```

## Splunk Integration

### Overview

Native Splunk integration using HTTP Event Collector (HEC) with proper event formatting and batching support.

### Splunk HEC Setup

#### Step 1: Enable HEC

1. Log into Splunk Web
2. Navigate to Settings > Data Inputs > HTTP Event Collector
3. Click "Global Settings"
4. Enable "All tokens"
5. Set "HTTP Port Number" (default: 8088)
6. Save

#### Step 2: Create HEC Token

1. Click "New Token"
2. Name: "PurpleSploit Integration"
3. Source type: "purplesploit" (or create custom)
4. Select allowed indexes (e.g., "security")
5. Review and Submit
6. Copy the Token Value

#### Step 3: Get HEC URL

```
Format: https://<splunk-host>:8088/services/collector
Example: https://splunk.company.com:8088/services/collector
```

### Basic Configuration

```python
from purplesploit.integrations.siem import SplunkIntegration, SplunkConfig

# Configure
config = SplunkConfig(
    name="splunk",
    hec_token="12345678-1234-1234-1234-123456789012",
    hec_url="https://splunk.company.com:8088/services/collector",
    index="security",
    source_type="purplesploit",
    verify_ssl=True
)

# Initialize
splunk = SplunkIntegration(config)

# Connect and test
if splunk.connect():
    print("Splunk HEC connected")
    result = splunk.test_connection()
    print(f"Status: {result.get('status')}")
```

### Send Events

```python
# Single event
result = splunk.send_finding(
    title="XSS Vulnerability",
    description="Reflected XSS in search parameter",
    severity="medium",
    target="https://app.example.com/search",
    cvss_score=6.1,
    tags=["xss", "web"]
)

# Batch events (more efficient)
from purplesploit.integrations.base import NotificationPayload

events = [
    NotificationPayload(
        title="Finding 1",
        message="Description 1",
        severity="high",
        target="target1"
    ),
    NotificationPayload(
        title="Finding 2",
        message="Description 2",
        severity="medium",
        target="target2"
    )
]

result = splunk.send_batch(events)
print(f"Sent {result.get('events_sent')} events")
```

### Splunk Event Format

Events are sent in HEC format:

```json
{
  "event": {
    "event_type": "security_finding",
    "source": "purplesploit",
    "sourcetype": "purplesploit",
    "timestamp": "2024-01-15T14:30:00.000000",
    "title": "SQL Injection Detected",
    "message": "SQL injection in login form",
    "severity": "high",
    "priority": "high",
    "target": "https://app.example.com/login",
    "finding_id": "VULN-2024-001",
    "cvss_score": 8.5,
    "tags": ["injection", "sqli", "web"]
  },
  "sourcetype": "purplesploit",
  "index": "security",
  "time": 1705329000.0
}
```

### Splunk Queries

Search for PurpleSploit events:

```spl
# All PurpleSploit events
index=security sourcetype=purplesploit

# Critical findings only
index=security sourcetype=purplesploit severity=critical

# Recent findings (last 24h)
index=security sourcetype=purplesploit earliest=-24h

# Findings by target
index=security sourcetype=purplesploit
| stats count by target, severity

# Timeline
index=security sourcetype=purplesploit
| timechart count by severity

# CVSS >= 7.0
index=security sourcetype=purplesploit cvss_score>=7.0
```

### Splunk Dashboard

Create a dashboard to visualize findings:

```xml
<dashboard>
  <label>PurpleSploit Security Findings</label>
  <row>
    <panel>
      <title>Findings by Severity</title>
      <chart>
        <search>
          <query>index=security sourcetype=purplesploit | stats count by severity</query>
        </search>
        <option name="charting.chart">pie</option>
      </chart>
    </panel>
  </row>
  <row>
    <panel>
      <title>Recent Critical Findings</title>
      <table>
        <search>
          <query>index=security sourcetype=purplesploit severity=critical | table _time title target cvss_score</query>
        </search>
      </table>
    </panel>
  </row>
</dashboard>
```

## Elasticsearch Integration

### Overview

Direct integration with Elasticsearch for indexing security events. Works with Elasticsearch Cloud and self-hosted instances.

### Elasticsearch Setup

#### Prerequisites

- Elasticsearch cluster (7.x, 8.x)
- API key or basic auth credentials
- Network access to Elasticsearch

#### Create API Key

```bash
# Using Elasticsearch API
curl -X POST "http://localhost:9200/_security/api_key" \
  -H "Content-Type: application/json" \
  -u elastic:password \
  -d '{
    "name": "purplesploit-integration",
    "role_descriptors": {
      "purplesploit_writer": {
        "cluster": ["monitor"],
        "index": [
          {
            "names": ["purplesploit-*"],
            "privileges": ["create_index", "write", "read"]
          }
        ]
      }
    }
  }'

# Response contains:
# "id": "key_id"
# "api_key": "key_secret"
```

### Basic Configuration

```python
from purplesploit.integrations.siem import ElasticIntegration, ElasticConfig

# Configure
config = ElasticConfig(
    name="elasticsearch",
    webhook_url="http://localhost:9200",  # Elasticsearch URL
    api_key_id="key_id",
    api_key_secret="key_secret",
    index_pattern="purplesploit-findings",  # Creates daily indices
    verify_ssl=True
)

# Initialize
elastic = ElasticIntegration(config)

# Connect
if elastic.connect():
    result = elastic.test_connection()
    print(f"Connected to: {result.get('cluster_name')}")
    print(f"Version: {result.get('version')}")
```

### Send Events

```python
# Single event
result = elastic.send_finding(
    title="Authentication Bypass",
    description="Authentication can be bypassed using parameter tampering",
    severity="critical",
    target="https://api.example.com/auth",
    cvss_score=9.1,
    tags=["authentication", "bypass", "api"]
)

if result.get("success"):
    print(f"Indexed to: {result.get('index')}")
    print(f"Document ID: {result.get('id')}")

# Bulk events (more efficient)
events = [...]  # List of NotificationPayload
result = elastic.send_bulk(events)
print(f"Indexed {result.get('events_sent')} events")
```

### Index Pattern

Events are indexed to daily indices:

```
purplesploit-findings-2024.01.15
purplesploit-findings-2024.01.16
purplesploit-findings-2024.01.17
```

### Document Structure

```json
{
  "@timestamp": "2024-01-15T14:30:00.000000",
  "event_type": "security_finding",
  "source": "purplesploit",
  "sourcetype": "purplesploit",
  "title": "SQL Injection Detected",
  "message": "SQL injection in login form",
  "severity": "high",
  "priority": "high",
  "target": "https://app.example.com/login",
  "finding_id": "VULN-2024-001",
  "cvss_score": 8.5,
  "tags": ["injection", "sqli", "web"],
  "extra_data": {}
}
```

### Search Findings

```python
# Search for findings
results = elastic.search_findings(
    query="sql injection",
    severity="high",
    from_date=datetime(2024, 1, 1),
    size=50
)

if results.get("success"):
    print(f"Found {results.get('total')} findings")

    for finding in results.get("findings", []):
        print(f"- {finding['title']} [{finding['severity']}]")
```

### Elasticsearch Queries

```json
# Get all critical findings
GET purplesploit-*/_search
{
  "query": {
    "term": {
      "severity": "critical"
    }
  }
}

# Findings in last 24 hours
GET purplesploit-*/_search
{
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  }
}

# CVSS >= 7.0
GET purplesploit-*/_search
{
  "query": {
    "range": {
      "cvss_score": {
        "gte": 7.0
      }
    }
  }
}

# Aggregation by severity
GET purplesploit-*/_search
{
  "size": 0,
  "aggs": {
    "by_severity": {
      "terms": {
        "field": "severity.keyword"
      }
    }
  }
}
```

### Kibana Dashboard

Create visualizations in Kibana:

1. **Index Pattern**: Create `purplesploit-*` index pattern
2. **Discover**: Explore findings data
3. **Visualizations**:
   - Pie chart: Findings by severity
   - Line chart: Findings over time
   - Data table: Recent critical findings
   - Metric: Total CVSS score
4. **Dashboard**: Combine visualizations

## Event Formats

### Security Finding Event

```json
{
  "event_type": "security_finding",
  "source": "purplesploit",
  "sourcetype": "purplesploit",
  "timestamp": "2024-01-15T14:30:00.000000",
  "title": "SQL Injection in Login Form",
  "message": "Detailed description of the finding...",
  "severity": "high",
  "priority": "high",
  "target": "https://app.example.com/login",
  "finding_id": "VULN-2024-001",
  "cvss_score": 8.5,
  "tags": ["injection", "sqli", "web", "authentication"],
  "extra_data": {
    "cwe": "CWE-89",
    "owasp": "A1:2021-Injection",
    "payload": "' OR '1'='1",
    "remediation": "Use parameterized queries"
  }
}
```

### Scan Lifecycle Event

```json
{
  "event_type": "scan_started",
  "source": "purplesploit",
  "sourcetype": "purplesploit",
  "timestamp": "2024-01-15T14:00:00.000000",
  "scan_name": "Full Application Scan",
  "target": "https://app.example.com",
  "status": "running",
  "details": {
    "modules": ["web", "api", "network"],
    "estimated_duration": "2 hours",
    "scan_id": "SCAN-2024-001"
  }
}
```

### Scan Complete Event

```json
{
  "event_type": "scan_completed",
  "source": "purplesploit",
  "sourcetype": "purplesploit",
  "timestamp": "2024-01-15T16:00:00.000000",
  "scan_name": "Full Application Scan",
  "target": "https://app.example.com",
  "status": "completed",
  "details": {
    "duration_seconds": 7200,
    "findings_count": 15,
    "critical_count": 2,
    "high_count": 5,
    "medium_count": 6,
    "low_count": 2,
    "scan_id": "SCAN-2024-001"
  }
}
```

## Event Types

### 1. Security Findings

Vulnerability discoveries:

```python
siem.send_finding(
    title="XSS Vulnerability",
    description="Reflected XSS in search",
    severity="medium",
    target="https://app.example.com/search",
    cvss_score=6.1,
    tags=["xss", "web"]
)
```

### 2. Scan Events

Scan lifecycle tracking:

```python
# Scan started
siem.send_scan_event(
    event_type="scan_started",
    scan_name="Nmap Full Scan",
    target="192.168.1.0/24",
    status="running",
    details={"modules": ["nmap"], "scan_id": "SCAN-001"}
)

# Scan completed
siem.send_scan_event(
    event_type="scan_completed",
    scan_name="Nmap Full Scan",
    target="192.168.1.0/24",
    status="completed",
    details={
        "duration": 3600,
        "hosts_found": 45,
        "services_found": 127
    }
)

# Scan failed
siem.send_scan_event(
    event_type="scan_failed",
    scan_name="Web Scan",
    target="https://app.example.com",
    status="failed",
    details={"error": "Connection timeout"}
)
```

### 3. Custom Events

Application-specific events:

```python
from purplesploit.integrations.base import NotificationPayload

payload = NotificationPayload(
    title="Credential Discovered",
    message="Found AWS credentials in source code",
    severity="high",
    target="https://github.com/company/repo",
    tags=["credential", "leak", "aws"],
    extra_data={
        "credential_type": "aws_access_key",
        "location": "config/settings.py:15",
        "repository": "company/webapp"
    }
)

siem.send_notification(payload)
```

## Configuration Examples

### Example 1: QRadar Integration

```python
# QRadar via generic webhook
config = SIEMConfig(
    name="qradar",
    webhook_url="https://qradar.company.com/api/forensics/capture/logfile",
    custom_headers={
        "SEC": "your-qradar-token",
        "Content-Type": "application/json"
    },
    source_type="purplesploit",
    verify_ssl=True
)

siem = SIEMWebhook(config)
```

### Example 2: Azure Sentinel

```python
# Azure Sentinel via Log Analytics
import hashlib
import hmac
import base64
from datetime import datetime

def build_signature(customer_id, shared_key, date, content_length):
    """Build Azure Sentinel signature"""
    x_headers = f"x-ms-date:{date}"
    string_to_hash = f"POST\n{content_length}\napplication/json\n{x_headers}\n/api/logs"
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    return f"SharedKey {customer_id}:{encoded_hash}"

# Configuration
customer_id = "your-workspace-id"
shared_key = "your-shared-key"
log_type = "PurpleSploitFindings"

rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')

config = SIEMConfig(
    name="sentinel",
    webhook_url=f"https://{customer_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
    custom_headers={
        "Authorization": build_signature(customer_id, shared_key, rfc1123date, 0),
        "Log-Type": log_type,
        "x-ms-date": rfc1123date,
        "time-generated-field": "timestamp"
    }
)

siem = SIEMWebhook(config)
```

### Example 3: Graylog

```python
# Graylog via GELF HTTP
config = SIEMConfig(
    name="graylog",
    webhook_url="http://graylog.company.com:12201/gelf",
    source_type="purplesploit",
    verify_ssl=False  # If using HTTP
)

siem = SIEMWebhook(config)
```

## Event Correlation

### Correlate with Scan Data

```python
# Send scan start
siem.send_scan_event(
    event_type="scan_started",
    scan_name="Full Scan",
    target="app.example.com",
    status="running",
    details={"scan_id": "SCAN-001"}
)

# Send findings with scan ID
for finding in findings:
    finding["extra_data"]["scan_id"] = "SCAN-001"
    siem.send_finding(**finding)

# Send scan complete
siem.send_scan_event(
    event_type="scan_completed",
    scan_name="Full Scan",
    target="app.example.com",
    status="completed",
    details={"scan_id": "SCAN-001", "findings_count": len(findings)}
)
```

### Correlate with Attack Surface

```python
# Add asset context
finding["extra_data"]["asset_criticality"] = "high"
finding["extra_data"]["asset_owner"] = "platform-team"
finding["extra_data"]["environment"] = "production"

siem.send_finding(**finding)
```

### Correlate with Remediation

```python
# Send finding
result = siem.send_finding(title="XSS", ...)

# Send remediation event
remediation_event = NotificationPayload(
    title="Remediation Started",
    message="XSS vulnerability remediation in progress",
    extra_data={
        "finding_id": "VULN-001",
        "jira_ticket": "SEC-123",
        "assigned_to": "dev-team",
        "eta": "2024-01-20"
    }
)

siem.send_notification(remediation_event)
```

## Advanced Features

### Batch Processing

```python
# Collect events
events = []

for finding in findings_list:
    payload = NotificationPayload(
        title=finding["title"],
        message=finding["description"],
        severity=finding["severity"],
        target=finding["target"]
    )
    events.append(payload)

# Send batch (Splunk and Elasticsearch support batching)
if isinstance(siem, SplunkIntegration):
    result = siem.send_batch(events)
elif isinstance(siem, ElasticIntegration):
    result = siem.send_bulk(events)

print(f"Sent {result.get('events_sent')} events")
```

### Error Handling

```python
def send_with_retry(siem, payload, max_retries=3):
    """Send event with retry logic"""
    for attempt in range(max_retries):
        result = siem.send_notification(payload)

        if result.get("success"):
            return result

        error = result.get("error", "")

        if "Rate limited" in error:
            wait_time = 60 * (attempt + 1)
            print(f"Rate limited, waiting {wait_time}s...")
            time.sleep(wait_time)
        elif "503" in error or "504" in error:
            # Service unavailable, retry
            time.sleep(5)
        else:
            # Other error, don't retry
            break

    return result
```

### Health Monitoring

```python
def monitor_siem_health(siem):
    """Monitor SIEM integration health"""
    status = siem.get_status()

    if status["status"] != "connected":
        # Alert on disconnection
        send_alert(f"SIEM integration down: {status['error']}")

    if status["request_count"] > 50:
        # Warn on high volume
        send_alert(f"High SIEM traffic: {status['request_count']} req/min")

    # Test connection periodically
    test_result = siem.test_connection()
    if not test_result.get("success"):
        send_alert(f"SIEM health check failed: {test_result.get('error')}")
```

## Troubleshooting

### Common Issues

#### 1. Connection Refused

```
Error: Connection refused
```

**Solutions:**
- Verify SIEM URL is correct
- Check network connectivity
- Verify firewall rules
- Check SIEM service is running

#### 2. Authentication Failed

```
HTTP 401: Unauthorized
```

**Solutions:**
- Verify API key/token is correct
- Check token hasn't expired
- Verify user has permissions
- For Splunk: Check HEC is enabled

#### 3. SSL Certificate Error

```
SSL: CERTIFICATE_VERIFY_FAILED
```

**Solutions:**
- Verify SSL certificate is valid
- For self-signed certs: Set `verify_ssl=False` (not recommended for production)
- Add CA certificate to trust store

```python
# Temporary workaround (testing only)
config.verify_ssl = False
```

#### 4. Rate Limiting

```
HTTP 429: Too Many Requests
```

**Solutions:**
- Reduce rate_limit in config
- Implement batching
- Add delays between requests

```python
config.rate_limit = 30  # 30 requests per minute
```

#### 5. Index Not Found (Elasticsearch)

```
Error: index_not_found_exception
```

**Solutions:**
- Index is created automatically on first write
- Verify permissions to create indices
- Check index pattern matches

### Debug Mode

```python
import logging

logging.basicConfig(level=logging.DEBUG)

# Enable debug logging
logger = logging.getLogger("purplesploit.integrations.siem")
logger.setLevel(logging.DEBUG)

# See detailed request/response logs
siem.send_finding(...)
```

### Test Configuration

```python
# Test connection
result = siem.test_connection()
print(f"Success: {result.get('success')}")
print(f"Details: {result}")

# Check integration status
status = siem.get_status()
print(f"Status: {status['status']}")
print(f"Requests: {status['request_count']}")
```

## Security Considerations

### Protect Credentials

```python
# Bad: Hardcoded
api_key = "secret-key"

# Good: Environment variables
api_key = os.getenv("SIEM_API_KEY")

# Better: Secrets manager
from secrets_manager import get_secret
api_key = get_secret("siem/api_key")
```

### Network Security

- Use HTTPS for all communication
- Implement certificate validation
- Use VPN for on-premise SIEM access
- Implement IP allowlisting

```python
# Always verify SSL in production
config.verify_ssl = True
```

### Data Minimization

Avoid sending sensitive data to SIEM:

```python
# Bad: Sending actual passwords
description = f"Found password: {actual_password}"

# Good: Redacting sensitive data
description = "Found hardcoded credential (redacted)"
```

### Access Control

- Use dedicated service accounts
- Grant minimum necessary permissions
- Rotate API keys regularly
- Monitor integration logs

### Audit Logging

Log all SIEM events:

```python
def send_with_audit(siem, payload):
    """Send event with audit logging"""
    result = siem.send_notification(payload)

    audit = {
        "timestamp": datetime.utcnow().isoformat(),
        "integration": siem.name,
        "event_type": payload.title,
        "severity": payload.severity,
        "success": result.get("success")
    }

    with open("siem_audit.log", "a") as f:
        f.write(json.dumps(audit) + "\n")

    return result
```

## Complete Example

```python
"""
Complete SIEM integration example
"""

import os
from purplesploit.integrations.siem import (
    SplunkIntegration,
    ElasticIntegration,
    SplunkConfig,
    ElasticConfig
)
from purplesploit.integrations.base import NotificationPayload


class SIEMManager:
    """Manage multiple SIEM integrations"""

    def __init__(self):
        self.integrations = []

        # Add Splunk
        splunk_config = SplunkConfig(
            name="splunk",
            hec_token=os.getenv("SPLUNK_HEC_TOKEN"),
            hec_url=os.getenv("SPLUNK_HEC_URL"),
            index="security",
            source_type="purplesploit"
        )
        splunk = SplunkIntegration(splunk_config)
        if splunk.connect():
            self.integrations.append(splunk)

        # Add Elasticsearch
        elastic_config = ElasticConfig(
            name="elasticsearch",
            webhook_url=os.getenv("ELASTIC_URL"),
            api_key_id=os.getenv("ELASTIC_KEY_ID"),
            api_key_secret=os.getenv("ELASTIC_KEY_SECRET"),
            index_pattern="purplesploit-findings"
        )
        elastic = ElasticIntegration(elastic_config)
        if elastic.connect():
            self.integrations.append(elastic)

    def send_finding(self, finding):
        """Send finding to all SIEMs"""
        results = []

        for siem in self.integrations:
            result = siem.send_finding(
                title=finding["title"],
                description=finding["description"],
                severity=finding["severity"],
                target=finding["target"],
                finding_id=finding.get("id"),
                cvss_score=finding.get("cvss_score"),
                tags=finding.get("tags", [])
            )

            results.append({
                "siem": siem.name,
                "success": result.get("success"),
                "error": result.get("error")
            })

        return results

    def send_scan_lifecycle(self, event_type, scan_name, target, details):
        """Send scan lifecycle event to all SIEMs"""
        for siem in self.integrations:
            siem.send_scan_event(
                event_type=event_type,
                scan_name=scan_name,
                target=target,
                status=details.get("status", "running"),
                details=details
            )


def main():
    """Main workflow"""
    # Initialize SIEM manager
    manager = SIEMManager()

    # Send scan start
    manager.send_scan_lifecycle(
        event_type="scan_started",
        scan_name="Full Application Scan",
        target="https://app.example.com",
        details={"scan_id": "SCAN-001", "modules": ["web", "api"]}
    )

    # Send findings
    findings = [
        {
            "id": "VULN-001",
            "title": "SQL Injection",
            "description": "SQL injection in login",
            "severity": "high",
            "target": "https://app.example.com/login",
            "cvss_score": 8.5,
            "tags": ["injection", "sqli"]
        }
    ]

    for finding in findings:
        results = manager.send_finding(finding)
        for result in results:
            print(f"{result['siem']}: {'Success' if result['success'] else 'Failed'}")

    # Send scan complete
    manager.send_scan_lifecycle(
        event_type="scan_completed",
        scan_name="Full Application Scan",
        target="https://app.example.com",
        details={
            "scan_id": "SCAN-001",
            "status": "completed",
            "findings_count": len(findings)
        }
    )


if __name__ == "__main__":
    main()
```

## Conclusion

SIEM integrations provide centralized visibility into security findings and enable correlation with broader security data. Proper configuration ensures your security operations team has the data needed for effective monitoring and response.

### Key Takeaways

1. Choose appropriate integration (Generic, Splunk, Elasticsearch)
2. Configure authentication and endpoints correctly
3. Use structured event formats
4. Implement event correlation
5. Leverage batching for performance
6. Monitor integration health
7. Follow security best practices

### Resources

- Splunk HEC: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector
- Elasticsearch API: https://www.elastic.co/guide/en/elasticsearch/reference/current/docs-index_.html
- PurpleSploit docs: `docs/API.md`
