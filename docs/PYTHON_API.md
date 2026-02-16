# PurpleSploit Python API Documentation

This document covers the Python programmatic APIs for PurpleSploit, including the Plugin System and Reporting Module.

**Package Version:** 6.8.1

## Table of Contents

- [Plugin System API](#plugin-system-api)
- [Reporting API](#reporting-api)
- [Framework API](#framework-api)

---

## Plugin System API

The Plugin System provides a marketplace-style plugin management system for extending PurpleSploit functionality.

### Plugin Manager

```python
from purplesploit.plugins.manager import PluginManager

# Initialize plugin manager
manager = PluginManager(
    plugins_dir=None,     # Optional: custom plugins directory
    config_dir=None,      # Optional: custom config directory
    framework=None        # Optional: framework reference
)
```

#### Default Directories

- **Plugins:** `~/.purplesploit/plugins/`
- **Config:** `~/.purplesploit/config/`
- **State File:** `~/.purplesploit/config/plugins.json`

### Core Methods

#### Search Plugins

```python
# Search all repositories
plugins = manager.search(
    query="nmap",                    # Search term
    category=PluginCategory.RECON,   # Filter by category (optional)
    tags=["network", "scanner"],     # Filter by tags (optional)
    installed_only=False             # Only show installed (optional)
)
```

#### Get Plugin Information

```python
plugin = manager.get_plugin("custom_scanner")
if plugin:
    print(f"Name: {plugin.name}")
    print(f"Version: {plugin.version}")
    print(f"Status: {plugin.status}")
    print(f"Has Update: {plugin.has_update}")
```

#### Install Plugin

```python
try:
    plugin = manager.install(
        name="custom_scanner",
        version="1.2.0",     # Optional: specific version
        force=False          # Force reinstall
    )
    print(f"Installed {plugin.name} v{plugin.installed_version}")
except ValueError as e:
    print(f"Plugin not found: {e}")
except RuntimeError as e:
    print(f"Installation failed: {e}")
```

#### Update Plugin

```python
try:
    plugin = manager.update(
        name="custom_scanner",
        version=None         # None = latest version
    )
    print(f"Updated to v{plugin.installed_version}")
except ValueError as e:
    print(f"Update failed: {e}")
```

#### Uninstall Plugin

```python
success = manager.uninstall(
    name="custom_scanner",
    keep_config=False        # Keep configuration files
)
```

#### Enable/Disable Plugin

```python
# Disable without uninstalling
manager.disable("custom_scanner")

# Re-enable
manager.enable("custom_scanner")
```

#### List Installed Plugins

```python
installed = manager.list_installed()
for plugin in installed:
    status = "enabled" if plugin.enabled else "disabled"
    print(f"{plugin.name} v{plugin.installed_version} ({status})")
```

#### Check for Updates

```python
updates = manager.check_updates()
for plugin in updates:
    print(f"{plugin.name}: {plugin.installed_version} -> {plugin.latest_version}")
```

#### Get Statistics

```python
stats = manager.get_statistics()
# {
#     "total_installed": 5,
#     "enabled": 4,
#     "disabled": 1,
#     "updates_available": 2,
#     "by_category": {"recon": 2, "network": 3}
# }
```

#### Repository Management

```python
from purplesploit.plugins.repository import PluginRepository, LocalPluginRepository

# Add a custom repository
custom_repo = LocalPluginRepository(
    name="custom",
    path="/path/to/local/plugins"
)
manager.add_repository(custom_repo)

# List repositories
repos = manager.list_repositories()

# Remove repository
manager.remove_repository("custom")
```

### Plugin Categories

```python
from purplesploit.plugins.models import PluginCategory

# Available categories:
PluginCategory.RECON        # Reconnaissance
PluginCategory.NETWORK      # Network testing
PluginCategory.WEB          # Web application
PluginCategory.EXPLOIT      # Exploitation
PluginCategory.POST         # Post-exploitation
PluginCategory.AD           # Active Directory
PluginCategory.OSINT        # Open Source Intelligence
PluginCategory.CLOUD        # Cloud security
PluginCategory.MOBILE       # Mobile testing
PluginCategory.REPORTING    # Reporting tools
PluginCategory.INTEGRATION  # Third-party integrations
PluginCategory.UTILITY      # Utilities
```

### Plugin Status

```python
from purplesploit.plugins.models import PluginStatus

PluginStatus.NOT_INSTALLED
PluginStatus.INSTALLED
PluginStatus.UPDATE_AVAILABLE
PluginStatus.DISABLED
PluginStatus.BROKEN
```

### Creating a Plugin Manifest

Plugins require a `plugin.yaml` manifest file:

```yaml
name: custom_scanner
version: 1.0.0
description: Custom network scanner module
author: Your Name
category: network
tags:
  - scanner
  - network
  - discovery

# Plugin dependencies
dependencies:
  - name: base_scanner
    version_constraint: ">=1.0.0"
    optional: false

# Python pip packages
python_dependencies:
  - requests>=2.28.0
  - scapy>=2.5.0

# System packages (informational)
system_dependencies:
  - nmap

# Module registration
module_path: network/custom_scanner
main_class: CustomScannerModule

# Compatibility
min_framework_version: "2.0.0"
platforms:
  - linux
  - darwin

# Metadata
homepage: https://example.com/plugin
license: MIT
repository: https://github.com/example/plugin
documentation: https://example.com/docs
```

---

## Reporting API

The Reporting API generates professional penetration test reports in multiple formats.

### Report Generator

```python
from purplesploit.reporting.generator import ReportGenerator
from purplesploit.reporting.models import Finding, ReportConfig, Severity

# Initialize generator
generator = ReportGenerator(framework=None)  # Optional framework reference
```

### Creating Findings

```python
# Method 1: Using create_finding helper
finding = generator.create_finding(
    title="SQL Injection in Login Form",
    severity="critical",
    description="The login form is vulnerable to SQL injection...",
    target="192.168.1.100",
    cvss_score=9.8,
    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    cve_ids=["CVE-2024-1234"],
    cwe_ids=["CWE-89"],
    impact="Complete database compromise",
    remediation="Use parameterized queries",
    references=["https://owasp.org/injection"],
    port=443,
    service="https",
    module_name="web/sqlmap"
)

# Method 2: Direct Finding creation
from purplesploit.reporting.models import Finding, Evidence

finding = Finding(
    id="FIND-001",
    title="Weak SSH Configuration",
    severity=Severity.HIGH,
    description="SSH server allows weak cipher suites",
    target="10.10.10.50",
    port=22,
    service="ssh"
)

# Add evidence
evidence = Evidence(
    id="EV-001",
    finding_id="FIND-001",
    file_type="log",
    description="SSH audit output",
    content="[SSH audit log content]"
)
finding.add_evidence(evidence)

generator.add_finding(finding)
```

### Managing Findings

```python
# Add single finding
generator.add_finding(finding)

# Add multiple findings
generator.add_findings([finding1, finding2, finding3])

# Clear all findings
generator.clear_findings()

# Get summary
summary = generator.get_summary()
# {
#     "total_findings": 15,
#     "severity_counts": {"critical": 2, "high": 5, ...},
#     "unique_targets": 8,
#     "critical_count": 2,
#     "high_count": 5,
#     "findings_by_target": {"192.168.1.100": 3, ...}
# }
```

### Report Configuration

```python
from purplesploit.reporting.models import ReportConfig, Severity, FindingStatus
from datetime import datetime

config = ReportConfig(
    # Metadata
    title="Penetration Test Report",
    subtitle="Q1 2024 Security Assessment",
    client_name="Acme Corp",
    assessor_name="Security Team",
    assessment_type="External Penetration Test",

    # Date range
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 1, 15),

    # Scope
    scope=["192.168.1.0/24", "webapp.acme.com"],
    out_of_scope=["192.168.1.1"],

    # Report sections
    include_executive_summary=True,
    include_methodology=True,
    include_findings_detail=True,
    include_evidence=True,
    include_appendix=True,
    include_raw_output=False,

    # Filtering
    min_severity=Severity.LOW,  # Exclude INFO findings
    statuses_to_include=[
        FindingStatus.CONFIRMED,
        FindingStatus.REPORTED
    ],

    # Branding
    logo_path="/path/to/logo.png",
    company_name="Security Consultants Inc",
    company_website="https://securityconsultants.com",

    # Output
    output_dir="./reports",
    filename_prefix="acme_pentest"
)

generator.set_config(config)
```

### Generating Reports

```python
# Generate in specific format
report_path = generator.generate(
    format="pdf",                    # pdf, html, xlsx, markdown, json
    output_path="./report.pdf"       # Optional custom path
)

print(f"Report generated: {report_path}")
```

#### Supported Formats

| Format | Description | Use Case |
|--------|-------------|----------|
| `pdf` | Professional PDF document | Client deliverable |
| `html` | Interactive HTML report | Web viewing |
| `xlsx` | Excel spreadsheet | Data analysis |
| `markdown` | Markdown document | Git/wiki integration |
| `json` | JSON data export | Automation/integration |

### Import/Export Findings

```python
# Save findings to JSON
generator.save_findings_to_json("findings.json")

# Load findings from JSON
generator.load_findings_from_json("findings.json")
```

### Import from Module Results

```python
# After running a module
result = framework.run_module(module)

# Import finding from result
finding = generator.import_from_module_result(
    module_name="web/sqlmap",
    result=result,
    target="192.168.1.100",
    auto_severity="medium"  # Default if not detected
)
```

### Quick Report Generation

```python
from purplesploit.reporting.generator import quick_report

# Generate report from finding dictionaries
report_path = quick_report(
    findings=[
        {
            "title": "Open SSH Port",
            "severity": "low",
            "description": "SSH service exposed",
            "target": "10.10.10.5"
        },
        {
            "title": "Anonymous FTP",
            "severity": "high",
            "description": "FTP allows anonymous access",
            "target": "10.10.10.5",
            "port": 21
        }
    ],
    output_path="quick_report.html",
    format="html",
    title="Quick Assessment Report",
    client_name="Test Client"
)
```

### Severity Levels

```python
from purplesploit.reporting.models import Severity

# Severity values
Severity.CRITICAL  # CVSS 9.0-10.0
Severity.HIGH      # CVSS 7.0-8.9
Severity.MEDIUM    # CVSS 4.0-6.9
Severity.LOW       # CVSS 0.1-3.9
Severity.INFO      # CVSS 0.0

# Get severity from CVSS score
severity = Severity.from_cvss(8.5)  # Returns Severity.HIGH

# Get color for display
color = Severity.HIGH.color  # Returns "#c0392b"

# Get CVSS range
low, high = Severity.HIGH.cvss_range  # Returns (7.0, 8.9)
```

### Finding Status

```python
from purplesploit.reporting.models import FindingStatus

FindingStatus.DRAFT           # Initial state
FindingStatus.CONFIRMED       # Verified by assessor
FindingStatus.REPORTED        # Included in report
FindingStatus.REMEDIATED      # Fixed by client
FindingStatus.VERIFIED        # Fix verified
FindingStatus.FALSE_POSITIVE  # Not a real issue

# Update finding status
finding.confirm()           # Set to CONFIRMED
finding.mark_remediated()   # Set to REMEDIATED
```

---

## Framework API

Basic framework interaction for module execution.

### Initialization

```python
from purplesploit.core.framework import Framework

# Initialize framework
framework = Framework(db_path="~/.purplesploit/purplesploit.db")

# Discover available modules
module_count = framework.discover_modules()
print(f"Discovered {module_count} modules")
```

### Module Operations

```python
# List all modules
modules = framework.list_modules(category="recon")  # Optional filter

# Search modules
results = framework.search_modules("nmap")

# Get module metadata
metadata = framework.get_module("recon/nmap")

# Load and use module
module = framework.use_module("recon/nmap")

# Set options
module.set_option("RHOST", "192.168.1.100")
module.set_option("PORTS", "1-1000")

# Show options
options = module.show_options()

# Run module
results = framework.run_module(module)
```

### Target Management

```python
# Add target
framework.add_target("server1", "network", "192.168.1.100")

# Session targets
targets = framework.session.targets.list()
current = framework.session.targets.get_current()
```

### Credential Management

```python
# Add credential
framework.add_credential("admin", "P@ssw0rd!")

# Session credentials
creds = framework.session.credentials.list()
```

### Statistics

```python
stats = framework.get_stats()
# {
#     "modules": 45,
#     "categories": 8,
#     "targets": 10,
#     "credentials": 5,
#     "current_module": "recon/nmap"
# }
```

---

## See Also

- [API.md](./API.md) - REST API documentation
- [CONTRIBUTING.md](./CONTRIBUTING.md) - Module development guide
- [DISCLAIMER.md](./DISCLAIMER.md) - Legal disclaimer
