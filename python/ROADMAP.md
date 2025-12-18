# PurpleSploit Roadmap: Next-Level Features

## Overview

This roadmap outlines the strategic direction for taking PurpleSploit from a solid pentesting framework to an industry-leading offensive security platform. The improvements focus on three pillars:

1. **Professional Deliverables** - Client-facing reporting and evidence management
2. **Automation & Intelligence** - AI-driven recommendations and workflow automation
3. **Integration & Scale** - External tool integration and distributed architecture

---

## Current State Assessment

### Strengths
- **40 modules** across 10 categories (recon, network, web, SMB, AD, impacket, deploy, AI, c2, utility)
- **Context persistence** across module switches (key differentiator from Metasploit)
- **Dual interface** - CLI + FastAPI web server with real-time sync
- **Comprehensive test suite** - 1758 tests passing
- **Modern Python codebase** - Clean architecture with separation of concerns

### Gaps
- No professional reporting output (PDF/HTML)
- Limited OSINT/passive reconnaissance
- AI capabilities underutilized
- No vulnerability scanning integration (Nuclei)
- Manual workflow orchestration

---

## Phase 1: Core Capabilities (Weeks 1-2)

### 1.1 Professional Reporting Module
**Priority: HIGHEST** | **Effort: 3 days**

Create comprehensive reporting capabilities for client deliverables.

**Features:**
- PDF report generation with executive summary
- HTML interactive report with filtering/search
- XLSX export with pivot tables for metrics
- Markdown export for GitHub/wiki
- CVSS v3.1 scoring with evidence
- Customizable report templates
- Screenshot/evidence attachment support

**Files to create:**
- `purplesploit/reporting/generator.py` - Core report generation
- `purplesploit/reporting/templates/` - Report templates (Jinja2)
- `purplesploit/reporting/pdf.py` - PDF generation (WeasyPrint)
- `purplesploit/reporting/html.py` - HTML generation
- `purplesploit/reporting/xlsx.py` - Excel generation (openpyxl)

**CLI Commands:**
```
report generate pdf <output_path>
report generate html <output_path>
report generate xlsx <output_path>
report template list
report template use <template_name>
```

### 1.2 Nuclei Integration Module
**Priority: HIGHEST** | **Effort: 2 days**

Integrate Nuclei for template-based vulnerability scanning.

**Features:**
- Run Nuclei scans with 8000+ community templates
- Filter templates by severity, type, tags
- Auto-import findings to database
- Support for custom templates
- Background scanning with progress tracking

**Files to create:**
- `purplesploit/modules/recon/nuclei.py` - Nuclei module

**Operations:**
1. Full Scan - All templates
2. Critical/High Only - Severity filter
3. CVE Scan - Known CVEs only
4. Technology Scan - Tech-specific templates
5. Custom Templates - User-provided templates
6. Exposed Panels - Admin panel detection
7. Takeover Detection - Subdomain takeover

### 1.3 OSINT Modules
**Priority: HIGH** | **Effort: 3 days**

Passive reconnaissance modules for early-stage intelligence.

**Modules to create:**
- `purplesploit/modules/osint/shodan.py` - Shodan API integration
- `purplesploit/modules/osint/censys.py` - Censys API integration
- `purplesploit/modules/osint/dnsdumpster.py` - DNS enumeration
- `purplesploit/modules/osint/harvester.py` - theHarvester wrapper
- `purplesploit/modules/osint/crtsh.py` - Certificate transparency

**Features:**
- API key management in config
- Rate limiting compliance
- Result caching
- Auto-populate targets from discoveries
- Historical data comparison

---

## Phase 2: Intelligence & Automation (Weeks 3-4)

### 2.1 AI Automation Expansion
**Priority: HIGH** | **Effort: 4 days**

Expand AI capabilities for intelligent recommendations.

**Features:**
- **Attack Path Analysis** - Suggest attack chains based on discovered services
- **Module Recommendations** - ML-based next-step suggestions
- **Natural Language Queries** - "What can I do with these SMB shares?"
- **Automated Evidence Extraction** - Parse findings from tool output
- **Risk Prioritization** - Score targets by exploitability

**Enhancements to:**
- `purplesploit/modules/ai/ai_automation.py` - Core AI logic
- `purplesploit/modules/ai/methodology.py` - Testing methodology

**New files:**
- `purplesploit/ai/recommender.py` - Module recommendation engine
- `purplesploit/ai/nlp.py` - Natural language processing
- `purplesploit/ai/attack_paths.py` - Attack chain analysis

### 2.2 Findings Management System
**Priority: HIGH** | **Effort: 3 days**

Professional findings tracking and management.

**Features:**
- Finding lifecycle: Draft → Confirmed → Reported → Remediated → Verified
- CVSS calculator integration
- Evidence attachment (screenshots, logs, PoC)
- Remediation tracking
- Duplicate detection
- Tagging and categorization
- MITRE ATT&CK mapping

**Database additions:**
- Enhanced findings table with status workflow
- Evidence attachments table
- Finding comments/notes table

**CLI Commands:**
```
findings list [--status <status>] [--severity <severity>]
findings add <title> --severity <sev> --target <target>
findings update <id> --status <status>
findings evidence <id> add <file_path>
findings export [--format pdf|html|xlsx]
```

### 2.3 Module Chaining Wizard
**Priority: MEDIUM** | **Effort: 3 days**

Visual and CLI workflow automation.

**Features:**
- Pre-built workflow templates
- Chain modules with data passing
- Conditional execution (if finding X, run module Y)
- Parallel execution support
- Progress tracking and resumption
- Workflow export/import

**Workflow Templates:**
1. **Full Network Assessment** - nmap → nxc_smb → secretsdump
2. **Web Application Test** - httpx → feroxbuster → nuclei → sqlmap
3. **Active Directory Attack** - nmap → nxc_ldap → kerberoast → asreproast
4. **Cloud Security Review** - shodan → nuclei → specific cloud modules

**Files to create:**
- `purplesploit/core/workflow.py` - Workflow engine
- `purplesploit/workflows/` - Workflow template definitions
- `purplesploit/ui/workflow_wizard.py` - Interactive wizard

**CLI Commands:**
```
workflow list
workflow run <workflow_name> --target <target>
workflow create <name>
workflow edit <name>
workflow export <name> <file_path>
```

---

## Phase 3: Integration & Scale (Weeks 5-8)

### 3.1 External Integrations
- Slack/Teams notifications on critical findings
- Jira/GitHub Issues integration for finding tracking
- SIEM webhook support (Splunk, ELK)
- Burp Suite Collaborator integration

### 3.2 Distributed Architecture
- Agent deployment on target networks
- Centralized findings aggregation
- Load balancing across agents
- Proxied network support

### 3.3 Plugin Marketplace
- Community module repository
- Module versioning and signing
- Dependency management
- One-click installation

---

## Phase 4: Enterprise Features (Months 3+)

### 4.1 Multi-User Collaboration
- Role-based access control (RBAC)
- Team workspaces
- Activity audit logging
- Real-time collaboration

### 4.2 Compliance & Governance
- NIST/CIS/PCI-DSS mapping
- Compliance report templates
- Evidence chain of custody
- Data retention policies

### 4.3 Advanced Analytics
- Engagement metrics dashboard
- Trend analysis across assessments
- Coverage heatmaps
- Risk score progression

---

## Technical Specifications

### Reporting Module Architecture
```
purplesploit/reporting/
├── __init__.py
├── generator.py        # Main report orchestrator
├── pdf.py              # PDF generation (WeasyPrint)
├── html.py             # HTML generation (Jinja2)
├── xlsx.py             # Excel generation (openpyxl)
├── markdown.py         # Markdown export
├── evidence.py         # Evidence management
├── templates/
│   ├── executive.html  # Executive summary template
│   ├── technical.html  # Technical details template
│   ├── findings.html   # Findings listing template
│   └── styles.css      # Report styling
└── assets/
    └── logo.png        # Default logo
```

### OSINT Module Architecture
```
purplesploit/modules/osint/
├── __init__.py
├── base.py             # BaseOSINTModule with API handling
├── shodan.py           # Shodan integration
├── censys.py           # Censys integration
├── dnsdumpster.py      # DNSdumpster scraping
├── harvester.py        # theHarvester wrapper
├── crtsh.py            # Certificate transparency
└── whois.py            # WHOIS lookups
```

### AI Module Architecture
```
purplesploit/ai/
├── __init__.py
├── recommender.py      # Module recommendation engine
├── attack_paths.py     # Attack chain analysis
├── nlp.py              # Natural language queries
├── evidence.py         # Automated evidence extraction
└── models/
    └── priorities.json # Risk scoring model
```

---

## Dependencies to Add

```
# Reporting
weasyprint>=60.0        # PDF generation
openpyxl>=3.1.0         # Excel generation
jinja2>=3.1.0           # Template engine (likely already present)

# OSINT
shodan>=1.30.0          # Shodan API
censys>=2.2.0           # Censys API

# AI
openai>=1.0.0           # GPT integration (optional)
anthropic>=0.18.0       # Claude integration (optional)
sentence-transformers   # Local embeddings (optional)
```

---

## Success Metrics

| Metric | Current | Target |
|--------|---------|--------|
| Module Count | 40 | 55+ |
| Report Formats | 0 | 4 (PDF, HTML, XLSX, MD) |
| OSINT Integrations | 0 | 5+ |
| Workflow Templates | 0 | 10+ |
| AI Recommendations | Basic | Context-aware |
| Test Coverage | 85% | 90%+ |

---

## Timeline Summary

| Phase | Duration | Key Deliverables |
|-------|----------|------------------|
| Phase 1 | Weeks 1-2 | Reporting, Nuclei, OSINT modules |
| Phase 2 | Weeks 3-4 | AI expansion, Findings UI, Workflow wizard |
| Phase 3 | Weeks 5-8 | Integrations, Distributed architecture |
| Phase 4 | Month 3+ | Enterprise features, Compliance |

---

## Getting Started

To begin Phase 1 implementation:

1. **Reporting Module**: Start with PDF generation using WeasyPrint
2. **Nuclei Module**: Wrap nuclei CLI with operation handlers
3. **OSINT Modules**: Begin with Shodan (most common use case)

Each module should follow existing patterns in `purplesploit/modules/` and include:
- Full test coverage
- CLI command integration
- Database persistence for results
- Documentation
