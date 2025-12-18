"""
Data models for PurpleSploit reporting.

Defines Finding, Evidence, and ReportConfig dataclasses used throughout
the reporting module.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pathlib import Path


class Severity(Enum):
    """Finding severity levels aligned with CVSS v3.1"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def cvss_range(self) -> tuple:
        """Return CVSS score range for this severity"""
        ranges = {
            "critical": (9.0, 10.0),
            "high": (7.0, 8.9),
            "medium": (4.0, 6.9),
            "low": (0.1, 3.9),
            "info": (0.0, 0.0),
        }
        return ranges[self.value]

    @property
    def color(self) -> str:
        """Return color code for this severity"""
        colors = {
            "critical": "#7b241c",
            "high": "#c0392b",
            "medium": "#e67e22",
            "low": "#f1c40f",
            "info": "#3498db",
        }
        return colors[self.value]

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Determine severity from CVSS score"""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO


class FindingStatus(Enum):
    """Finding lifecycle status"""
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"


@dataclass
class Evidence:
    """Evidence attachment for a finding"""
    id: str
    finding_id: str
    file_path: Optional[str] = None
    file_type: str = "text"  # text, image, log, pcap, etc.
    description: str = ""
    content: Optional[str] = None  # For inline text content
    captured_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "file_path": self.file_path,
            "file_type": self.file_type,
            "description": self.description,
            "content": self.content,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        if data.get("captured_at") and isinstance(data["captured_at"], str):
            data["captured_at"] = datetime.fromisoformat(data["captured_at"])
        return cls(**data)


@dataclass
class Finding:
    """Security finding/vulnerability"""
    id: str
    title: str
    severity: Severity
    description: str
    target: str

    # Optional fields
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    # Impact and remediation
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # MITRE ATT&CK mapping
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Module and technical details
    module_name: Optional[str] = None
    port: Optional[int] = None
    service: Optional[str] = None
    raw_output: Optional[str] = None

    # Status tracking
    status: FindingStatus = FindingStatus.DRAFT

    # Evidence
    evidence: List[Evidence] = field(default_factory=list)

    # Timestamps
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None

    # Notes
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "target": self.target,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "module_name": self.module_name,
            "port": self.port,
            "service": self.service,
            "raw_output": self.raw_output,
            "status": self.status.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "remediated_at": self.remediated_at.isoformat() if self.remediated_at else None,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        # Convert severity string to enum
        if isinstance(data.get("severity"), str):
            data["severity"] = Severity(data["severity"])

        # Convert status string to enum
        if isinstance(data.get("status"), str):
            data["status"] = FindingStatus(data["status"])

        # Convert evidence dicts to Evidence objects
        if data.get("evidence"):
            data["evidence"] = [
                Evidence.from_dict(e) if isinstance(e, dict) else e
                for e in data["evidence"]
            ]

        # Convert datetime strings
        for dt_field in ["discovered_at", "confirmed_at", "remediated_at"]:
            if data.get(dt_field) and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])

        return cls(**data)

    def add_evidence(self, evidence: Evidence):
        """Add evidence to this finding"""
        evidence.finding_id = self.id
        self.evidence.append(evidence)

    def confirm(self):
        """Mark finding as confirmed"""
        self.status = FindingStatus.CONFIRMED
        self.confirmed_at = datetime.utcnow()

    def mark_remediated(self):
        """Mark finding as remediated"""
        self.status = FindingStatus.REMEDIATED
        self.remediated_at = datetime.utcnow()


@dataclass
class ReportConfig:
    """Configuration for report generation"""
    # Report metadata
    title: str = "Penetration Test Report"
    subtitle: str = ""
    client_name: str = ""
    assessor_name: str = ""
    assessment_type: str = "Penetration Test"

    # Date range
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    report_date: datetime = field(default_factory=datetime.utcnow)

    # Scope
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)

    # Report options
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_findings_detail: bool = True
    include_evidence: bool = True
    include_appendix: bool = True
    include_raw_output: bool = False

    # Filtering
    min_severity: Severity = Severity.INFO
    statuses_to_include: List[FindingStatus] = field(
        default_factory=lambda: [
            FindingStatus.DRAFT,
            FindingStatus.CONFIRMED,
            FindingStatus.REPORTED,
        ]
    )

    # Branding
    logo_path: Optional[str] = None
    company_name: str = ""
    company_website: str = ""

    # Output options
    output_dir: str = "."
    filename_prefix: str = "report"

    # Template selection
    template_name: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "client_name": self.client_name,
            "assessor_name": self.assessor_name,
            "assessment_type": self.assessment_type,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "report_date": self.report_date.isoformat() if self.report_date else None,
            "scope": self.scope,
            "out_of_scope": self.out_of_scope,
            "include_executive_summary": self.include_executive_summary,
            "include_methodology": self.include_methodology,
            "include_findings_detail": self.include_findings_detail,
            "include_evidence": self.include_evidence,
            "include_appendix": self.include_appendix,
            "include_raw_output": self.include_raw_output,
            "min_severity": self.min_severity.value,
            "statuses_to_include": [s.value for s in self.statuses_to_include],
            "logo_path": self.logo_path,
            "company_name": self.company_name,
            "company_website": self.company_website,
            "output_dir": self.output_dir,
            "filename_prefix": self.filename_prefix,
            "template_name": self.template_name,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportConfig":
        # Convert severity string to enum
        if isinstance(data.get("min_severity"), str):
            data["min_severity"] = Severity(data["min_severity"])

        # Convert status strings to enums
        if data.get("statuses_to_include"):
            data["statuses_to_include"] = [
                FindingStatus(s) if isinstance(s, str) else s
                for s in data["statuses_to_include"]
            ]

        # Convert datetime strings
        for dt_field in ["start_date", "end_date", "report_date"]:
            if data.get(dt_field) and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])

        return cls(**data)


@dataclass
class ReportData:
    """Container for all data needed to generate a report"""
    config: ReportConfig
    findings: List[Finding]
    targets: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)

    # Statistics computed from findings
    @property
    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        """Group findings by severity"""
        result = {s: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity"""
        return {
            s.value: len(findings)
            for s, findings in self.findings_by_severity.items()
        }

    @property
    def findings_by_target(self) -> Dict[str, List[Finding]]:
        """Group findings by target"""
        result: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            if finding.target not in result:
                result[finding.target] = []
            result[finding.target].append(finding)
        return result

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return len(self.findings_by_severity[Severity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len(self.findings_by_severity[Severity.HIGH])

    @property
    def unique_targets(self) -> int:
        return len(set(f.target for f in self.findings))

    def filter_findings(self, config: ReportConfig) -> List[Finding]:
        """Filter findings based on report config"""
        severity_order = list(Severity)
        min_idx = severity_order.index(config.min_severity)
        allowed_severities = severity_order[:min_idx + 1]

        return [
            f for f in self.findings
            if f.severity in allowed_severities
            and f.status in config.statuses_to_include
        ]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "config": self.config.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "targets": self.targets,
            "services": self.services,
            "credentials": self.credentials,
            "statistics": {
                "total_findings": self.total_findings,
                "severity_counts": self.severity_counts,
                "unique_targets": self.unique_targets,
                "critical_count": self.critical_count,
                "high_count": self.high_count,
            }
        }
