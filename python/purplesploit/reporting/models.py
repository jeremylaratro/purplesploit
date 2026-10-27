"""Report containers and compatibility imports for canonical findings.

Finding, Evidence, Severity and FindingStatus are import aliases, not parallel
reporting models. Legacy file_type and string-note inputs are adapted by core.
Construct findings and evidence with keyword arguments: positional field order
follows the canonical core dataclasses. Finding.add_evidence accepts either the
core title/content arguments or the former reporting evidence object argument.
"""

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import json
from typing import List, Optional, Dict, Any

from purplesploit.core.findings import Evidence, Finding, FindingStatus, Severity

__all__ = ["Evidence", "Finding", "FindingStatus", "Severity", "ReportConfig", "ReportData"]


def finding_record_json(finding: Finding, config: "ReportConfig") -> str:
    """Render the versioned record while honoring evidence/raw-output options."""
    data = finding.to_report_dict()
    if not config.include_evidence:
        data.pop("evidence")
    if not config.include_raw_output:
        data.pop("raw_output")
    return json.dumps(data, indent=2, sort_keys=True)


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    title: str = "Penetration Test Report"
    subtitle: str = ""
    client_name: str = ""
    assessor_name: str = ""
    assessment_type: str = "Penetration Test"
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    report_date: datetime = field(default_factory=datetime.utcnow)
    scope: List[str] = field(default_factory=list)
    out_of_scope: List[str] = field(default_factory=list)
    include_executive_summary: bool = True
    include_methodology: bool = True
    include_findings_detail: bool = True
    include_evidence: bool = True
    include_appendix: bool = True
    include_raw_output: bool = False
    min_severity: Severity = Severity.INFO
    statuses_to_include: List[FindingStatus] = field(default_factory=lambda: [
        FindingStatus.DRAFT, FindingStatus.CONFIRMED, FindingStatus.REPORTED,
        FindingStatus.ACCEPTED_RISK,
    ])
    logo_path: Optional[str] = None
    company_name: str = ""
    company_website: str = ""
    output_dir: str = "."
    filename_prefix: str = "report"
    template_name: str = "default"

    def to_dict(self) -> Dict[str, Any]:
        data = deepcopy(vars(self))
        for name in ("start_date", "end_date", "report_date"):
            value = data[name]
            data[name] = value.isoformat() if value else None
        data["min_severity"] = self.min_severity.value
        data["statuses_to_include"] = [s.value for s in self.statuses_to_include]
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ReportConfig":
        data = deepcopy(data)
        if isinstance(data.get("min_severity"), str):
            data["min_severity"] = Severity(data["min_severity"])
        if "statuses_to_include" in data:
            data["statuses_to_include"] = [FindingStatus(s) for s in data["statuses_to_include"]]
        for name in ("start_date", "end_date", "report_date"):
            if isinstance(data.get(name), str):
                data[name] = datetime.fromisoformat(data[name])
        return cls(**data)


@dataclass
class ReportData:
    """Container whose version 1 JSON projection retains every finding field."""

    config: ReportConfig
    findings: List[Finding]
    targets: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)

    def __post_init__(self):
        self.findings = [Finding.from_dict(f) if isinstance(f, dict) else f for f in self.findings]
        if any(not isinstance(f, Finding) for f in self.findings):
            raise TypeError("Report findings must be canonical Finding objects or dictionaries")

    @property
    def findings_by_severity(self) -> Dict[Severity, List[Finding]]:
        result = {s: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity].append(finding)
        return result

    @property
    def severity_counts(self) -> Dict[str, int]:
        return {s.value: len(findings) for s, findings in self.findings_by_severity.items()}

    @property
    def findings_by_target(self) -> Dict[str, List[Finding]]:
        result: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            result.setdefault(finding.target, []).append(finding)
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
        severity_order = list(Severity)
        allowed = severity_order[:severity_order.index(config.min_severity) + 1]
        return [f for f in self.findings if f.severity in allowed and f.status in config.statuses_to_include]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": 1,
            "config": self.config.to_dict(),
            "findings": [f.to_report_dict() for f in self.findings],
            "targets": deepcopy(self.targets),
            "services": deepcopy(self.services),
            "credentials": deepcopy(self.credentials),
            "statistics": {
                "total_findings": self.total_findings,
                "severity_counts": self.severity_counts,
                "unique_targets": self.unique_targets,
                "critical_count": self.critical_count,
                "high_count": self.high_count,
            },
        }
