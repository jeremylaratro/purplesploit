"""
Findings Management System for PurpleSploit

Professional findings tracking with lifecycle management, evidence,
CVSS scoring, and MITRE ATT&CK mapping.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from enum import Enum
from pathlib import Path
import json
import uuid


class FindingStatus(Enum):
    """Finding lifecycle status."""
    DRAFT = "draft"
    CONFIRMED = "confirmed"
    REPORTED = "reported"
    REMEDIATED = "remediated"
    VERIFIED = "verified"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"


class Severity(Enum):
    """Finding severity aligned with CVSS v3.1."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        """Determine severity from CVSS score."""
        if score >= 9.0:
            return cls.CRITICAL
        elif score >= 7.0:
            return cls.HIGH
        elif score >= 4.0:
            return cls.MEDIUM
        elif score > 0:
            return cls.LOW
        return cls.INFO


@dataclass
class Evidence:
    """Evidence attached to a finding."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding_id: str = ""
    title: str = ""
    description: str = ""
    file_path: Optional[str] = None
    content: Optional[str] = None
    evidence_type: str = "text"  # text, screenshot, log, pcap, file
    captured_at: datetime = field(default_factory=datetime.utcnow)
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "content": self.content,
            "evidence_type": self.evidence_type,
            "captured_at": self.captured_at.isoformat() if self.captured_at else None,
            "tags": self.tags,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Evidence":
        if data.get("captured_at") and isinstance(data["captured_at"], str):
            data["captured_at"] = datetime.fromisoformat(data["captured_at"])
        return cls(**data)


@dataclass
class Finding:
    """Security finding with full lifecycle support."""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    title: str = ""
    severity: Severity = Severity.MEDIUM
    status: FindingStatus = FindingStatus.DRAFT
    description: str = ""
    target: str = ""

    # Technical details
    port: Optional[int] = None
    service: Optional[str] = None
    protocol: Optional[str] = None
    url: Optional[str] = None

    # Vulnerability details
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cve_ids: List[str] = field(default_factory=list)
    cwe_ids: List[str] = field(default_factory=list)

    # MITRE ATT&CK
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)

    # Impact and remediation
    impact: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)

    # Evidence and proof
    evidence: List[Evidence] = field(default_factory=list)
    proof_of_concept: str = ""
    raw_output: str = ""

    # Metadata
    module_name: Optional[str] = None
    discovered_at: datetime = field(default_factory=datetime.utcnow)
    confirmed_at: Optional[datetime] = None
    reported_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    verified_at: Optional[datetime] = None

    # Tracking
    assigned_to: Optional[str] = None
    notes: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    duplicate_of: Optional[str] = None

    def add_evidence(
        self,
        title: str,
        content: Optional[str] = None,
        file_path: Optional[str] = None,
        evidence_type: str = "text",
        description: str = "",
    ) -> Evidence:
        """Add evidence to the finding."""
        evidence = Evidence(
            finding_id=self.id,
            title=title,
            content=content,
            file_path=file_path,
            evidence_type=evidence_type,
            description=description,
        )
        self.evidence.append(evidence)
        return evidence

    def confirm(self, notes: str = "") -> None:
        """Mark finding as confirmed."""
        self.status = FindingStatus.CONFIRMED
        self.confirmed_at = datetime.utcnow()
        if notes:
            self.notes.append(f"[Confirmed] {notes}")

    def mark_reported(self) -> None:
        """Mark finding as reported."""
        self.status = FindingStatus.REPORTED
        self.reported_at = datetime.utcnow()

    def mark_remediated(self, notes: str = "") -> None:
        """Mark finding as remediated."""
        self.status = FindingStatus.REMEDIATED
        self.remediated_at = datetime.utcnow()
        if notes:
            self.notes.append(f"[Remediated] {notes}")

    def verify_remediation(self, verified: bool, notes: str = "") -> None:
        """Verify remediation status."""
        if verified:
            self.status = FindingStatus.VERIFIED
            self.verified_at = datetime.utcnow()
        else:
            self.status = FindingStatus.CONFIRMED  # Back to confirmed if not fixed
        if notes:
            self.notes.append(f"[Verification] {notes}")

    def mark_false_positive(self, reason: str) -> None:
        """Mark as false positive."""
        self.status = FindingStatus.FALSE_POSITIVE
        self.notes.append(f"[False Positive] {reason}")

    def accept_risk(self, reason: str, accepted_by: str) -> None:
        """Mark as accepted risk."""
        self.status = FindingStatus.ACCEPTED_RISK
        self.notes.append(f"[Accepted Risk by {accepted_by}] {reason}")

    def add_note(self, note: str) -> None:
        """Add a note to the finding."""
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M")
        self.notes.append(f"[{timestamp}] {note}")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "description": self.description,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "protocol": self.protocol,
            "url": self.url,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "cve_ids": self.cve_ids,
            "cwe_ids": self.cwe_ids,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "impact": self.impact,
            "remediation": self.remediation,
            "references": self.references,
            "evidence": [e.to_dict() for e in self.evidence],
            "proof_of_concept": self.proof_of_concept,
            "raw_output": self.raw_output,
            "module_name": self.module_name,
            "discovered_at": self.discovered_at.isoformat() if self.discovered_at else None,
            "confirmed_at": self.confirmed_at.isoformat() if self.confirmed_at else None,
            "reported_at": self.reported_at.isoformat() if self.reported_at else None,
            "remediated_at": self.remediated_at.isoformat() if self.remediated_at else None,
            "verified_at": self.verified_at.isoformat() if self.verified_at else None,
            "assigned_to": self.assigned_to,
            "notes": self.notes,
            "tags": self.tags,
            "duplicate_of": self.duplicate_of,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Finding":
        # Convert enums
        if isinstance(data.get("severity"), str):
            data["severity"] = Severity(data["severity"])
        if isinstance(data.get("status"), str):
            data["status"] = FindingStatus(data["status"])

        # Convert evidence
        if data.get("evidence"):
            data["evidence"] = [
                Evidence.from_dict(e) if isinstance(e, dict) else e
                for e in data["evidence"]
            ]

        # Convert datetimes
        for dt_field in ["discovered_at", "confirmed_at", "reported_at", "remediated_at", "verified_at"]:
            if data.get(dt_field) and isinstance(data[dt_field], str):
                data[dt_field] = datetime.fromisoformat(data[dt_field])

        return cls(**data)


class FindingsManager:
    """
    Manages findings throughout the assessment lifecycle.

    Features:
    - Create, update, delete findings
    - Track status transitions
    - Evidence management
    - Duplicate detection
    - Export to various formats
    """

    def __init__(self, framework=None, storage_path: Optional[str] = None):
        self.framework = framework
        self.findings: Dict[str, Finding] = {}

        if storage_path:
            self.storage_path = Path(storage_path)
        else:
            self.storage_path = Path.home() / ".purplesploit" / "findings"

        self.storage_path.mkdir(parents=True, exist_ok=True)
        self._load_findings()

    def _load_findings(self) -> None:
        """Load findings from storage."""
        findings_file = self.storage_path / "findings.json"
        if findings_file.exists():
            try:
                with open(findings_file, 'r') as f:
                    data = json.load(f)
                    for finding_data in data:
                        finding = Finding.from_dict(finding_data)
                        self.findings[finding.id] = finding
            except Exception:
                pass

    def _save_findings(self) -> None:
        """Save findings to storage."""
        findings_file = self.storage_path / "findings.json"
        data = [f.to_dict() for f in self.findings.values()]
        with open(findings_file, 'w') as f:
            json.dump(data, f, indent=2, default=str)

    def create(
        self,
        title: str,
        severity: str,
        description: str,
        target: str,
        **kwargs
    ) -> Finding:
        """
        Create a new finding.

        Args:
            title: Finding title
            severity: Severity level
            description: Detailed description
            target: Affected target
            **kwargs: Additional finding attributes

        Returns:
            Created Finding
        """
        # Check for duplicates
        duplicate = self._find_duplicate(title, target, kwargs.get("port"))
        if duplicate:
            duplicate.add_note(f"Duplicate detection triggered for new finding")
            return duplicate

        finding = Finding(
            title=title,
            severity=Severity(severity.lower()) if isinstance(severity, str) else severity,
            description=description,
            target=target,
            **kwargs
        )

        self.findings[finding.id] = finding
        self._save_findings()

        return finding

    def get(self, finding_id: str) -> Optional[Finding]:
        """Get a finding by ID."""
        return self.findings.get(finding_id)

    def update(self, finding_id: str, **updates) -> Optional[Finding]:
        """Update a finding."""
        finding = self.findings.get(finding_id)
        if not finding:
            return None

        for key, value in updates.items():
            if hasattr(finding, key):
                setattr(finding, key, value)

        self._save_findings()
        return finding

    def delete(self, finding_id: str) -> bool:
        """Delete a finding."""
        if finding_id in self.findings:
            del self.findings[finding_id]
            self._save_findings()
            return True
        return False

    def list_findings(
        self,
        status: Optional[FindingStatus] = None,
        severity: Optional[Severity] = None,
        target: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> List[Finding]:
        """
        List findings with optional filters.

        Args:
            status: Filter by status
            severity: Filter by severity
            target: Filter by target
            tags: Filter by tags

        Returns:
            List of matching findings
        """
        results = list(self.findings.values())

        if status:
            results = [f for f in results if f.status == status]
        if severity:
            results = [f for f in results if f.severity == severity]
        if target:
            results = [f for f in results if target in f.target]
        if tags:
            results = [f for f in results if any(t in f.tags for t in tags)]

        # Sort by severity, then by discovered date
        severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        results.sort(key=lambda f: (severity_order.index(f.severity), f.discovered_at))

        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get findings statistics."""
        findings = list(self.findings.values())

        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_status": {},
            "by_target": {},
            "with_evidence": 0,
            "with_cvss": 0,
        }

        for sev in Severity:
            stats["by_severity"][sev.value] = len([f for f in findings if f.severity == sev])

        for status in FindingStatus:
            stats["by_status"][status.value] = len([f for f in findings if f.status == status])

        for finding in findings:
            if finding.target not in stats["by_target"]:
                stats["by_target"][finding.target] = 0
            stats["by_target"][finding.target] += 1

            if finding.evidence:
                stats["with_evidence"] += 1
            if finding.cvss_score:
                stats["with_cvss"] += 1

        return stats

    def add_evidence(
        self,
        finding_id: str,
        title: str,
        content: Optional[str] = None,
        file_path: Optional[str] = None,
        evidence_type: str = "text",
    ) -> Optional[Evidence]:
        """Add evidence to a finding."""
        finding = self.findings.get(finding_id)
        if not finding:
            return None

        evidence = finding.add_evidence(
            title=title,
            content=content,
            file_path=file_path,
            evidence_type=evidence_type,
        )
        self._save_findings()
        return evidence

    def transition_status(
        self,
        finding_id: str,
        new_status: FindingStatus,
        notes: str = "",
    ) -> bool:
        """Transition finding to a new status."""
        finding = self.findings.get(finding_id)
        if not finding:
            return False

        if new_status == FindingStatus.CONFIRMED:
            finding.confirm(notes)
        elif new_status == FindingStatus.REPORTED:
            finding.mark_reported()
        elif new_status == FindingStatus.REMEDIATED:
            finding.mark_remediated(notes)
        elif new_status == FindingStatus.VERIFIED:
            finding.verify_remediation(True, notes)
        elif new_status == FindingStatus.FALSE_POSITIVE:
            finding.mark_false_positive(notes)
        else:
            finding.status = new_status

        self._save_findings()
        return True

    def _find_duplicate(
        self,
        title: str,
        target: str,
        port: Optional[int] = None,
    ) -> Optional[Finding]:
        """Check for duplicate findings."""
        title_lower = title.lower()

        for finding in self.findings.values():
            if finding.status == FindingStatus.FALSE_POSITIVE:
                continue

            if finding.target == target:
                # Exact title match
                if finding.title.lower() == title_lower:
                    return finding

                # Same port and similar title
                if port and finding.port == port:
                    if self._similar_titles(finding.title, title):
                        return finding

        return None

    def _similar_titles(self, title1: str, title2: str, threshold: float = 0.8) -> bool:
        """Check if two titles are similar."""
        words1 = set(title1.lower().split())
        words2 = set(title2.lower().split())

        if not words1 or not words2:
            return False

        intersection = words1.intersection(words2)
        union = words1.union(words2)

        similarity = len(intersection) / len(union)
        return similarity >= threshold

    def export_json(self, output_path: str) -> str:
        """Export findings to JSON."""
        data = [f.to_dict() for f in self.findings.values()]
        with open(output_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return output_path

    def import_json(self, input_path: str) -> int:
        """Import findings from JSON."""
        with open(input_path, 'r') as f:
            data = json.load(f)

        imported = 0
        for finding_data in data:
            finding = Finding.from_dict(finding_data)
            if finding.id not in self.findings:
                self.findings[finding.id] = finding
                imported += 1

        self._save_findings()
        return imported

    def to_report_generator(self):
        """Convert to ReportGenerator findings format."""
        try:
            from purplesploit.reporting import ReportGenerator, Finding as ReportFinding, Severity as ReportSeverity

            gen = ReportGenerator(self.framework)

            for finding in self.findings.values():
                gen.create_finding(
                    title=finding.title,
                    severity=finding.severity.value,
                    description=finding.description,
                    target=finding.target,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    cve_ids=finding.cve_ids,
                    cwe_ids=finding.cwe_ids,
                    impact=finding.impact,
                    remediation=finding.remediation,
                    references=finding.references,
                    mitre_tactics=finding.mitre_tactics,
                    mitre_techniques=finding.mitre_techniques,
                    module_name=finding.module_name,
                    port=finding.port,
                    service=finding.service,
                    raw_output=finding.raw_output,
                    status=finding.status.value,
                    notes="\n".join(finding.notes),
                )

            return gen
        except ImportError:
            return None
