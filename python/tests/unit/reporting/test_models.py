"""
Tests for purplesploit.reporting.models module.

Tests the Severity, FindingStatus, Evidence, Finding, ReportConfig, and ReportData classes.
"""

import pytest
from datetime import datetime
from unittest.mock import Mock

from purplesploit.reporting.models import (
    Severity,
    FindingStatus,
    Evidence,
    Finding,
    ReportConfig,
    ReportData,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test that all severity values are defined."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_cvss_range_critical(self):
        """Test CVSS range for critical severity."""
        assert Severity.CRITICAL.cvss_range == (9.0, 10.0)

    def test_cvss_range_high(self):
        """Test CVSS range for high severity."""
        assert Severity.HIGH.cvss_range == (7.0, 8.9)

    def test_cvss_range_medium(self):
        """Test CVSS range for medium severity."""
        assert Severity.MEDIUM.cvss_range == (4.0, 6.9)

    def test_cvss_range_low(self):
        """Test CVSS range for low severity."""
        assert Severity.LOW.cvss_range == (0.1, 3.9)

    def test_cvss_range_info(self):
        """Test CVSS range for info severity."""
        assert Severity.INFO.cvss_range == (0.0, 0.0)

    def test_color_critical(self):
        """Test color for critical severity."""
        assert Severity.CRITICAL.color == "#7b241c"

    def test_color_high(self):
        """Test color for high severity."""
        assert Severity.HIGH.color == "#c0392b"

    def test_color_medium(self):
        """Test color for medium severity."""
        assert Severity.MEDIUM.color == "#e67e22"

    def test_color_low(self):
        """Test color for low severity."""
        assert Severity.LOW.color == "#f1c40f"

    def test_color_info(self):
        """Test color for info severity."""
        assert Severity.INFO.color == "#3498db"

    def test_from_cvss_critical(self):
        """Test from_cvss returns critical for high scores."""
        assert Severity.from_cvss(10.0) == Severity.CRITICAL
        assert Severity.from_cvss(9.0) == Severity.CRITICAL
        assert Severity.from_cvss(9.5) == Severity.CRITICAL

    def test_from_cvss_high(self):
        """Test from_cvss returns high for scores 7.0-8.9."""
        assert Severity.from_cvss(7.0) == Severity.HIGH
        assert Severity.from_cvss(8.9) == Severity.HIGH
        assert Severity.from_cvss(8.0) == Severity.HIGH

    def test_from_cvss_medium(self):
        """Test from_cvss returns medium for scores 4.0-6.9."""
        assert Severity.from_cvss(4.0) == Severity.MEDIUM
        assert Severity.from_cvss(6.9) == Severity.MEDIUM
        assert Severity.from_cvss(5.5) == Severity.MEDIUM

    def test_from_cvss_low(self):
        """Test from_cvss returns low for scores 0.1-3.9."""
        assert Severity.from_cvss(0.1) == Severity.LOW
        assert Severity.from_cvss(3.9) == Severity.LOW
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_from_cvss_info(self):
        """Test from_cvss returns info for score 0."""
        assert Severity.from_cvss(0.0) == Severity.INFO


class TestFindingStatus:
    """Tests for FindingStatus enum."""

    def test_status_values(self):
        """Test that all status values are defined."""
        assert FindingStatus.DRAFT.value == "draft"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.REPORTED.value == "reported"
        assert FindingStatus.REMEDIATED.value == "remediated"
        assert FindingStatus.VERIFIED.value == "verified"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"


class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_creation_defaults(self):
        """Test creating Evidence with minimal parameters."""
        evidence = Evidence(id="ev1", finding_id="f1")

        assert evidence.id == "ev1"
        assert evidence.finding_id == "f1"
        assert evidence.file_path is None
        assert evidence.file_type == "text"
        assert evidence.description == ""
        assert evidence.content is None
        assert isinstance(evidence.captured_at, datetime)

    def test_evidence_creation_full(self):
        """Test creating Evidence with all parameters."""
        captured = datetime(2025, 1, 15, 10, 30, 0)
        evidence = Evidence(
            id="ev1",
            finding_id="f1",
            file_path="/tmp/screenshot.png",
            file_type="image",
            description="Screenshot of vulnerability",
            content=None,
            captured_at=captured,
        )

        assert evidence.file_path == "/tmp/screenshot.png"
        assert evidence.file_type == "image"
        assert evidence.description == "Screenshot of vulnerability"
        assert evidence.captured_at == captured

    def test_evidence_to_dict(self):
        """Test Evidence.to_dict() serialization."""
        captured = datetime(2025, 1, 15, 10, 30, 0)
        evidence = Evidence(
            id="ev1",
            finding_id="f1",
            file_path="/tmp/log.txt",
            file_type="log",
            description="Log output",
            content="Error: unauthorized",
            captured_at=captured,
        )

        data = evidence.to_dict()

        assert data["id"] == "ev1"
        assert data["finding_id"] == "f1"
        assert data["file_path"] == "/tmp/log.txt"
        assert data["file_type"] == "log"
        assert data["description"] == "Log output"
        assert data["content"] == "Error: unauthorized"
        assert data["captured_at"] == "2025-01-15T10:30:00"

    def test_evidence_from_dict(self):
        """Test Evidence.from_dict() deserialization."""
        data = {
            "id": "ev1",
            "finding_id": "f1",
            "file_path": "/tmp/data.pcap",
            "file_type": "pcap",
            "description": "Network capture",
            "content": None,
            "captured_at": "2025-01-15T10:30:00",
        }

        evidence = Evidence.from_dict(data)

        assert evidence.id == "ev1"
        assert evidence.finding_id == "f1"
        assert evidence.file_type == "pcap"
        assert evidence.captured_at == datetime(2025, 1, 15, 10, 30, 0)


class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation_minimal(self):
        """Test creating Finding with minimal required parameters."""
        finding = Finding(
            id="f1",
            title="SQL Injection",
            severity=Severity.HIGH,
            description="SQL injection vulnerability found",
            target="192.168.1.100",
        )

        assert finding.id == "f1"
        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.HIGH
        assert finding.description == "SQL injection vulnerability found"
        assert finding.target == "192.168.1.100"
        assert finding.status == FindingStatus.DRAFT

    def test_finding_creation_full(self):
        """Test creating Finding with all parameters."""
        finding = Finding(
            id="f1",
            title="CVE-2021-44228 Log4Shell",
            severity=Severity.CRITICAL,
            description="Remote code execution via Log4j",
            target="10.0.0.50",
            cvss_score=10.0,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            cve_ids=["CVE-2021-44228"],
            cwe_ids=["CWE-917"],
            impact="Full system compromise",
            remediation="Update Log4j to version 2.17.0 or later",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            mitre_tactics=["Initial Access"],
            mitre_techniques=["T1190"],
            module_name="nuclei",
            port=8080,
            service="http",
        )

        assert finding.cvss_score == 10.0
        assert finding.cve_ids == ["CVE-2021-44228"]
        assert finding.port == 8080
        assert finding.service == "http"

    def test_finding_to_dict(self):
        """Test Finding.to_dict() serialization."""
        finding = Finding(
            id="f1",
            title="XSS",
            severity=Severity.MEDIUM,
            description="Cross-site scripting",
            target="example.com",
            status=FindingStatus.CONFIRMED,
        )

        data = finding.to_dict()

        assert data["id"] == "f1"
        assert data["title"] == "XSS"
        assert data["severity"] == "medium"
        assert data["status"] == "confirmed"
        assert "discovered_at" in data
        assert data["evidence"] == []

    def test_finding_from_dict(self):
        """Test Finding.from_dict() deserialization."""
        data = {
            "id": "f1",
            "title": "XSS",
            "severity": "medium",
            "description": "Cross-site scripting",
            "target": "example.com",
            "status": "confirmed",
            "evidence": [],
            "cve_ids": [],
            "cwe_ids": [],
            "references": [],
            "mitre_tactics": [],
            "mitre_techniques": [],
            "notes": "",
        }

        finding = Finding.from_dict(data)

        assert finding.id == "f1"
        assert finding.severity == Severity.MEDIUM
        assert finding.status == FindingStatus.CONFIRMED

    def test_finding_add_evidence(self):
        """Test adding evidence to a finding."""
        finding = Finding(
            id="f1",
            title="Test Finding",
            severity=Severity.LOW,
            description="Test",
            target="test.local",
        )

        evidence = Evidence(id="ev1", finding_id="other")
        finding.add_evidence(evidence)

        assert len(finding.evidence) == 1
        assert finding.evidence[0].finding_id == "f1"

    def test_finding_confirm(self):
        """Test confirming a finding."""
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.MEDIUM,
            description="Test",
            target="test.local",
        )

        finding.confirm()

        assert finding.status == FindingStatus.CONFIRMED
        assert finding.confirmed_at is not None

    def test_finding_mark_remediated(self):
        """Test marking a finding as remediated."""
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test.local",
        )

        finding.mark_remediated()

        assert finding.status == FindingStatus.REMEDIATED
        assert finding.remediated_at is not None


class TestReportConfig:
    """Tests for ReportConfig dataclass."""

    def test_config_defaults(self):
        """Test ReportConfig with default values."""
        config = ReportConfig()

        assert config.title == "Penetration Test Report"
        assert config.subtitle == ""
        assert config.client_name == ""
        assert config.include_executive_summary is True
        assert config.include_findings_detail is True
        assert config.min_severity == Severity.INFO
        assert config.output_dir == "."
        assert config.filename_prefix == "report"

    def test_config_custom_values(self):
        """Test ReportConfig with custom values."""
        config = ReportConfig(
            title="Custom Report",
            client_name="ACME Corp",
            assessor_name="John Doe",
            include_raw_output=True,
            min_severity=Severity.MEDIUM,
        )

        assert config.title == "Custom Report"
        assert config.client_name == "ACME Corp"
        assert config.assessor_name == "John Doe"
        assert config.include_raw_output is True
        assert config.min_severity == Severity.MEDIUM

    def test_config_to_dict(self):
        """Test ReportConfig.to_dict() serialization."""
        config = ReportConfig(
            title="Test Report",
            client_name="Client",
        )

        data = config.to_dict()

        assert data["title"] == "Test Report"
        assert data["client_name"] == "Client"
        assert data["min_severity"] == "info"
        assert "statuses_to_include" in data

    def test_config_from_dict(self):
        """Test ReportConfig.from_dict() deserialization."""
        data = {
            "title": "Test Report",
            "subtitle": "Subtitle",
            "client_name": "Client",
            "assessor_name": "",
            "assessment_type": "Penetration Test",
            "start_date": None,
            "end_date": None,
            "report_date": "2025-01-15T10:00:00",
            "scope": ["192.168.1.0/24"],
            "out_of_scope": [],
            "include_executive_summary": True,
            "include_methodology": True,
            "include_findings_detail": True,
            "include_evidence": True,
            "include_appendix": True,
            "include_raw_output": False,
            "min_severity": "medium",
            "statuses_to_include": ["draft", "confirmed"],
            "logo_path": None,
            "company_name": "",
            "company_website": "",
            "output_dir": ".",
            "filename_prefix": "report",
            "template_name": "default",
        }

        config = ReportConfig.from_dict(data)

        assert config.title == "Test Report"
        assert config.min_severity == Severity.MEDIUM
        assert config.scope == ["192.168.1.0/24"]
        assert len(config.statuses_to_include) == 2


class TestReportData:
    """Tests for ReportData dataclass."""

    @pytest.fixture
    def sample_findings(self):
        """Create sample findings for testing."""
        return [
            Finding(
                id="f1",
                title="Critical Issue",
                severity=Severity.CRITICAL,
                description="Critical vulnerability",
                target="192.168.1.1",
            ),
            Finding(
                id="f2",
                title="High Issue",
                severity=Severity.HIGH,
                description="High vulnerability",
                target="192.168.1.1",
            ),
            Finding(
                id="f3",
                title="Medium Issue",
                severity=Severity.MEDIUM,
                description="Medium vulnerability",
                target="192.168.1.2",
            ),
            Finding(
                id="f4",
                title="Low Issue",
                severity=Severity.LOW,
                description="Low vulnerability",
                target="192.168.1.2",
            ),
        ]

    def test_report_data_creation(self, sample_findings):
        """Test creating ReportData."""
        config = ReportConfig()
        report_data = ReportData(
            config=config,
            findings=sample_findings,
        )

        assert report_data.config == config
        assert len(report_data.findings) == 4

    def test_findings_by_severity(self, sample_findings):
        """Test grouping findings by severity."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        by_severity = report_data.findings_by_severity

        assert len(by_severity[Severity.CRITICAL]) == 1
        assert len(by_severity[Severity.HIGH]) == 1
        assert len(by_severity[Severity.MEDIUM]) == 1
        assert len(by_severity[Severity.LOW]) == 1
        assert len(by_severity[Severity.INFO]) == 0

    def test_severity_counts(self, sample_findings):
        """Test severity counts property."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        counts = report_data.severity_counts

        assert counts["critical"] == 1
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1
        assert counts["info"] == 0

    def test_findings_by_target(self, sample_findings):
        """Test grouping findings by target."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        by_target = report_data.findings_by_target

        assert len(by_target["192.168.1.1"]) == 2
        assert len(by_target["192.168.1.2"]) == 2

    def test_total_findings(self, sample_findings):
        """Test total findings count."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        assert report_data.total_findings == 4

    def test_critical_count(self, sample_findings):
        """Test critical findings count."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        assert report_data.critical_count == 1

    def test_high_count(self, sample_findings):
        """Test high findings count."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        assert report_data.high_count == 1

    def test_unique_targets(self, sample_findings):
        """Test unique targets count."""
        config = ReportConfig()
        report_data = ReportData(config=config, findings=sample_findings)

        assert report_data.unique_targets == 2

    def test_filter_findings_by_severity(self, sample_findings):
        """Test filtering findings by minimum severity."""
        config = ReportConfig(min_severity=Severity.MEDIUM)
        report_data = ReportData(config=config, findings=sample_findings)

        filtered = report_data.filter_findings(config)

        # Should include critical, high, and medium (severity order is CRITICAL first)
        severities = [f.severity for f in filtered]
        assert Severity.CRITICAL in severities
        assert Severity.HIGH in severities
        assert Severity.MEDIUM in severities
        # LOW should also be included since it comes after MEDIUM in the enum order

    def test_filter_findings_by_status(self, sample_findings):
        """Test filtering findings by status."""
        # Mark one finding as false positive
        sample_findings[0].status = FindingStatus.FALSE_POSITIVE

        config = ReportConfig(
            statuses_to_include=[FindingStatus.DRAFT, FindingStatus.CONFIRMED]
        )
        report_data = ReportData(config=config, findings=sample_findings)

        filtered = report_data.filter_findings(config)

        # Should exclude the false positive
        assert len(filtered) == 3

    def test_to_dict(self, sample_findings):
        """Test ReportData.to_dict() serialization."""
        config = ReportConfig(title="Test Report")
        report_data = ReportData(
            config=config,
            findings=sample_findings,
            targets=[{"ip": "192.168.1.1", "name": "Host1"}],
            services=[{"target": "192.168.1.1", "port": 80, "service": "http"}],
        )

        data = report_data.to_dict()

        assert data["config"]["title"] == "Test Report"
        assert len(data["findings"]) == 4
        assert len(data["targets"]) == 1
        assert len(data["services"]) == 1
        assert "statistics" in data
        assert data["statistics"]["total_findings"] == 4
