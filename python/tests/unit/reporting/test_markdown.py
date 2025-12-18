"""
Tests for purplesploit.reporting.markdown module.

Tests the MarkdownReportGenerator class.
"""

import pytest
from pathlib import Path
from datetime import datetime

from purplesploit.reporting.markdown import MarkdownReportGenerator
from purplesploit.reporting.models import (
    Finding,
    Evidence,
    Severity,
    FindingStatus,
    ReportConfig,
    ReportData,
)


@pytest.fixture
def sample_report_data():
    """Create sample report data for testing."""
    config = ReportConfig(
        title="Security Assessment Report",
        subtitle="Penetration Test Results",
        client_name="ACME Corporation",
        assessor_name="John Security",
        assessment_type="Web Application Penetration Test",
        scope=["192.168.1.0/24", "example.com"],
        start_date=datetime(2025, 1, 1),
        end_date=datetime(2025, 1, 15),
        include_executive_summary=True,
        include_findings_detail=True,
        include_appendix=True,
    )

    findings = [
        Finding(
            id="f1",
            title="Critical SQL Injection",
            severity=Severity.CRITICAL,
            description="SQL injection vulnerability allows database access",
            target="192.168.1.100",
            port=443,
            service="https",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cve_ids=["CVE-2021-12345"],
            cwe_ids=["CWE-89"],
            impact="Full database compromise possible",
            remediation="Use parameterized queries and input validation",
            references=["https://owasp.org/sqli"],
            mitre_tactics=["Initial Access"],
            mitre_techniques=["T1190"],
            module_name="sqlmap",
            raw_output="Parameter 'id' is vulnerable",
        ),
        Finding(
            id="f2",
            title="Cross-Site Scripting",
            severity=Severity.MEDIUM,
            description="Reflected XSS in search functionality",
            target="192.168.1.100",
            port=443,
            service="https",
            impact="Session hijacking possible",
            remediation="Encode all output",
        ),
    ]

    return ReportData(
        config=config,
        findings=findings,
        targets=[
            {"ip": "192.168.1.100", "name": "Web Server", "description": "Main web server"},
        ],
        services=[
            {"target": "192.168.1.100", "port": 443, "service": "https", "version": "nginx/1.18"},
        ],
    )


class TestMarkdownReportGeneratorGenerate:
    """Tests for Markdown report generation."""

    def test_generate_creates_file(self, sample_report_data, tmp_path):
        """Test that generate creates output file."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        assert Path(result).stat().st_size > 0

    def test_generate_contains_title(self, sample_report_data, tmp_path):
        """Test that generated markdown contains title."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "# Security Assessment Report" in content

    def test_generate_contains_subtitle(self, sample_report_data, tmp_path):
        """Test that subtitle is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "Penetration Test Results" in content

    def test_generate_contains_report_info(self, sample_report_data, tmp_path):
        """Test that report information table is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Report Information" in content
        assert "ACME Corporation" in content
        assert "John Security" in content

    def test_generate_contains_toc(self, sample_report_data, tmp_path):
        """Test that table of contents is included by default."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Table of Contents" in content
        assert "#executive-summary" in content
        assert "#findings-summary" in content
        assert "#detailed-findings" in content

    def test_generate_without_toc(self, sample_report_data, tmp_path):
        """Test generation without table of contents."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path, include_toc=False)
        content = Path(output_path).read_text()

        assert "## Table of Contents" not in content

    def test_generate_contains_executive_summary(self, sample_report_data, tmp_path):
        """Test that executive summary is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Executive Summary" in content
        assert "identified **2** security findings" in content

    def test_generate_executive_summary_critical_alert(self, sample_report_data, tmp_path):
        """Test that critical findings trigger alert in summary."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "Immediate attention required" in content
        assert "Critical severity" in content

    def test_generate_contains_scope(self, sample_report_data, tmp_path):
        """Test that scope is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "### Scope" in content
        assert "192.168.1.0/24" in content
        assert "example.com" in content

    def test_generate_contains_findings_summary(self, sample_report_data, tmp_path):
        """Test that findings summary table is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Findings Summary" in content
        assert "| Severity | Count |" in content
        assert "TOTAL" in content

    def test_generate_contains_detailed_findings(self, sample_report_data, tmp_path):
        """Test that detailed findings section is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Detailed Findings" in content
        assert "#### Critical SQL Injection" in content
        assert "#### Cross-Site Scripting" in content

    def test_generate_finding_metadata_table(self, sample_report_data, tmp_path):
        """Test that finding metadata tables are included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "| **ID** |" in content
        assert "| **Severity** |" in content
        assert "| **Target** |" in content

    def test_generate_finding_cvss_info(self, sample_report_data, tmp_path):
        """Test that CVSS information is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "| **CVSS Score** | 9.8 |" in content
        assert "CVSS:3.1" in content

    def test_generate_finding_cve_references(self, sample_report_data, tmp_path):
        """Test that CVE references are linked."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "**CVE References:**" in content
        assert "CVE-2021-12345" in content
        assert "nvd.nist.gov" in content

    def test_generate_finding_cwe_references(self, sample_report_data, tmp_path):
        """Test that CWE references are linked."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "**CWE References:**" in content
        assert "CWE-89" in content
        assert "cwe.mitre.org" in content

    def test_generate_finding_mitre_mapping(self, sample_report_data, tmp_path):
        """Test that MITRE ATT&CK mapping is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "**MITRE ATT&CK Mapping:**" in content
        assert "Initial Access" in content
        assert "T1190" in content

    def test_generate_finding_impact_remediation(self, sample_report_data, tmp_path):
        """Test that impact and remediation are included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "**Impact:**" in content
        assert "Full database compromise" in content
        assert "**Remediation:**" in content
        assert "parameterized queries" in content

    def test_generate_finding_references(self, sample_report_data, tmp_path):
        """Test that references are included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "**References:**" in content
        assert "https://owasp.org/sqli" in content

    def test_generate_targets_appendix(self, sample_report_data, tmp_path):
        """Test that targets appendix is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Targets" in content
        assert "| Name | IP/URL | Description |" in content
        assert "Web Server" in content

    def test_generate_services_appendix(self, sample_report_data, tmp_path):
        """Test that services appendix is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Services" in content
        assert "| Target | Port | Service | Version |" in content
        assert "nginx/1.18" in content

    def test_generate_contains_footer(self, sample_report_data, tmp_path):
        """Test that footer is included."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path)
        content = Path(output_path).read_text()

        assert "Generated by PurpleSploit" in content

    def test_generate_with_raw_output(self, tmp_path):
        """Test generation with raw output enabled."""
        config = ReportConfig(
            title="Test",
            include_raw_output=True,
        )
        findings = [
            Finding(
                id="f1",
                title="Test Finding",
                severity=Severity.HIGH,
                description="Test",
                target="192.168.1.1",
                raw_output="Command output here",
            )
        ]
        report_data = ReportData(config=config, findings=findings)

        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(report_data, output_path)
        content = Path(output_path).read_text()

        assert "<details>" in content
        assert "Raw Output" in content
        assert "Command output here" in content

    def test_generate_with_evidence(self, tmp_path):
        """Test generation with evidence included."""
        config = ReportConfig(
            title="Test",
            include_evidence=True,
        )
        finding = Finding(
            id="f1",
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test",
            target="192.168.1.1",
        )
        evidence = Evidence(
            id="ev1",
            finding_id="f1",
            description="Screenshot of vulnerability",
            content="Error message captured",
            file_path="/tmp/screenshot.png",
        )
        finding.evidence.append(evidence)

        report_data = ReportData(config=config, findings=[finding])

        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(report_data, output_path)
        content = Path(output_path).read_text()

        assert "**Evidence:**" in content
        assert "Screenshot of vulnerability" in content
        assert "Error message captured" in content

    def test_generate_with_badge_images(self, sample_report_data, tmp_path):
        """Test generation with shields.io badges."""
        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(sample_report_data, output_path, include_badge_images=True)
        content = Path(output_path).read_text()

        assert "img.shields.io/badge" in content

    def test_generate_without_executive_summary(self, tmp_path):
        """Test generation without executive summary."""
        config = ReportConfig(
            title="Test",
            include_executive_summary=False,
        )
        report_data = ReportData(config=config, findings=[])

        gen = MarkdownReportGenerator()
        output_path = tmp_path / "report.md"

        gen.generate(report_data, output_path)
        content = Path(output_path).read_text()

        assert "## Executive Summary" not in content


class TestMarkdownReportGeneratorHelpers:
    """Tests for helper methods."""

    def test_get_severity_emoji_critical(self):
        """Test emoji for critical severity."""
        gen = MarkdownReportGenerator()
        emoji = gen._get_severity_emoji(Severity.CRITICAL)

        # Should return some emoji representation
        assert len(emoji) > 0

    def test_get_severity_emoji_high(self):
        """Test emoji for high severity."""
        gen = MarkdownReportGenerator()
        emoji = gen._get_severity_emoji(Severity.HIGH)

        assert len(emoji) > 0

    def test_get_severity_emoji_medium(self):
        """Test emoji for medium severity."""
        gen = MarkdownReportGenerator()
        emoji = gen._get_severity_emoji(Severity.MEDIUM)

        assert len(emoji) > 0

    def test_get_severity_emoji_low(self):
        """Test emoji for low severity."""
        gen = MarkdownReportGenerator()
        emoji = gen._get_severity_emoji(Severity.LOW)

        assert len(emoji) > 0

    def test_get_severity_emoji_info(self):
        """Test emoji for info severity."""
        gen = MarkdownReportGenerator()
        emoji = gen._get_severity_emoji(Severity.INFO)

        assert len(emoji) > 0

    def test_get_badge_color_critical(self):
        """Test badge color for critical."""
        gen = MarkdownReportGenerator()
        color = gen._get_badge_color(Severity.CRITICAL)

        assert color == "7b241c"

    def test_get_badge_color_high(self):
        """Test badge color for high."""
        gen = MarkdownReportGenerator()
        color = gen._get_badge_color(Severity.HIGH)

        assert color == "c0392b"


class TestMarkdownReportGeneratorFindingFormat:
    """Tests for finding formatting."""

    def test_format_finding_basic(self):
        """Test basic finding formatting."""
        gen = MarkdownReportGenerator()
        config = ReportConfig()
        finding = Finding(
            id="f1",
            title="Test Finding",
            severity=Severity.HIGH,
            description="Description text",
            target="192.168.1.1",
        )

        lines = gen._format_finding(finding, config)

        assert len(lines) > 0
        # Should contain title, metadata, description
        content = "\n".join(lines)
        assert "Test Finding" in content
        assert "HIGH" in content
        assert "192.168.1.1" in content
        assert "Description text" in content

    def test_format_finding_with_port_service(self):
        """Test finding formatting with port and service."""
        gen = MarkdownReportGenerator()
        config = ReportConfig()
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.MEDIUM,
            description="Test",
            target="192.168.1.1",
            port=8080,
            service="http",
        )

        lines = gen._format_finding(finding, config)
        content = "\n".join(lines)

        assert "8080" in content
        assert "http" in content

    def test_format_finding_without_optional_fields(self):
        """Test finding formatting without optional fields."""
        gen = MarkdownReportGenerator()
        config = ReportConfig()
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.LOW,
            description="Test",
            target="test.local",
        )

        lines = gen._format_finding(finding, config)
        content = "\n".join(lines)

        # Should not have Impact section if empty
        assert "**Impact:**" not in content or finding.impact in content

    def test_format_finding_ends_with_separator(self):
        """Test that formatted finding ends with separator."""
        gen = MarkdownReportGenerator()
        config = ReportConfig()
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.INFO,
            description="Test",
            target="test.local",
        )

        lines = gen._format_finding(finding, config)

        assert "---" in lines
