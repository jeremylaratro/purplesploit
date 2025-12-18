"""
Tests for purplesploit.reporting.generator module.

Tests the ReportGenerator class and quick_report function.
"""

import pytest
import json
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from purplesploit.reporting.generator import ReportGenerator, quick_report
from purplesploit.reporting.models import (
    Finding,
    Severity,
    FindingStatus,
    ReportConfig,
    ReportData,
)


class TestReportGeneratorInit:
    """Tests for ReportGenerator initialization."""

    def test_init_without_framework(self):
        """Test initialization without framework."""
        gen = ReportGenerator()

        assert gen.framework is None
        assert gen.findings == []
        assert isinstance(gen.config, ReportConfig)

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        gen = ReportGenerator(framework=mock_framework)

        assert gen.framework == mock_framework


class TestReportGeneratorFindings:
    """Tests for findings management."""

    def test_add_finding(self):
        """Test adding a single finding."""
        gen = ReportGenerator()
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.HIGH,
            description="Test finding",
            target="192.168.1.1",
        )

        gen.add_finding(finding)

        assert len(gen.findings) == 1
        assert gen.findings[0].id == "f1"

    def test_add_findings(self):
        """Test adding multiple findings."""
        gen = ReportGenerator()
        findings = [
            Finding(
                id="f1",
                title="Test1",
                severity=Severity.HIGH,
                description="Test1",
                target="192.168.1.1",
            ),
            Finding(
                id="f2",
                title="Test2",
                severity=Severity.MEDIUM,
                description="Test2",
                target="192.168.1.2",
            ),
        ]

        gen.add_findings(findings)

        assert len(gen.findings) == 2

    def test_clear_findings(self):
        """Test clearing all findings."""
        gen = ReportGenerator()
        gen.add_finding(
            Finding(
                id="f1",
                title="Test",
                severity=Severity.LOW,
                description="Test",
                target="test",
            )
        )

        gen.clear_findings()

        assert len(gen.findings) == 0

    def test_create_finding(self):
        """Test creating a finding via create_finding method."""
        gen = ReportGenerator()

        finding = gen.create_finding(
            title="SQL Injection",
            severity="high",
            description="SQL injection found",
            target="192.168.1.100",
            port=443,
            service="https",
        )

        assert len(gen.findings) == 1
        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.HIGH
        assert finding.port == 443
        assert finding.service == "https"

    def test_create_finding_with_kwargs(self):
        """Test creating a finding with additional kwargs."""
        gen = ReportGenerator()

        finding = gen.create_finding(
            title="XSS",
            severity="medium",
            description="XSS found",
            target="example.com",
            cvss_score=6.5,
            cve_ids=["CVE-2024-1234"],
            remediation="Sanitize input",
        )

        assert finding.cvss_score == 6.5
        assert finding.cve_ids == ["CVE-2024-1234"]
        assert finding.remediation == "Sanitize input"


class TestReportGeneratorConfig:
    """Tests for configuration management."""

    def test_set_config(self):
        """Test setting report configuration."""
        gen = ReportGenerator()
        config = ReportConfig(
            title="Custom Report",
            client_name="ACME Corp",
        )

        gen.set_config(config)

        assert gen.config.title == "Custom Report"
        assert gen.config.client_name == "ACME Corp"


class TestReportGeneratorBuildData:
    """Tests for building report data."""

    def test_build_report_data_without_framework(self):
        """Test building report data without framework."""
        gen = ReportGenerator()
        gen.create_finding(
            title="Test",
            severity="high",
            description="Test",
            target="192.168.1.1",
        )

        report_data = gen._build_report_data()

        assert isinstance(report_data, ReportData)
        assert len(report_data.findings) == 1
        assert report_data.targets == []
        assert report_data.services == []

    def test_build_report_data_with_framework(self):
        """Test building report data with framework database."""
        mock_target = Mock()
        mock_target.to_dict.return_value = {"ip": "192.168.1.1", "name": "Host1"}

        mock_service = Mock()
        mock_service.to_dict.return_value = {"port": 80, "service": "http"}

        mock_cred = Mock()
        mock_cred.to_dict.return_value = {"username": "admin"}

        mock_db = Mock()
        mock_db.get_all_targets.return_value = [mock_target]
        mock_db.get_all_services.return_value = [mock_service]
        mock_db.get_all_credentials.return_value = [mock_cred]

        mock_framework = Mock()
        mock_framework.database = mock_db

        gen = ReportGenerator(framework=mock_framework)
        gen.create_finding(
            title="Test",
            severity="high",
            description="Test",
            target="192.168.1.1",
        )

        report_data = gen._build_report_data()

        assert len(report_data.targets) == 1
        assert len(report_data.services) == 1
        assert len(report_data.credentials) == 1


class TestReportGeneratorGenerate:
    """Tests for report generation."""

    @pytest.fixture
    def generator_with_findings(self, tmp_path):
        """Create generator with sample findings."""
        gen = ReportGenerator()
        gen.config.output_dir = str(tmp_path)

        gen.create_finding(
            title="Critical Vulnerability",
            severity="critical",
            description="A critical security issue",
            target="192.168.1.1",
        )
        gen.create_finding(
            title="Medium Issue",
            severity="medium",
            description="A medium security issue",
            target="192.168.1.2",
        )

        return gen

    def test_generate_json(self, generator_with_findings, tmp_path):
        """Test JSON report generation."""
        output_path = tmp_path / "report.json"

        result = generator_with_findings.generate("json", str(output_path))

        assert Path(result).exists()
        with open(result) as f:
            data = json.load(f)
        assert "findings" in data
        assert len(data["findings"]) == 2

    def test_generate_json_auto_path(self, generator_with_findings, tmp_path):
        """Test JSON generation with auto-generated path."""
        result = generator_with_findings.generate("json")

        assert Path(result).exists()
        assert result.endswith(".json")

    def test_generate_invalid_format(self, generator_with_findings):
        """Test that invalid format raises ValueError."""
        with pytest.raises(ValueError, match="Unsupported format"):
            generator_with_findings.generate("invalid_format")

    @patch('purplesploit.reporting.generator.HTMLReportGenerator')
    def test_generate_html(self, mock_html_gen, generator_with_findings, tmp_path):
        """Test HTML report generation."""
        mock_instance = Mock()
        mock_instance.generate.return_value = str(tmp_path / "report.html")
        mock_html_gen.return_value = mock_instance

        output_path = tmp_path / "report.html"
        result = generator_with_findings.generate("html", str(output_path))

        mock_html_gen.assert_called_once()
        mock_instance.generate.assert_called_once()

    @patch('purplesploit.reporting.generator.MarkdownReportGenerator')
    def test_generate_markdown(self, mock_md_gen, generator_with_findings, tmp_path):
        """Test Markdown report generation."""
        mock_instance = Mock()
        mock_instance.generate.return_value = str(tmp_path / "report.md")
        mock_md_gen.return_value = mock_instance

        output_path = tmp_path / "report.md"
        result = generator_with_findings.generate("markdown", str(output_path))

        mock_md_gen.assert_called_once()
        mock_instance.generate.assert_called_once()

    @patch('purplesploit.reporting.generator.MarkdownReportGenerator')
    def test_generate_md_alias(self, mock_md_gen, generator_with_findings, tmp_path):
        """Test 'md' as alias for markdown format."""
        mock_instance = Mock()
        mock_instance.generate.return_value = str(tmp_path / "report.md")
        mock_md_gen.return_value = mock_instance

        output_path = tmp_path / "report.md"
        result = generator_with_findings.generate("md", str(output_path))

        mock_md_gen.assert_called_once()

    @patch('purplesploit.reporting.generator.PDFReportGenerator')
    def test_generate_pdf(self, mock_pdf_gen, generator_with_findings, tmp_path):
        """Test PDF report generation."""
        mock_instance = Mock()
        mock_instance.generate.return_value = str(tmp_path / "report.pdf")
        mock_pdf_gen.return_value = mock_instance

        output_path = tmp_path / "report.pdf"
        result = generator_with_findings.generate("pdf", str(output_path))

        mock_pdf_gen.assert_called_once()

    @patch('purplesploit.reporting.generator.XLSXReportGenerator')
    def test_generate_xlsx(self, mock_xlsx_gen, generator_with_findings, tmp_path):
        """Test XLSX report generation."""
        mock_instance = Mock()
        mock_instance.generate.return_value = str(tmp_path / "report.xlsx")
        mock_xlsx_gen.return_value = mock_instance

        output_path = tmp_path / "report.xlsx"
        result = generator_with_findings.generate("xlsx", str(output_path))

        mock_xlsx_gen.assert_called_once()

    def test_generate_creates_parent_directory(self, generator_with_findings, tmp_path):
        """Test that generate creates parent directories."""
        output_path = tmp_path / "subdir" / "nested" / "report.json"

        result = generator_with_findings.generate("json", str(output_path))

        assert Path(result).exists()
        assert (tmp_path / "subdir" / "nested").is_dir()


class TestReportGeneratorJsonIO:
    """Tests for JSON import/export of findings."""

    def test_save_findings_to_json(self, tmp_path):
        """Test saving findings to JSON file."""
        gen = ReportGenerator()
        gen.create_finding(
            title="Test Finding",
            severity="high",
            description="Test description",
            target="192.168.1.1",
        )

        json_path = tmp_path / "findings.json"
        gen.save_findings_to_json(str(json_path))

        assert json_path.exists()
        with open(json_path) as f:
            data = json.load(f)
        assert len(data) == 1
        assert data[0]["title"] == "Test Finding"

    def test_load_findings_from_json_list(self, tmp_path):
        """Test loading findings from JSON list format."""
        findings_data = [
            {
                "id": "f1",
                "title": "Finding 1",
                "severity": "high",
                "description": "Desc 1",
                "target": "192.168.1.1",
                "status": "draft",
                "evidence": [],
                "cve_ids": [],
                "cwe_ids": [],
                "references": [],
                "mitre_tactics": [],
                "mitre_techniques": [],
                "notes": "",
            },
            {
                "id": "f2",
                "title": "Finding 2",
                "severity": "medium",
                "description": "Desc 2",
                "target": "192.168.1.2",
                "status": "confirmed",
                "evidence": [],
                "cve_ids": [],
                "cwe_ids": [],
                "references": [],
                "mitre_tactics": [],
                "mitre_techniques": [],
                "notes": "",
            },
        ]

        json_path = tmp_path / "findings.json"
        with open(json_path, "w") as f:
            json.dump(findings_data, f)

        gen = ReportGenerator()
        gen.load_findings_from_json(str(json_path))

        assert len(gen.findings) == 2
        assert gen.findings[0].title == "Finding 1"

    def test_load_findings_from_json_report_format(self, tmp_path):
        """Test loading findings from full report JSON format."""
        report_data = {
            "config": {"title": "Test Report"},
            "findings": [
                {
                    "id": "f1",
                    "title": "Finding 1",
                    "severity": "high",
                    "description": "Desc",
                    "target": "192.168.1.1",
                    "status": "draft",
                    "evidence": [],
                    "cve_ids": [],
                    "cwe_ids": [],
                    "references": [],
                    "mitre_tactics": [],
                    "mitre_techniques": [],
                    "notes": "",
                }
            ],
        }

        json_path = tmp_path / "report.json"
        with open(json_path, "w") as f:
            json.dump(report_data, f)

        gen = ReportGenerator()
        gen.load_findings_from_json(str(json_path))

        assert len(gen.findings) == 1


class TestReportGeneratorSummary:
    """Tests for summary generation."""

    def test_get_summary(self):
        """Test getting findings summary."""
        gen = ReportGenerator()
        gen.create_finding(
            title="Critical1", severity="critical", description="", target="192.168.1.1"
        )
        gen.create_finding(
            title="Critical2", severity="critical", description="", target="192.168.1.1"
        )
        gen.create_finding(
            title="High1", severity="high", description="", target="192.168.1.2"
        )
        gen.create_finding(
            title="Medium1", severity="medium", description="", target="192.168.1.3"
        )

        summary = gen.get_summary()

        assert summary["total_findings"] == 4
        assert summary["severity_counts"]["critical"] == 2
        assert summary["severity_counts"]["high"] == 1
        assert summary["critical_count"] == 2
        assert summary["high_count"] == 1
        assert summary["unique_targets"] == 3
        assert summary["findings_by_target"]["192.168.1.1"] == 2


class TestReportGeneratorImportFromModule:
    """Tests for importing findings from module results."""

    def test_import_from_module_result_success(self):
        """Test importing finding from successful module result."""
        gen = ReportGenerator()

        result = {
            "success": True,
            "title": "SQL Injection Detected",
            "description": "SQL injection vulnerability found in login form",
            "severity": "high",
            "port": 443,
            "service": "https",
            "stdout": "Parameter 'id' is vulnerable",
        }

        finding = gen.import_from_module_result(
            module_name="sqlmap",
            result=result,
            target="192.168.1.100",
        )

        assert finding is not None
        assert finding.title == "SQL Injection Detected"
        assert finding.severity == Severity.HIGH
        assert finding.port == 443
        assert finding.module_name == "sqlmap"
        assert len(gen.findings) == 1

    def test_import_from_module_result_failure(self):
        """Test that failed module results are not imported."""
        gen = ReportGenerator()

        result = {"success": False, "error": "Connection failed"}

        finding = gen.import_from_module_result(
            module_name="nmap",
            result=result,
            target="192.168.1.100",
        )

        assert finding is None
        assert len(gen.findings) == 0

    def test_import_from_module_result_no_description(self):
        """Test that results without description are not imported."""
        gen = ReportGenerator()

        result = {"success": True, "title": "Finding"}

        finding = gen.import_from_module_result(
            module_name="module",
            result=result,
            target="192.168.1.100",
        )

        assert finding is None

    def test_import_from_module_result_default_severity(self):
        """Test default severity assignment."""
        gen = ReportGenerator()

        result = {
            "success": True,
            "description": "Information disclosure",
            "output": "Server version: Apache 2.4",
        }

        finding = gen.import_from_module_result(
            module_name="httpx",
            result=result,
            target="192.168.1.100",
            auto_severity="low",
        )

        assert finding.severity == Severity.LOW


class TestQuickReport:
    """Tests for quick_report convenience function."""

    def test_quick_report_basic(self, tmp_path):
        """Test quick_report with basic parameters."""
        findings = [
            {
                "title": "Test Finding",
                "severity": "high",
                "description": "Test description",
                "target": "192.168.1.1",
            }
        ]

        output_path = tmp_path / "quick_report.json"
        result = quick_report(
            findings=findings,
            output_path=str(output_path),
            format="json",
        )

        assert Path(result).exists()

    def test_quick_report_with_config(self, tmp_path):
        """Test quick_report with config options."""
        findings = [
            {
                "title": "Test Finding",
                "severity": "medium",
                "description": "Test",
                "target": "example.com",
            }
        ]

        output_path = tmp_path / "report.json"
        result = quick_report(
            findings=findings,
            output_path=str(output_path),
            format="json",
            title="Custom Title",
            client_name="Test Client",
        )

        with open(result) as f:
            data = json.load(f)

        assert data["config"]["title"] == "Custom Title"
        assert data["config"]["client_name"] == "Test Client"
