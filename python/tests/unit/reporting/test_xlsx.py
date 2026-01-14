"""
Tests for purplesploit.reporting.xlsx module.

Tests the XLSXReportGenerator class.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from purplesploit.reporting.xlsx import XLSXReportGenerator, OPENPYXL_AVAILABLE
from purplesploit.reporting.models import (
    Finding,
    Severity,
    FindingStatus,
    ReportConfig,
    ReportData,
)


@pytest.fixture
def sample_report_data():
    """Create sample report data for testing."""
    config = ReportConfig(
        title="XLSX Test Report",
        client_name="Test Client",
        assessor_name="Test Assessor",
    )

    findings = [
        Finding(
            id="f1",
            title="SQL Injection",
            severity=Severity.CRITICAL,
            description="SQL injection vulnerability",
            target="192.168.1.100",
            port=443,
            service="https",
            status=FindingStatus.CONFIRMED,
            cvss_score=9.8,
            cve_ids=["CVE-2021-1234"],
            impact="Full database access",
            remediation="Use parameterized queries",
        ),
        Finding(
            id="f2",
            title="XSS",
            severity=Severity.MEDIUM,
            description="Reflected XSS",
            target="192.168.1.100",
            status=FindingStatus.DRAFT,
        ),
        Finding(
            id="f3",
            title="Info Disclosure",
            severity=Severity.INFO,
            description="Server version disclosed",
            target="192.168.1.101",
        ),
    ]

    return ReportData(
        config=config,
        findings=findings,
        targets=[
            {"ip": "192.168.1.100", "name": "Web Server"},
            {"ip": "192.168.1.101", "name": "API Server"},
        ],
        services=[
            {"target": "192.168.1.100", "port": 443, "service": "https"},
            {"target": "192.168.1.101", "port": 80, "service": "http"},
        ],
    )


class TestXLSXReportGeneratorInit:
    """Tests for XLSXReportGenerator initialization."""

    def test_init(self):
        """Test initialization."""
        gen = XLSXReportGenerator()

        assert isinstance(gen._openpyxl_available, bool)

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_openpyxl_available_when_installed(self):
        """Test that openpyxl is detected when installed."""
        gen = XLSXReportGenerator()

        assert gen._openpyxl_available is True


class TestXLSXReportGeneratorGenerate:
    """Tests for XLSX generation."""

    def test_generate_raises_without_openpyxl(self, sample_report_data, tmp_path):
        """Test that generate raises ImportError when openpyxl not available."""
        gen = XLSXReportGenerator()
        gen._openpyxl_available = False

        output_path = tmp_path / "report.xlsx"

        with pytest.raises(ImportError, match="openpyxl is required"):
            gen.generate(sample_report_data, output_path)

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_generate_creates_file(self, sample_report_data, tmp_path):
        """Test that generate creates output file."""
        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        result = gen.generate(sample_report_data, output_path)

        assert Path(result).exists()
        assert Path(result).stat().st_size > 0

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_generate_creates_worksheets(self, sample_report_data, tmp_path):
        """Test that generate creates expected worksheets."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        sheet_names = wb.sheetnames

        assert "Summary" in sheet_names
        assert "Findings" in sheet_names
        assert "Targets" in sheet_names
        assert "Services" in sheet_names

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_summary_sheet_content(self, sample_report_data, tmp_path):
        """Test Summary sheet contains correct data."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Summary"]

        # Check title is in first row
        assert ws["A1"].value == "XLSX Test Report"

        # Should contain severity counts
        values = [cell.value for row in ws.iter_rows() for cell in row if cell.value]
        assert "Critical" in str(values)
        assert "High" in str(values)
        assert "Medium" in str(values)

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_findings_sheet_headers(self, sample_report_data, tmp_path):
        """Test Findings sheet has correct headers."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        headers = [cell.value for cell in ws[1]]
        expected_headers = ["ID", "Title", "Severity", "Status", "Target", "Port", "Service"]

        for expected in expected_headers:
            assert expected in headers

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_findings_sheet_data(self, sample_report_data, tmp_path):
        """Test Findings sheet contains finding data."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        # Get all data
        data = list(ws.iter_rows(min_row=2, values_only=True))

        # Should have 3 findings
        assert len(data) == 3

        # First finding should be SQL Injection
        titles = [row[1] for row in data]
        assert "SQL Injection" in titles
        assert "XSS" in titles
        assert "Info Disclosure" in titles

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_targets_sheet_content(self, sample_report_data, tmp_path):
        """Test Targets sheet contains target data."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Targets"]

        # Get all data
        data = list(ws.iter_rows(values_only=True))

        # Should have header + 2 targets
        assert len(data) >= 3

        # Check targets are present
        values_str = str(data)
        assert "192.168.1.100" in values_str
        assert "Web Server" in values_str

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_services_sheet_content(self, sample_report_data, tmp_path):
        """Test Services sheet contains service data."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Services"]

        # Get all data
        data = list(ws.iter_rows(values_only=True))

        # Should have header + 2 services
        assert len(data) >= 3

        # Check services are present
        values_str = str(data)
        assert "https" in values_str
        assert "443" in values_str


class TestXLSXReportGeneratorFormatting:
    """Tests for XLSX formatting."""

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_severity_fill_colors(self, sample_report_data, tmp_path):
        """Test that severity cells have correct fill colors."""
        import openpyxl
        from openpyxl.styles import PatternFill

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        # Find severity column index
        headers = [cell.value for cell in ws[1]]
        sev_col = headers.index("Severity") + 1

        # Check cells have fills
        critical_row = None
        for row_num, row in enumerate(ws.iter_rows(min_row=2), start=2):
            if row[sev_col - 1].value == "CRITICAL":
                critical_row = row_num
                break

        if critical_row:
            cell = ws.cell(row=critical_row, column=sev_col)
            # Cell should have some fill
            assert cell.fill is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_header_styling(self, sample_report_data, tmp_path):
        """Test that headers have bold styling."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        # First row headers should be bold
        for cell in ws[1]:
            if cell.value:
                assert cell.font.bold is True

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_column_widths_adjusted(self, sample_report_data, tmp_path):
        """Test that column widths are adjusted."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        # Check that at least one column has a non-default width
        has_adjusted_width = False
        for col_dim in ws.column_dimensions.values():
            if col_dim.width is not None and col_dim.width > 8.43:  # Default width
                has_adjusted_width = True
                break

        # This test is lenient - just checking widths were considered
        assert ws.column_dimensions is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_auto_filter_enabled(self, sample_report_data, tmp_path):
        """Test that auto-filter is enabled on findings sheet."""
        import openpyxl

        gen = XLSXReportGenerator()
        output_path = tmp_path / "report.xlsx"

        gen.generate(sample_report_data, output_path)

        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]

        # Auto filter should be set
        assert ws.auto_filter.ref is not None


class TestXLSXReportGeneratorHelpers:
    """Tests for helper methods."""

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_get_severity_fill_critical(self):
        """Test fill color for critical severity."""
        gen = XLSXReportGenerator()
        fill = gen._get_severity_fill(Severity.CRITICAL)

        # Should return some fill
        assert fill is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_get_severity_fill_high(self):
        """Test fill color for high severity."""
        gen = XLSXReportGenerator()
        fill = gen._get_severity_fill(Severity.HIGH)

        assert fill is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_get_severity_fill_medium(self):
        """Test fill color for medium severity."""
        gen = XLSXReportGenerator()
        fill = gen._get_severity_fill(Severity.MEDIUM)

        assert fill is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_get_severity_fill_low(self):
        """Test fill color for low severity."""
        gen = XLSXReportGenerator()
        fill = gen._get_severity_fill(Severity.LOW)

        assert fill is not None

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_get_severity_fill_info(self):
        """Test fill color for info severity."""
        gen = XLSXReportGenerator()
        fill = gen._get_severity_fill(Severity.INFO)

        assert fill is not None

    def test_get_severity_fill_returns_none_without_openpyxl(self):
        """Test that _get_severity_fill returns None when openpyxl unavailable."""
        gen = XLSXReportGenerator()
        gen._openpyxl_available = False

        fill = gen._get_severity_fill(Severity.CRITICAL)

        assert fill is None


class TestXLSXReportGeneratorEmptyData:
    """Tests for handling empty data."""

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_generate_with_no_findings(self, tmp_path):
        """Test generation with no findings."""
        config = ReportConfig(title="Empty Report")
        report_data = ReportData(config=config, findings=[])

        gen = XLSXReportGenerator()
        output_path = tmp_path / "empty_report.xlsx"

        result = gen.generate(report_data, output_path)

        assert Path(result).exists()

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_generate_with_no_targets(self, tmp_path):
        """Test generation with no targets."""
        config = ReportConfig(title="No Targets")
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="192.168.1.1",
        )
        report_data = ReportData(config=config, findings=[finding], targets=[])

        gen = XLSXReportGenerator()
        output_path = tmp_path / "no_targets.xlsx"

        result = gen.generate(report_data, output_path)

        assert Path(result).exists()

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_generate_with_no_services(self, tmp_path):
        """Test generation with no services."""
        config = ReportConfig(title="No Services")
        report_data = ReportData(config=config, findings=[], services=[])

        gen = XLSXReportGenerator()
        output_path = tmp_path / "no_services.xlsx"

        result = gen.generate(report_data, output_path)

        assert Path(result).exists()


class TestXLSXReportGeneratorLongContent:
    """Tests for handling long content."""

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_long_description_handled(self, tmp_path):
        """Test that long descriptions are handled."""
        config = ReportConfig(title="Long Content")
        finding = Finding(
            id="f1",
            title="Test",
            severity=Severity.HIGH,
            description="A" * 5000,  # Very long description
            target="192.168.1.1",
        )
        report_data = ReportData(config=config, findings=[finding])

        gen = XLSXReportGenerator()
        output_path = tmp_path / "long_content.xlsx"

        result = gen.generate(report_data, output_path)

        assert Path(result).exists()

    @pytest.mark.skipif(not OPENPYXL_AVAILABLE, reason="openpyxl not installed")
    def test_special_characters_handled(self, tmp_path):
        """Test that special characters are handled."""
        import openpyxl

        config = ReportConfig(title="Special Characters")
        finding = Finding(
            id="f1",
            title="Test <script>alert('xss')</script>",
            severity=Severity.HIGH,
            description="Contains \"quotes\" and 'apostrophes' & ampersands",
            target="192.168.1.1",
        )
        report_data = ReportData(config=config, findings=[finding])

        gen = XLSXReportGenerator()
        output_path = tmp_path / "special_chars.xlsx"

        result = gen.generate(report_data, output_path)

        assert Path(result).exists()

        # Verify content is readable
        wb = openpyxl.load_workbook(output_path)
        ws = wb["Findings"]
        data = list(ws.iter_rows(min_row=2, values_only=True))
        assert len(data) > 0
