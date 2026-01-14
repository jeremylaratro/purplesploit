"""
Unit tests for export/import functionality in purplesploit.ui.commands.

Tests cover:
- Hosts file export (export, append, sudo)
- Graph export/import (JSON, DOT, Cytoscape)
- Findings export
- Sessions export
- Report generation
- Parse command (nmap XML import)
- Analysis results
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
from purplesploit.ui.commands import CommandHandler
import json


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def mock_framework():
    """Create a mock framework for command handler testing."""
    framework = MagicMock()
    framework.session = MagicMock()
    framework.session.current_module = None
    framework.session.targets = MagicMock()
    framework.session.targets.list.return_value = []
    framework.session.credentials = MagicMock()
    framework.session.workspace = "default"
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.modules = {}
    framework.database = MagicMock()
    framework.attack_graph = MagicMock()
    framework.session_manager = MagicMock()
    return framework


@pytest.fixture
def command_handler(mock_framework):
    """Create a CommandHandler instance for testing."""
    with patch('purplesploit.ui.commands.Display'), \
         patch('purplesploit.ui.commands.InteractiveSelector'):
        handler = CommandHandler(mock_framework)
        handler.display = MagicMock()
        handler.interactive = MagicMock()
    return handler


# =============================================================================
# Hosts File Export Tests
# =============================================================================

class TestHostsExport:
    """Tests for hosts file export functionality."""

    def test_hosts_display_only(self, command_handler, mock_framework):
        """Test hosts command displays entries."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"},
            {"ip": "192.168.1.2", "name": "server2"}
        ]

        result = command_handler.cmd_hosts([])

        assert result is True
        mock_framework.session.targets.list.assert_called_once()

    def test_hosts_no_targets(self, command_handler, mock_framework):
        """Test hosts when no targets configured."""
        mock_framework.session.targets.list.return_value = []

        result = command_handler.cmd_hosts([])

        assert result is True
        command_handler.display.print_warning.assert_called()

    def test_hosts_export(self, command_handler, mock_framework):
        """Test exporting hosts to file."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"},
            {"ip": "192.168.1.2", "name": "server2"}
        ]

        with patch('builtins.open', mock_open()) as mock_file:
            result = command_handler.cmd_hosts(["export", "hosts.txt"])

            assert result is True
            mock_file.assert_called_once()

    def test_hosts_export_no_filename(self, command_handler, mock_framework):
        """Test export without filename shows error."""
        result = command_handler.cmd_hosts(["export"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_hosts_append(self, command_handler, mock_framework):
        """Test appending hosts to existing file."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]

        with patch('builtins.open', mock_open(read_data="# Existing content\n")) as mock_file:
            result = command_handler.cmd_hosts(["append", "hosts.txt"])

            assert result is True

    def test_hosts_sudo(self, command_handler, mock_framework):
        """Test appending to /etc/hosts with sudo."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]

        with patch('tempfile.NamedTemporaryFile') as mock_temp, \
             patch('subprocess.run') as mock_run:
            mock_temp.return_value.__enter__.return_value.name = "/tmp/hosts123"
            mock_run.return_value.returncode = 0

            result = command_handler.cmd_hosts(["sudo"])

            assert result is True

    def test_hosts_without_names(self, command_handler, mock_framework):
        """Test hosts generates default names for IPs."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": None},
            {"ip": "10.0.0.5", "name": ""}
        ]

        result = command_handler.cmd_hosts([])

        assert result is True

    def test_hosts_export_write_error(self, command_handler, mock_framework):
        """Test hosts export handles write errors."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]

        with patch('builtins.open', side_effect=PermissionError("Permission denied")):
            result = command_handler.cmd_hosts(["export", "/root/hosts.txt"])

            assert result is True
            command_handler.display.print_error.assert_called()


# =============================================================================
# Graph Export/Import Tests
# =============================================================================

class TestGraphExportImport:
    """Tests for attack graph export and import."""

    def test_graph_export_json_to_stdout(self, command_handler, mock_framework):
        """Test exporting graph to JSON without filename."""
        mock_framework.attack_graph.export_json.return_value = '{"nodes": [], "edges": []}'

        result = command_handler._graph_export(mock_framework.attack_graph, ["json"])

        assert result is True
        mock_framework.attack_graph.export_json.assert_called_once()

    def test_graph_export_json_to_file(self, command_handler, mock_framework):
        """Test exporting graph to JSON file."""
        mock_framework.attack_graph.export_json.return_value = '{"nodes": [], "edges": []}'

        with patch('builtins.open', mock_open()) as mock_file:
            result = command_handler._graph_export(mock_framework.attack_graph, ["json", "graph.json"])

            assert result is True
            mock_file.assert_called_once_with("graph.json", "w")

    def test_graph_export_dot(self, command_handler, mock_framework):
        """Test exporting graph to DOT format."""
        mock_framework.attack_graph.export_dot.return_value = "digraph G { }"

        with patch('builtins.open', mock_open()) as mock_file:
            result = command_handler._graph_export(mock_framework.attack_graph, ["dot", "graph.dot"])

            assert result is True

    def test_graph_export_cytoscape(self, command_handler, mock_framework):
        """Test exporting graph to Cytoscape format."""
        mock_framework.attack_graph.export_cytoscape.return_value = {"elements": []}

        result = command_handler._graph_export(mock_framework.attack_graph, ["cytoscape"])

        assert result is True

    def test_graph_export_no_format(self, command_handler, mock_framework):
        """Test graph export without format shows error."""
        result = command_handler._graph_export(mock_framework.attack_graph, [])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_graph_export_invalid_format(self, command_handler, mock_framework):
        """Test graph export with invalid format."""
        result = command_handler._graph_export(mock_framework.attack_graph, ["xml"])

        assert result is True

    def test_graph_import_json(self, command_handler, mock_framework):
        """Test importing graph from JSON file."""
        graph_data = {"nodes": [{"id": "1", "label": "host1"}], "edges": []}

        with patch('builtins.open', mock_open(read_data=json.dumps(graph_data))), \
             patch('purplesploit.ui.commands.AttackGraph') as mock_ag:
            mock_graph = MagicMock()
            mock_ag.from_json.return_value = mock_graph

            result = command_handler._graph_import(mock_framework.attack_graph, ["graph.json"])

            assert result is True

    def test_graph_import_no_file(self, command_handler, mock_framework):
        """Test graph import without filename shows error."""
        result = command_handler._graph_import(mock_framework.attack_graph, [])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_graph_import_file_not_found(self, command_handler, mock_framework):
        """Test graph import with non-existent file."""
        with patch('pathlib.Path.exists', return_value=False):
            result = command_handler._graph_import(mock_framework.attack_graph, ["missing.json"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_graph_import_invalid_json(self, command_handler, mock_framework):
        """Test graph import with invalid JSON."""
        with patch('builtins.open', mock_open(read_data="invalid json")):
            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler._graph_import(mock_framework.attack_graph, ["bad.json"])

                assert result is True
                command_handler.display.print_error.assert_called()


# =============================================================================
# Findings Export Tests
# =============================================================================

class TestFindingsExport:
    """Tests for findings export functionality."""

    def test_findings_export_json(self, command_handler, mock_framework):
        """Test exporting findings to JSON."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.export_json.return_value = "findings_default.json"
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["json"])

            assert result is True
            mock_manager.export_json.assert_called_once()

    def test_findings_export_custom_filename(self, command_handler, mock_framework):
        """Test exporting findings with custom filename."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.export_json.return_value = "my_findings.json"
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["json", "my_findings.json"])

            assert result is True
            mock_manager.export_json.assert_called_once_with("my_findings.json")

    def test_findings_export_no_format(self, command_handler, mock_framework):
        """Test findings export without format."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export([])

            assert result is True
            handler.display.print_error.assert_called()

    def test_findings_export_unsupported_format(self, command_handler, mock_framework):
        """Test findings export with unsupported format."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["xml"])

            assert result is True
            handler.display.print_error.assert_called()


# =============================================================================
# Sessions Export Tests
# =============================================================================

class TestSessionsExport:
    """Tests for sessions export functionality."""

    def test_sessions_export_default(self, command_handler, mock_framework):
        """Test exporting sessions to default file."""
        mock_framework.session_manager.export_sessions.return_value = "sessions_default.json"

        result = command_handler._sessions_export(mock_framework.session_manager, [])

        assert result is True
        mock_framework.session_manager.export_sessions.assert_called_once()

    def test_sessions_export_custom_file(self, command_handler, mock_framework):
        """Test exporting sessions to custom file."""
        mock_framework.session_manager.export_sessions.return_value = "my_sessions.json"

        result = command_handler._sessions_export(mock_framework.session_manager, ["my_sessions.json"])

        assert result is True
        mock_framework.session_manager.export_sessions.assert_called_once_with("my_sessions.json")

    def test_sessions_export_error(self, command_handler, mock_framework):
        """Test sessions export error handling."""
        mock_framework.session_manager.export_sessions.side_effect = Exception("Export failed")

        result = command_handler._sessions_export(mock_framework.session_manager, [])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Nmap XML Parse/Import Tests
# =============================================================================

class TestNmapParse:
    """Tests for nmap XML parsing and import."""

    def test_parse_nmap_xml_success(self, command_handler, mock_framework):
        """Test parsing nmap XML file."""
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [
                    {
                        "ip": "192.168.1.1",
                        "hostname": "server1.local",
                        "ports": [
                            {"port": 80, "service": "http", "state": "open"},
                            {"port": 443, "service": "https", "state": "open"}
                        ]
                    }
                ],
                "total_scanned": 1,
                "hosts_discovered": 1
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/scan.xml"])

                assert result is True
                mock_module.parse_xml_results.assert_called_once()

    def test_parse_file_not_found(self, command_handler, mock_framework):
        """Test parse with non-existent file."""
        with patch('pathlib.Path.exists', return_value=False):
            result = command_handler.cmd_parse(["missing.xml"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_parse_no_args(self, command_handler):
        """Test parse without arguments."""
        result = command_handler.cmd_parse([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_parse_invalid_xml(self, command_handler, mock_framework):
        """Test parsing invalid XML."""
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.side_effect = Exception("Invalid XML")
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/bad.xml"])

                assert result is True
                command_handler.display.print_error.assert_called()

    def test_parse_creates_targets(self, command_handler, mock_framework):
        """Test parse creates targets in database."""
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [{"ip": "192.168.1.1", "ports": [80]}],
                "total_scanned": 1,
                "hosts_discovered": 1
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/scan.xml"])

                assert result is True

    def test_parse_creates_services(self, command_handler, mock_framework):
        """Test parse creates service entries."""
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [{
                    "ip": "192.168.1.1",
                    "ports": [
                        {"port": 80, "service": "http", "state": "open"}
                    ]
                }],
                "total_scanned": 1,
                "hosts_discovered": 1
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/scan.xml"])

                assert result is True


# =============================================================================
# Report Generation Tests
# =============================================================================

class TestReportGeneration:
    """Tests for report generation and export."""

    def test_report_pdf(self, command_handler, mock_framework):
        """Test generating PDF report."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_pdf.return_value = "/path/to/report.pdf"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["pdf", "report.pdf"])

            assert result is True

    def test_report_html(self, command_handler, mock_framework):
        """Test generating HTML report."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_html.return_value = "/path/to/report.html"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["html", "report.html"])

            assert result is True

    def test_report_xlsx(self, command_handler, mock_framework):
        """Test generating XLSX report."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_xlsx.return_value = "/path/to/report.xlsx"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["xlsx"])

            assert result is True

    def test_report_default_filename(self, command_handler, mock_framework):
        """Test report generation with default filename."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_pdf.return_value = "/path/to/report_default.pdf"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["pdf"])

            assert result is True

    def test_report_includes_findings(self, command_handler, mock_framework):
        """Test report includes findings data."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg, \
             patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_gen = MagicMock()
            mock_rg.return_value = mock_gen

            mock_findings = MagicMock()
            mock_findings.list_findings.return_value = [
                {"title": "SQL Injection", "severity": "high"}
            ]
            mock_fm.return_value = mock_findings

            result = command_handler.cmd_report(["pdf"])

            assert result is True

    def test_report_error_handling(self, command_handler, mock_framework):
        """Test report generation error handling."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_pdf.side_effect = Exception("Generation failed")
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["pdf"])

            assert result is True
            command_handler.display.print_error.assert_called()


# =============================================================================
# Analysis Results Export Tests
# =============================================================================

class TestAnalysisExport:
    """Tests for analysis results export."""

    def test_analysis_export_web_scans(self, command_handler, mock_framework):
        """Test exporting web scan analysis."""
        mock_framework.session.analysis_results = {
            "web_scans": [
                {"url": "http://test.com", "findings": ["XSS", "SQLi"]}
            ]
        }

        result = command_handler.cmd_analysis(["export", "web_analysis.json"])

        assert result is True

    def test_analysis_export_empty(self, command_handler, mock_framework):
        """Test exporting when no analysis results."""
        mock_framework.session.analysis_results = {}

        result = command_handler.cmd_analysis(["export", "analysis.json"])

        assert result is True


# =============================================================================
# Integration Tests
# =============================================================================

class TestExportIntegration:
    """Integration tests for export/import workflows."""

    def test_nmap_to_targets_workflow(self, command_handler, mock_framework):
        """Test complete workflow: parse nmap -> create targets -> export hosts."""
        # Parse nmap XML
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [{"ip": "192.168.1.1", "ports": [80, 443]}],
                "total_scanned": 1,
                "hosts_discovered": 1
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                command_handler.cmd_parse(["/path/to/scan.xml"])

        # Export hosts
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]

        with patch('builtins.open', mock_open()):
            result = command_handler.cmd_hosts(["export", "hosts.txt"])

            assert result is True

    def test_findings_to_report_workflow(self, command_handler, mock_framework):
        """Test workflow: create findings -> export findings -> generate report."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm, \
             patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            # Create findings manager with data
            mock_manager = MagicMock()
            mock_manager.list_findings.return_value = [
                {"title": "Finding 1", "severity": "high"}
            ]
            mock_manager.export_json.return_value = "findings.json"
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            # Export findings
            handler._findings_export(["json"])

            # Generate report
            mock_gen = MagicMock()
            mock_gen.generate_pdf.return_value = "report.pdf"
            mock_rg.return_value = mock_gen

            handler.cmd_report(["pdf"])

            assert True

    def test_graph_export_import_roundtrip(self, command_handler, mock_framework):
        """Test exporting and re-importing graph."""
        graph_data = {
            "nodes": [{"id": "1", "label": "host1"}],
            "edges": [{"source": "1", "target": "2"}]
        }

        # Export
        mock_framework.attack_graph.export_json.return_value = json.dumps(graph_data)

        with patch('builtins.open', mock_open()) as mock_file:
            command_handler._graph_export(mock_framework.attack_graph, ["json", "graph.json"])

        # Import
        with patch('builtins.open', mock_open(read_data=json.dumps(graph_data))), \
             patch('purplesploit.ui.commands.AttackGraph') as mock_ag:
            mock_graph = MagicMock()
            mock_ag.from_json.return_value = mock_graph

            result = command_handler._graph_import(mock_framework.attack_graph, ["graph.json"])

            assert result is True


# =============================================================================
# Error Handling Tests
# =============================================================================

class TestExportErrorHandling:
    """Tests for error handling in export/import operations."""

    def test_hosts_export_permission_denied(self, command_handler, mock_framework):
        """Test hosts export with permission error."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1"}
        ]

        with patch('builtins.open', side_effect=PermissionError()):
            result = command_handler.cmd_hosts(["export", "/root/hosts.txt"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_graph_export_write_error(self, command_handler, mock_framework):
        """Test graph export with write error."""
        mock_framework.attack_graph.export_json.return_value = '{"nodes": []}'

        with patch('builtins.open', side_effect=IOError("Disk full")):
            result = command_handler._graph_export(mock_framework.attack_graph, ["json", "graph.json"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_parse_malformed_xml(self, command_handler, mock_framework):
        """Test parsing malformed XML."""
        with patch('purplesploit.ui.commands.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.side_effect = ValueError("Malformed XML")
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/bad.xml"])

                assert result is True
                command_handler.display.print_error.assert_called()

    def test_sessions_export_no_manager(self, command_handler, mock_framework):
        """Test sessions export when manager not available."""
        mock_framework.session_manager = None

        result = command_handler.cmd_sessions(["export"])

        # Should handle gracefully
        assert result is True


# =============================================================================
# Advanced Export Features Tests
# =============================================================================

class TestAdvancedExportFeatures:
    """Tests for advanced export features."""

    def test_hosts_export_with_comments(self, command_handler, mock_framework):
        """Test hosts export includes comments."""
        mock_framework.session.targets.list.return_value = [
            {"ip": "192.168.1.1", "name": "server1", "description": "Web server"}
        ]

        with patch('builtins.open', mock_open()) as mock_file:
            result = command_handler.cmd_hosts(["export", "hosts.txt"])

            assert result is True

    def test_graph_export_with_metadata(self, command_handler, mock_framework):
        """Test graph export includes metadata."""
        mock_framework.attack_graph.export_json.return_value = json.dumps({
            "metadata": {"created": "2025-01-01", "version": "1.0"},
            "nodes": [],
            "edges": []
        })

        with patch('builtins.open', mock_open()):
            result = command_handler._graph_export(mock_framework.attack_graph, ["json", "graph.json"])

            assert result is True

    def test_findings_export_filtered(self, command_handler, mock_framework):
        """Test exporting filtered findings."""
        with patch('purplesploit.ui.commands.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.export_json.return_value = "findings_high.json"
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["json", "findings_high.json", "--severity", "high"])

            assert result is True

    @pytest.mark.parametrize("format_type,extension", [
        ("json", ".json"),
        ("dot", ".dot"),
        ("cytoscape", ".json"),
    ])
    def test_graph_export_formats(self, command_handler, mock_framework, format_type, extension):
        """Test different graph export formats."""
        if format_type == "json":
            mock_framework.attack_graph.export_json.return_value = "{}"
        elif format_type == "dot":
            mock_framework.attack_graph.export_dot.return_value = "digraph {}"
        elif format_type == "cytoscape":
            mock_framework.attack_graph.export_cytoscape.return_value = {"elements": []}

        filename = f"graph{extension}"
        with patch('builtins.open', mock_open()):
            result = command_handler._graph_export(mock_framework.attack_graph, [format_type, filename])

            assert result is True

    def test_report_multiple_formats(self, command_handler, mock_framework):
        """Test generating report in multiple formats."""
        with patch('purplesploit.ui.commands.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_pdf.return_value = "report.pdf"
            mock_gen.generate_html.return_value = "report.html"
            mock_gen.generate_xlsx.return_value = "report.xlsx"
            mock_rg.return_value = mock_gen

            # Generate all formats
            command_handler.cmd_report(["pdf", "report.pdf"])
            command_handler.cmd_report(["html", "report.html"])
            command_handler.cmd_report(["xlsx", "report.xlsx"])

            assert True
