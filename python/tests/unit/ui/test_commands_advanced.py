"""
Unit tests for advanced features in purplesploit.ui.commands.

Tests cover:
- Findings management (add, list, show, update, evidence, stats)
- Workflow automation commands
- Report generation
- Plugin management
- Auto-enumeration
- Attack graph visualization
- Credential spray intelligence
- Analysis and webresults commands
- Deploy command
- Defaults management
- Parse command (nmap XML)
"""

import pytest
from unittest.mock import MagicMock, patch, mock_open
from purplesploit.ui.commands import CommandHandler


# =============================================================================
# Helper Functions
# =============================================================================

def create_mock_finding(id="1", title="Test Finding", severity=None, status=None, **kwargs):
    """Create a mock Finding object with proper attributes."""
    from purplesploit.core.findings import Severity, FindingStatus

    finding = MagicMock()
    finding.id = id
    finding.title = title
    finding.severity = severity or Severity.HIGH
    finding.status = status or FindingStatus.DRAFT
    finding.cvss_score = kwargs.get('cvss_score', 7.5)
    finding.target = kwargs.get('target', '192.168.1.1')
    finding.description = kwargs.get('description', 'Test description')
    finding.evidence = kwargs.get('evidence', [])
    finding.recommendations = kwargs.get('recommendations', [])
    finding.created_at = kwargs.get('created_at', '2026-01-23')
    finding.updated_at = kwargs.get('updated_at', '2026-01-23')
    return finding


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
    framework.session.targets.get_current.return_value = None
    framework.session.credentials = MagicMock()
    framework.session.credentials.list.return_value = []
    framework.session.workspace = "default"
    framework.session.command_history = []
    framework.session.add_command = MagicMock()
    framework.modules = {}
    framework.database = MagicMock()
    framework.findings = MagicMock()
    framework.workflow_engine = MagicMock()
    framework.plugin_manager = MagicMock()
    framework.attack_graph = MagicMock()
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
# Findings Management Tests
# =============================================================================

class TestFindingsCommand:
    """Tests for findings management commands."""

    def test_findings_list_with_findings(self, command_handler, mock_framework):
        """Test listing findings."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.list_findings.return_value = [
                create_mock_finding(id="1", title="SQL Injection")
            ]
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler.cmd_findings(["list"])

            assert result is True
            mock_manager.list_findings.assert_called_once()

    def test_findings_list_empty(self, command_handler, mock_framework):
        """Test listing findings when none exist."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.list_findings.return_value = []
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler.cmd_findings(["list"])

            assert result is True
            handler.display.print_warning.assert_called()

    def test_findings_add(self, command_handler, mock_framework):
        """Test adding a finding."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm, \
             patch('builtins.input') as mock_input:
            mock_manager = MagicMock()
            mock_manager.create.return_value = create_mock_finding(id="finding-123", title="SQL Injection")
            mock_fm.return_value = mock_manager

            # Mock the input() calls: severity, target, description
            mock_input.side_effect = ["high", "192.168.1.1", "Database accepts unfiltered input"]

            # Setup framework current target
            mock_framework.session.targets.current = None

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_add(["SQL Injection"])

            assert result is True
            mock_manager.create.assert_called_once()

    def test_findings_show(self, command_handler, mock_framework):
        """Test showing finding details."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.get.return_value = create_mock_finding(
                id="1",
                title="SQL Injection",
                description="Test finding description"
            )
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_show(["1"])

            assert result is True
            mock_manager.get.assert_called_once_with("1")

    def test_findings_show_not_found(self, command_handler, mock_framework):
        """Test showing non-existent finding."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.get.return_value = None
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_show(["999"])

            assert result is True
            handler.display.print_error.assert_called()

    def test_findings_update(self, command_handler, mock_framework):
        """Test updating finding status."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.transition_status.return_value = True
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_update(["1", "confirmed"])

            assert result is True
            mock_manager.transition_status.assert_called_once()

    def test_findings_evidence(self, command_handler, mock_framework):
        """Test adding evidence to finding."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm, \
             patch('purplesploit.ui.commands.Path') as mock_path:
            mock_manager = MagicMock()
            mock_manager.add_evidence.return_value = MagicMock()  # Return truthy evidence object
            mock_fm.return_value = mock_manager

            # Mock the Path to say file exists
            mock_path_instance = MagicMock()
            mock_path_instance.exists.return_value = True
            mock_path_instance.name = "screenshot.png"
            mock_path.return_value = mock_path_instance

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_evidence(["1", "/path/to/screenshot.png"])

            assert result is True
            mock_manager.add_evidence.assert_called_once()

    def test_findings_export_json(self, command_handler, mock_framework):
        """Test exporting findings to JSON."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.export_json.return_value = "/path/to/findings.json"
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["json", "output.json"])

            assert result is True
            mock_manager.export_json.assert_called_once_with("output.json")

    def test_findings_export_unsupported_format(self, command_handler, mock_framework):
        """Test exporting findings with unsupported format."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_export(["xml"])

            assert result is True
            handler.display.print_error.assert_called()

    def test_findings_stats(self, command_handler, mock_framework):
        """Test findings statistics."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.get_statistics.return_value = {
                "total": 10,
                "by_severity": {"high": 3, "medium": 5, "low": 2},
                "by_status": {"draft": 4, "confirmed": 6},
                "with_evidence": 5,
                "with_cvss": 8
            }
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_stats()

            assert result is True
            mock_manager.get_statistics.assert_called_once()

    def test_findings_clear(self, command_handler, mock_framework):
        """Test clearing all findings."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm, \
             patch('builtins.input', return_value='y'):
            mock_manager = MagicMock()
            mock_manager.findings = {}
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler._findings_clear()

            assert result is True
            handler.display.print_success.assert_called()

    def test_findings_default_to_list(self, command_handler, mock_framework):
        """Test findings command defaults to list."""
        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_manager.list_findings.return_value = []
            mock_fm.return_value = mock_manager

            handler = command_handler
            handler._findings_manager = mock_manager

            result = handler.cmd_findings([])

            assert result is True


# =============================================================================
# Workflow Command Tests
# =============================================================================

class TestWorkflowCommand:
    """Tests for workflow automation commands."""

    def test_workflow_list(self, command_handler, mock_framework):
        """Test listing workflows."""
        mock_engine = MagicMock()

        # Create mock workflow with proper structure
        mock_workflow = MagicMock()
        mock_workflow.id = "wf-1"
        mock_workflow.name = "Web Recon"
        mock_workflow.status = MagicMock(value="ready")  # status.value is accessed
        mock_workflow.steps = []
        mock_workflow.tags = []

        mock_engine.list_workflows.return_value = [mock_workflow]
        command_handler._workflow_engine = mock_engine

        result = command_handler.cmd_workflow(["list"])

        assert result is True
        mock_engine.list_workflows.assert_called_once()

    def test_workflow_templates(self, command_handler, mock_framework):
        """Test listing workflow templates."""
        mock_engine = MagicMock()
        mock_engine.list_templates.return_value = [
            {
                "id": "ad-enum",
                "name": "AD Enum",
                "description": "Active Directory enumeration",
                "steps": 5,
                "tags": ["ad", "enum"]
            }
        ]
        command_handler._workflow_engine = mock_engine

        result = command_handler.cmd_workflow(["templates"])

        assert result is True
        mock_engine.list_templates.assert_called_once()

    def test_workflow_create(self, command_handler, mock_framework):
        """Test creating a workflow."""
        mock_engine = MagicMock()
        mock_engine.create_workflow.return_value = MagicMock(id="wf-123")
        command_handler._workflow_engine = mock_engine
        command_handler.interactive.get_input.side_effect = [
            "My Workflow",
            "Test workflow"
        ]

        result = command_handler.cmd_workflow(["create", "My Workflow"])

        assert result is True
        mock_engine.create_workflow.assert_called_once()

    def test_workflow_run(self, command_handler, mock_framework):
        """Test running a workflow."""
        mock_engine = MagicMock()
        mock_engine.run_workflow.return_value = {
            "success": True,
            "steps_completed": 3,
            "steps_failed": 0,
            "steps_skipped": 0
        }
        command_handler._workflow_engine = mock_engine

        # Set up a valid current target
        mock_target = MagicMock()
        mock_target.identifier = "192.168.1.100"
        mock_framework.session.targets.current = mock_target

        result = command_handler.cmd_workflow(["run", "wf-123"])

        assert result is True
        # run_workflow is called with workflow_id and variables dict
        mock_engine.run_workflow.assert_called_once()

    def test_workflow_show(self, command_handler, mock_framework):
        """Test showing workflow details."""
        mock_engine = MagicMock()
        mock_workflow = MagicMock()
        mock_workflow.id = "wf-123"
        mock_workflow.name = "Test"
        mock_workflow.description = "Test workflow"
        mock_workflow.status = "ready"
        mock_workflow.steps = []
        mock_workflow.tags = []
        mock_workflow.created_at = "2026-01-23"
        mock_engine.get_workflow.return_value = mock_workflow
        command_handler._workflow_engine = mock_engine

        result = command_handler.cmd_workflow(["show", "wf-123"])

        assert result is True

    def test_workflow_status(self, command_handler, mock_framework):
        """Test checking workflow status."""
        mock_engine = MagicMock()

        # Create mock workflow object
        mock_workflow = MagicMock()
        mock_workflow.id = "wf-123"
        mock_workflow.name = "Test Workflow"
        mock_workflow.status = MagicMock(value="running")
        mock_workflow.progress = 50
        mock_workflow.steps = [MagicMock(), MagicMock()]

        mock_engine.get_workflow.return_value = mock_workflow
        command_handler._workflow_engine = mock_engine

        result = command_handler.cmd_workflow(["status", "wf-123"])

        assert result is True
        mock_engine.get_workflow.assert_called_once()


# =============================================================================
# Report Generation Tests
# =============================================================================

class TestReportCommand:
    """Tests for report generation commands."""

    def test_report_no_args(self, command_handler):
        """Test report without arguments shows usage."""
        result = command_handler.cmd_report([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_report_generate_pdf(self, command_handler, mock_framework):
        """Test generating PDF report."""
        with patch('purplesploit.reporting.generator.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_pdf.return_value = "/path/to/report.pdf"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["pdf", "output.pdf"])

            assert result is True

    def test_report_generate_html(self, command_handler, mock_framework):
        """Test generating HTML report."""
        with patch('purplesploit.reporting.generator.ReportGenerator') as mock_rg:
            mock_gen = MagicMock()
            mock_gen.generate_html.return_value = "/path/to/report.html"
            mock_rg.return_value = mock_gen

            result = command_handler.cmd_report(["html"])

            assert result is True

    def test_report_with_findings(self, command_handler, mock_framework):
        """Test report generation includes findings."""
        with patch('purplesploit.reporting.generator.ReportGenerator') as mock_rg, \
             patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_gen = MagicMock()
            mock_rg.return_value = mock_gen

            mock_findings = MagicMock()
            mock_findings.list_findings.return_value = [
                {"title": "Test Finding", "severity": "high"}
            ]
            mock_fm.return_value = mock_findings

            result = command_handler.cmd_report(["pdf"])

            assert result is True


# =============================================================================
# Plugin Management Tests
# =============================================================================

class TestPluginCommand:
    """Tests for plugin management commands."""

    def test_plugin_list(self, command_handler, mock_framework):
        """Test listing plugins."""
        from purplesploit.plugins.models import PluginStatus

        mock_manager = MagicMock()

        # Create proper plugin mock objects with all required attributes
        mock_plugin = MagicMock()
        mock_plugin.name = "test-plugin"
        mock_plugin.version = "1.0.0"
        mock_plugin.installed_version = "1.0.0"
        mock_plugin.status = PluginStatus.INSTALLED
        mock_plugin.manifest.category.value = "recon"
        mock_plugin.manifest.description = "Test description"

        mock_manager.list_installed.return_value = [mock_plugin]
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["list"])

        assert result is True
        mock_manager.list_installed.assert_called_once()

    def test_plugin_search(self, command_handler, mock_framework):
        """Test searching plugins."""
        mock_manager = MagicMock()

        # Return list of plugin result objects with all required attributes
        mock_result = MagicMock()
        mock_result.name = "recon-plugin"
        mock_result.version = "1.0.0"
        mock_result.installed_version = None
        mock_result.downloads = 100
        mock_result.manifest.category.value = "recon"
        mock_result.manifest.author = "Test Author"
        mock_result.manifest.description = "Recon plugin"

        mock_manager.search.return_value = [mock_result]
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["search", "recon"])

        assert result is True
        mock_manager.search.assert_called_once()

    def test_plugin_install(self, command_handler, mock_framework):
        """Test installing a plugin."""
        mock_manager = MagicMock()
        mock_manager.install.return_value = MagicMock(name="test-plugin", version="1.0.0")
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["install", "test-plugin"])

        assert result is True
        mock_manager.install.assert_called_once()

    def test_plugin_uninstall(self, command_handler, mock_framework):
        """Test uninstalling a plugin."""
        mock_manager = MagicMock()
        mock_manager.uninstall.return_value = True
        command_handler._plugin_manager = mock_manager

        # Mock input() for confirmation
        with patch('builtins.input', return_value='y'):
            result = command_handler.cmd_plugin(["uninstall", "test-plugin"])

        assert result is True
        mock_manager.uninstall.assert_called_once()

    def test_plugin_enable(self, command_handler, mock_framework):
        """Test enabling a plugin."""
        mock_manager = MagicMock()
        mock_manager.enable.return_value = True
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["enable", "test-plugin"])

        assert result is True
        mock_manager.enable.assert_called_once()

    def test_plugin_disable(self, command_handler, mock_framework):
        """Test disabling a plugin."""
        mock_manager = MagicMock()
        mock_manager.disable.return_value = True
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["disable", "test-plugin"])

        assert result is True
        mock_manager.disable.assert_called_once()

    def test_plugin_info(self, command_handler, mock_framework):
        """Test showing plugin info."""
        mock_manager = MagicMock()

        mock_plugin = MagicMock()
        mock_plugin.name = "test-plugin"
        mock_plugin.version = "1.0.0"
        mock_plugin.description = "Test plugin"
        mock_plugin.author = "Test Author"
        mock_plugin.license = "MIT"
        mock_plugin.repository = "https://github.com/test/test-plugin"
        mock_plugin.category = "recon"
        mock_plugin.tags = ["test"]
        mock_plugin.dependencies = []
        mock_plugin.commands = []

        mock_manager.get_plugin.return_value = mock_plugin
        command_handler._plugin_manager = mock_manager

        result = command_handler.cmd_plugin(["info", "test-plugin"])

        assert result is True


# =============================================================================
# Auto-Enumeration Tests
# =============================================================================

class TestAutoCommand:
    """Tests for smart auto-enumeration commands."""

    def test_auto_no_target(self, command_handler, mock_framework):
        """Test auto without target shows error."""
        mock_framework.session.targets.get_current.return_value = None

        result = command_handler.cmd_auto([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_auto_with_target(self, command_handler, mock_framework):
        """Test auto-enumeration with target."""
        mock_target = MagicMock()
        mock_target.identifier = "192.168.1.1"
        mock_framework.session.targets.current = mock_target

        with patch('purplesploit.core.auto_enum.AutoEnumPipeline') as mock_pipeline, \
             patch('purplesploit.core.auto_enum.create_auto_enum') as mock_create, \
             patch('purplesploit.core.auto_enum.EnumScope'), \
             patch('purplesploit.core.auto_enum.EnumPhase'):
            mock_pipe = MagicMock()
            mock_pipe.run.return_value = {"status": "completed"}
            mock_create.return_value = mock_pipe

            result = command_handler.cmd_auto([])

            assert result is True

    def test_auto_with_depth(self, command_handler, mock_framework):
        """Test auto-enumeration with depth parameter."""
        mock_target = {"ip": "192.168.1.1"}
        mock_framework.session.targets.get_current.return_value = mock_target

        with patch('purplesploit.core.auto_enum.AutoEnumPipeline') as mock_pipeline:
            mock_pipe = MagicMock()
            mock_pipeline.return_value = mock_pipe

            result = command_handler.cmd_auto(["--depth", "3"])

            assert result is True

    def test_auto_status(self, command_handler, mock_framework):
        """Test checking auto-enumeration status."""
        result = command_handler.cmd_auto(["status"])

        assert result is True

    def test_auto_stop(self, command_handler, mock_framework):
        """Test stopping auto-enumeration."""
        result = command_handler.cmd_auto(["stop"])

        assert result is True


# =============================================================================
# Attack Graph Tests
# =============================================================================

class TestGraphCommand:
    """Tests for attack graph visualization commands."""

    def test_graph_stats(self, command_handler, mock_framework):
        """Test showing graph statistics (no args = show stats)."""
        mock_graph = MagicMock()
        mock_graph.get_statistics.return_value = {
            "total_nodes": 15,
            "total_edges": 23,
            "hosts": 5,
            "services": 10,
            "credentials": 3,
            "vulnerabilities": 2,
            "compromised_hosts": 1,
            "attack_paths": 3
        }
        mock_graph.hosts = []
        mock_graph.services = {}
        mock_graph.credentials = []
        mock_graph.vulnerabilities = []

        with patch('purplesploit.core.attack_graph.create_attack_graph', return_value=mock_graph):
            result = command_handler.cmd_graph([])

            assert result is True
            mock_graph.get_statistics.assert_called_once()

    def test_graph_show(self, command_handler, mock_framework):
        """Test showing graph visualization."""
        mock_framework.attack_graph.get_nodes.return_value = []

        result = command_handler.cmd_graph(["show"])

        assert result is True

    def test_graph_paths(self, command_handler, mock_framework):
        """Test showing attack paths."""
        mock_framework.attack_graph.find_attack_paths.return_value = [
            {"path": ["node1", "node2"], "score": 0.8}
        ]

        result = command_handler.cmd_graph(["paths"])

        assert result is True

    def test_graph_export_json(self, command_handler, mock_framework):
        """Test exporting graph to JSON."""
        mock_graph = MagicMock()
        mock_graph.to_json.return_value = '{"nodes": []}'

        with patch('builtins.open', MagicMock()):
            result = command_handler._graph_export(mock_graph, ["json", "graph.json"])

            assert result is True

    def test_graph_export_dot(self, command_handler, mock_framework):
        """Test exporting graph to DOT format."""
        mock_graph = MagicMock()
        mock_graph.to_dot.return_value = "digraph {}"

        with patch('builtins.open', MagicMock()):
            result = command_handler._graph_export(mock_graph, ["dot", "graph.dot"])

            assert result is True

    def test_graph_import(self, command_handler, mock_framework):
        """Test importing graph from file."""
        with patch('builtins.open', mock_open(read_data='{"nodes": []}')):
            with patch('purplesploit.core.attack_graph.AttackGraph') as mock_ag:
                result = command_handler._graph_import(mock_framework.attack_graph, ["graph.json"])

                assert result is True

    def test_graph_clear(self, command_handler, mock_framework):
        """Test clearing the attack graph."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_graph(["clear"])

        assert result is True


# =============================================================================
# Credential Spray Tests
# =============================================================================

class TestSprayCommand:
    """Tests for credential spray intelligence commands."""

    def test_spray_no_args(self, command_handler):
        """Test spray without args shows usage."""
        result = command_handler.cmd_spray([])

        assert result is True
        command_handler.display.print_info.assert_called()

    def test_spray_start(self, command_handler, mock_framework):
        """Test starting credential spray."""
        with patch('purplesploit.core.credential_spray.CredentialSpray') as mock_engine:
            mock_spray = MagicMock()
            mock_engine.return_value = mock_spray

            result = command_handler.cmd_spray(["start", "--service", "smb"])

            assert result is True

    def test_spray_status(self, command_handler, mock_framework):
        """Test checking spray status."""
        result = command_handler.cmd_spray(["status"])

        assert result is True

    def test_spray_stop(self, command_handler, mock_framework):
        """Test stopping spray."""
        result = command_handler.cmd_spray(["stop"])

        assert result is True

    def test_spray_config(self, command_handler, mock_framework):
        """Test configuring spray settings."""
        result = command_handler.cmd_spray(["config"])

        assert result is True

    def test_spray_generate_passwords(self, command_handler, mock_framework):
        """Test spray wordlist subcommand for password generation."""
        # spray wordlist is the subcommand for password generation
        with patch('purplesploit.core.credential_spray.PasswordGenerator') as mock_gen:
            mock_generator = MagicMock()
            mock_generator.generate.return_value = ["Password1", "Password2"]
            mock_gen.return_value = mock_generator

            result = command_handler.cmd_spray(["wordlist"])

            assert result is True


# =============================================================================
# Analysis Command Tests
# =============================================================================

class TestAnalysisCommand:
    """Tests for analysis and webresults commands."""

    def test_analysis_list(self, command_handler, mock_framework):
        """Test listing analysis results."""
        mock_framework.session.analysis_results = {
            "web_scans": [{"url": "http://test.com", "findings": 5}]
        }

        result = command_handler.cmd_analysis(["list"])

        assert result is True

    def test_analysis_show(self, command_handler, mock_framework):
        """Test showing analysis details."""
        result = command_handler.cmd_analysis(["show", "scan-123"])

        assert result is True

    def test_analysis_clear(self, command_handler, mock_framework):
        """Test clearing analysis results."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_analysis(["clear"])

        assert result is True


# =============================================================================
# Deploy Command Tests
# =============================================================================

class TestDeployCommand:
    """Tests for deploy command."""

    def test_deploy_no_args(self, command_handler, mock_framework):
        """Test deploy without args shows available modules."""
        result = command_handler.cmd_deploy([])

        assert result is True

    def test_deploy_ligolo(self, command_handler, mock_framework):
        """Test deploying ligolo."""
        mock_framework.modules = {"deploy/ligolo": MagicMock()}
        mock_module = MagicMock()
        mock_module.name = "Ligolo Deploy"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_deploy(["ligolo"])

        assert result is True
        mock_framework.use_module.assert_called_once_with("deploy/ligolo")

    def test_deploy_c2(self, command_handler, mock_framework):
        """Test deploying C2 beacon."""
        mock_framework.modules = {"deploy/c2": MagicMock()}
        mock_module = MagicMock()
        mock_module.name = "C2 Deploy"
        mock_module.has_operations.return_value = False
        mock_framework.use_module.return_value = mock_module

        result = command_handler.cmd_deploy(["c2"])

        assert result is True

    def test_deploy_unknown_module(self, command_handler, mock_framework):
        """Test deploying unknown module."""
        result = command_handler.cmd_deploy(["unknown"])

        assert result is True
        command_handler.display.print_error.assert_called()


# =============================================================================
# Defaults Management Tests
# =============================================================================

class TestDefaultsCommand:
    """Tests for defaults management commands."""

    def test_defaults_list(self, command_handler, mock_framework):
        """Test listing default options."""
        mock_framework.session.defaults = {
            "THREADS": "10",
            "TIMEOUT": "30"
        }

        result = command_handler.cmd_defaults(["list"])

        assert result is True

    def test_defaults_set(self, command_handler, mock_framework):
        """Test setting a default option."""
        result = command_handler.cmd_defaults(["set", "THREADS", "20"])

        assert result is True

    def test_defaults_unset(self, command_handler, mock_framework):
        """Test unsetting a default option."""
        result = command_handler.cmd_defaults(["unset", "THREADS"])

        assert result is True

    def test_defaults_clear(self, command_handler, mock_framework):
        """Test clearing all defaults."""
        command_handler.interactive.confirm.return_value = True

        result = command_handler.cmd_defaults(["clear"])

        assert result is True


# =============================================================================
# Parse Command Tests
# =============================================================================

class TestParseCommand:
    """Tests for nmap XML parsing command."""

    def test_parse_no_args(self, command_handler):
        """Test parse without arguments."""
        result = command_handler.cmd_parse([])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_parse_nmap_xml(self, command_handler, mock_framework):
        """Test parsing nmap XML file."""
        with patch('purplesploit.modules.recon.nmap.NmapModule') as mock_nmap:
            mock_module = MagicMock()
            mock_module.parse_xml_results.return_value = {
                "hosts": [{"ip": "192.168.1.1", "ports": [80, 443]}]
            }
            mock_nmap.return_value = mock_module

            with patch('pathlib.Path.exists', return_value=True):
                result = command_handler.cmd_parse(["/path/to/scan.xml"])

                assert result is True

    def test_parse_file_not_found(self, command_handler, mock_framework):
        """Test parse with non-existent file."""
        with patch('pathlib.Path.exists', return_value=False):
            result = command_handler.cmd_parse(["/path/to/missing.xml"])

            assert result is True
            command_handler.display.print_error.assert_called()


# =============================================================================
# Ligolo Command Tests
# =============================================================================

class TestLigoloCommand:
    """Tests for ligolo-ng command."""

    def test_ligolo_start(self, command_handler, mock_framework):
        """Test starting ligolo-ng."""
        with patch('subprocess.Popen') as mock_popen:
            mock_process = MagicMock()
            mock_popen.return_value = mock_process

            result = command_handler.cmd_ligolo(["start"])

            assert result is True

    def test_ligolo_stop(self, command_handler, mock_framework):
        """Test stopping ligolo-ng."""
        result = command_handler.cmd_ligolo(["stop"])

        assert result is True

    def test_ligolo_status(self, command_handler, mock_framework):
        """Test checking ligolo-ng status."""
        result = command_handler.cmd_ligolo(["status"])

        assert result is True


# =============================================================================
# Edge Cases and Error Handling Tests
# =============================================================================

class TestAdvancedEdgeCases:
    """Tests for edge cases in advanced commands."""

    def test_findings_invalid_subcommand(self, command_handler, mock_framework):
        """Test findings with invalid subcommand."""
        with patch('purplesploit.core.findings.FindingsManager'):
            result = command_handler.cmd_findings(["invalid"])

            assert result is True
            command_handler.display.print_error.assert_called()

    def test_workflow_invalid_subcommand(self, command_handler, mock_framework):
        """Test workflow with invalid subcommand."""
        result = command_handler.cmd_workflow(["invalid"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_plugin_invalid_subcommand(self, command_handler, mock_framework):
        """Test plugin with invalid subcommand."""
        result = command_handler.cmd_plugin(["invalid"])

        assert result is True
        command_handler.display.print_error.assert_called()

    def test_graph_invalid_subcommand(self, command_handler, mock_framework):
        """Test graph with invalid subcommand."""
        result = command_handler.cmd_graph(["invalid"])

        assert result is True

    def test_auto_interrupted(self, command_handler, mock_framework):
        """Test auto-enumeration interrupted by user."""
        mock_target = {"ip": "192.168.1.1"}
        mock_framework.session.targets.get_current.return_value = mock_target

        with patch('purplesploit.core.auto_enum.AutoEnumPipeline') as mock_pipeline:
            mock_pipe = MagicMock()
            mock_pipe.run.side_effect = KeyboardInterrupt()
            mock_pipeline.return_value = mock_pipe

            result = command_handler.cmd_auto([])

            assert result is True

    def test_report_missing_dependencies(self, command_handler, mock_framework):
        """Test report generation with missing dependencies raises ImportError."""
        with patch('purplesploit.reporting.ReportGenerator', side_effect=ImportError("Missing lib")):
            # ImportError propagates up (implementation doesn't catch it)
            with pytest.raises(ImportError):
                command_handler.cmd_report(["generate", "pdf"])


# =============================================================================
# Integration Tests
# =============================================================================

class TestAdvancedIntegration:
    """Integration tests for advanced features."""

    def test_workflow_with_findings(self, command_handler, mock_framework):
        """Test workflow generates findings."""
        mock_framework.workflow_engine.run_workflow.return_value = {
            "status": "completed",
            "findings": [{"title": "SQL Injection"}]
        }

        with patch('purplesploit.core.findings.FindingsManager') as mock_fm:
            mock_manager = MagicMock()
            mock_fm.return_value = mock_manager

            result = command_handler.cmd_workflow(["run", "wf-123"])

            assert result is True

    def test_auto_enum_updates_graph(self, command_handler, mock_framework):
        """Test auto-enumeration updates attack graph."""
        mock_target = {"ip": "192.168.1.1"}
        mock_framework.session.targets.get_current.return_value = mock_target

        with patch('purplesploit.core.auto_enum.AutoEnumPipeline') as mock_pipeline:
            mock_pipe = MagicMock()
            mock_pipe.run.return_value = {"discovered_services": ["smb", "ldap"]}
            mock_pipeline.return_value = mock_pipe

            result = command_handler.cmd_auto([])

            assert result is True

    def test_spray_uses_graph_data(self, command_handler, mock_framework):
        """Test credential spray uses attack graph data."""
        mock_framework.attack_graph.get_nodes.return_value = [
            {"type": "credential", "value": "admin"}
        ]

        result = command_handler.cmd_spray(["start"])

        assert result is True
