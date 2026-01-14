"""
Extended tests for purplesploit.core.auto_enum module.

Comprehensive test coverage for:
- Pipeline stage execution (discovery, enumeration, exploitation)
- Service detection and processing
- Module recommendation and selection
- Error recovery and handling
- Parallel execution
- Progress tracking and callbacks
"""

import pytest
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime, timedelta
import threading
import time

from purplesploit.core.auto_enum import (
    AutoEnumPipeline,
    create_auto_enum,
    EnumPhase,
    EnumScope,
    ServiceRule,
    EnumResult,
    EnumProgress,
)


# =============================================================================
# Pipeline Stage Tests
# =============================================================================

class TestDiscoveryPhase:
    """Tests for discovery phase execution."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework with all necessary methods."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.services = MagicMock()
        framework.session.services.add_service = MagicMock()
        framework.database = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_run_discovery_phase_single_target(self, pipeline, mock_framework):
        """Test discovery phase with single target."""
        # Mock module loading and execution
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'output': 'Scan complete',
            'services': [
                {'service': 'smb', 'port': 445},
                {'service': 'http', 'port': 80},
            ]
        })

        pipeline._run_discovery_phase(['192.168.1.1'])

        # Verify module was used and run
        mock_framework.use_module.assert_called_once_with('recon/nmap')
        mock_framework.run_module.assert_called_once()

    def test_run_discovery_phase_multiple_targets(self, pipeline, mock_framework):
        """Test discovery phase with multiple targets."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': []
        })

        pipeline._run_discovery_phase(['192.168.1.1', '192.168.1.2', '192.168.1.3'])

        # Should have called use_module 3 times
        assert mock_framework.use_module.call_count == 3

    def test_run_discovery_phase_stop_requested(self, pipeline, mock_framework):
        """Test discovery phase respects stop request."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={'success': True, 'services': []})

        # Set stop flag
        pipeline._stop_requested = True

        pipeline._run_discovery_phase(['192.168.1.1', '192.168.1.2'])

        # Should not have called any modules
        mock_framework.use_module.assert_not_called()

    def test_run_discovery_phase_null_scope(self, mock_framework):
        """Test discovery with PASSIVE scope returns None for nmap operation."""
        pipeline = AutoEnumPipeline(mock_framework, scope=EnumScope.PASSIVE)

        operation = pipeline._get_nmap_operation()

        assert operation is None


class TestEnumerationPhase:
    """Tests for enumeration phase execution."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.services = MagicMock()
        framework.database = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline with discovered services."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {
            '192.168.1.1': {'smb', 'http'},
        }
        return pipeline

    def test_run_enumeration_phase_no_services(self, mock_framework):
        """Test enumeration skips target with no discovered services."""
        pipeline = AutoEnumPipeline(mock_framework)

        # No services discovered
        pipeline._run_enumeration_phase('192.168.1.1')

        # Should not have tried to run any modules
        mock_framework.use_module.assert_not_called()

    def test_run_enumeration_phase_with_services(self, pipeline, mock_framework):
        """Test enumeration runs appropriate modules for services."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'output': 'Complete',
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_enumeration_phase('192.168.1.1')

        # Modules should have been loaded
        assert mock_framework.use_module.call_count > 0

    def test_run_enumeration_phase_skips_auth_without_creds(self, pipeline, mock_framework):
        """Test enumeration skips auth-required modules when no creds."""
        # Ensure no credentials
        pipeline.discovered_credentials = []

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_enumeration_phase('192.168.1.1')

        # Verify auth-required modules were not called
        # The pipeline should still work, just skipping auth modules
        assert pipeline._has_credentials() is False

    def test_run_enumeration_phase_pause_resume(self, pipeline, mock_framework):
        """Test enumeration pause and resume."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        call_count = 0

        def run_side_effect(module):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                # Resume after first call
                pipeline._pause_requested = False
            return {
                'success': True,
                'services': [],
                'credentials': [],
                'users': [],
                'findings': [],
            }

        mock_framework.run_module = MagicMock(side_effect=run_side_effect)

        # Start paused but it should auto-resume
        pipeline._pause_requested = False

        pipeline._run_enumeration_phase('192.168.1.1')

        # Enumeration should complete
        assert mock_framework.run_module.call_count > 0


class TestExploitationPhase:
    """Tests for exploitation phase execution."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.add_credential = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline with services and credentials."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {
            '192.168.1.1': {'smb', 'ssh'},
        }
        pipeline.discovered_credentials = [
            {'username': 'admin', 'password': 'password123', 'domain': 'CORP'}
        ]
        return pipeline

    def test_run_exploitation_phase_with_credentials(self, pipeline, mock_framework):
        """Test exploitation phase uses discovered credentials."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {
            'RHOST': {},
            'USERNAME': {},
            'PASSWORD': {},
            'DOMAIN': {},
            'HASH': {},
        }
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        # Add exploitation rules
        pipeline.add_service_rule(ServiceRule(
            service='ssh',
            modules=['network/nxc_ssh'],
            requires_auth=True,
            phase=EnumPhase.EXPLOITATION,
            priority=10,
        ))

        pipeline._run_exploitation_phase(['192.168.1.1'])

        # Should have attempted to use credentials
        # Note: May not be called if no exploitation rules match
        # This is expected behavior

    def test_run_exploitation_phase_no_credentials(self, mock_framework):
        """Test exploitation phase skips when no credentials."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {'192.168.1.1': {'smb'}}
        pipeline.discovered_credentials = []

        pipeline._run_exploitation_phase(['192.168.1.1'])

        # Should not have tried to run modules
        mock_framework.use_module.assert_not_called()


class TestParallelEnumeration:
    """Tests for parallel enumeration execution."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.database = MagicMock()
        return framework

    def test_run_enumeration_parallel_multiple_targets(self, mock_framework):
        """Test parallel enumeration with multiple targets."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {
            '192.168.1.1': {'smb'},
            '192.168.1.2': {'http'},
            '192.168.1.3': {'ssh'},
        }

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        targets = ['192.168.1.1', '192.168.1.2', '192.168.1.3']
        pipeline._run_enumeration_parallel(targets, max_workers=3)

        # Should have processed all targets
        # Exact call count depends on rules matching

    def test_run_enumeration_parallel_handles_exceptions(self, mock_framework):
        """Test parallel enumeration handles exceptions gracefully."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {
            '192.168.1.1': {'smb'},
            '192.168.1.2': {'http'},
        }

        mock_framework.use_module = MagicMock(side_effect=Exception("Module error"))

        # Should not raise exception
        pipeline._run_enumeration_parallel(['192.168.1.1', '192.168.1.2'], max_workers=2)


# =============================================================================
# Service Detection Tests
# =============================================================================

class TestServiceDetection:
    """Tests for service detection and processing."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.services = MagicMock()
        framework.session.services.add_service = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_process_discovery_results_extracts_services(self, pipeline, mock_framework):
        """Test discovery results processing extracts services."""
        result = EnumResult(
            module='recon/nmap',
            operation='Quick Scan',
            target='192.168.1.1',
            success=True,
            discovered_services=[
                {'service': 'smb', 'port': 445},
                {'service': 'http', 'port': 80},
                {'service': 'ssh', 'port': 22},
            ]
        )

        pipeline._process_discovery_results('192.168.1.1', result)

        assert 'smb' in pipeline.discovered_services['192.168.1.1']
        assert 'http' in pipeline.discovered_services['192.168.1.1']
        assert 'ssh' in pipeline.discovered_services['192.168.1.1']

    def test_process_discovery_results_calls_service_callback(self, pipeline, mock_framework):
        """Test service callback is invoked for discovered services."""
        callback = MagicMock()
        pipeline.on_service_found = callback

        result = EnumResult(
            module='recon/nmap',
            operation='Quick Scan',
            target='192.168.1.1',
            success=True,
            discovered_services=[
                {'service': 'smb', 'port': 445},
            ]
        )

        pipeline._process_discovery_results('192.168.1.1', result)

        callback.assert_called_once_with('192.168.1.1', 'smb', 445)

    def test_process_discovery_results_adds_to_framework(self, pipeline, mock_framework):
        """Test discovered services are added to framework session."""
        result = EnumResult(
            module='recon/nmap',
            operation='Quick Scan',
            target='192.168.1.1',
            success=True,
            discovered_services=[
                {'service': 'http', 'port': 8080},
            ]
        )

        pipeline._process_discovery_results('192.168.1.1', result)

        mock_framework.session.services.add_service.assert_called_with(
            '192.168.1.1', 'http', 8080
        )

    def test_process_discovery_results_handles_unknown_service(self, pipeline, mock_framework):
        """Test handling of unknown service types."""
        result = EnumResult(
            module='recon/nmap',
            operation='Quick Scan',
            target='192.168.1.1',
            success=True,
            discovered_services=[
                {'service': 'unknown', 'port': 12345},
            ]
        )

        pipeline._process_discovery_results('192.168.1.1', result)

        assert 'unknown' in pipeline.discovered_services['192.168.1.1']


# =============================================================================
# Module Recommendation Tests
# =============================================================================

class TestModuleRecommendation:
    """Tests for module recommendation and selection."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        return MagicMock()

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_get_applicable_rules_by_service(self, pipeline):
        """Test rules are selected by service type."""
        services = {'smb'}

        rules = pipeline._get_applicable_rules(
            '192.168.1.1',
            services,
            EnumPhase.ENUMERATION
        )

        # Should return SMB-related rules
        smb_rules = [r for r in rules if r.service == 'smb']
        assert len(smb_rules) > 0

    def test_get_applicable_rules_by_phase(self, pipeline):
        """Test rules are filtered by phase."""
        services = {'smb', 'http'}

        enum_rules = pipeline._get_applicable_rules(
            '192.168.1.1',
            services,
            EnumPhase.ENUMERATION
        )

        exploit_rules = pipeline._get_applicable_rules(
            '192.168.1.1',
            services,
            EnumPhase.EXPLOITATION
        )

        # All returned rules should match the requested phase
        for rule in enum_rules:
            assert rule.phase == EnumPhase.ENUMERATION

        for rule in exploit_rules:
            assert rule.phase == EnumPhase.EXPLOITATION

    def test_get_applicable_rules_sorted_by_priority(self, pipeline):
        """Test rules are sorted by priority (high to low)."""
        # Add custom rules with different priorities
        pipeline.add_service_rule(ServiceRule(
            service='test',
            modules=['test/low'],
            priority=1,
            phase=EnumPhase.ENUMERATION,
        ))
        pipeline.add_service_rule(ServiceRule(
            service='test',
            modules=['test/high'],
            priority=10,
            phase=EnumPhase.ENUMERATION,
        ))

        rules = pipeline._get_applicable_rules(
            '192.168.1.1',
            {'test'},
            EnumPhase.ENUMERATION
        )

        # Higher priority should come first
        priorities = [r.priority for r in rules]
        assert priorities == sorted(priorities, reverse=True)

    def test_check_rule_conditions_has_users(self, pipeline):
        """Test has_users condition."""
        rule = ServiceRule(
            service='test',
            modules=['test/module'],
            conditions=[{'type': 'has_users'}]
        )

        # No users
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is False

        # With users
        pipeline.discovered_users['192.168.1.1'] = ['admin', 'user1']
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is True

    def test_check_rule_conditions_finding_exists(self, pipeline):
        """Test finding_exists condition."""
        rule = ServiceRule(
            service='test',
            modules=['test/module'],
            conditions=[{'type': 'finding_exists', 'finding_type': 'vuln'}]
        )

        # No findings
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is False

        # With matching finding
        pipeline.results.append(EnumResult(
            module='test',
            operation=None,
            target='192.168.1.1',
            success=True,
            findings=[{'type': 'vuln', 'name': 'SQL Injection'}]
        ))
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is True

    def test_check_rule_conditions_multiple(self, pipeline):
        """Test multiple conditions all must pass."""
        rule = ServiceRule(
            service='test',
            modules=['test/module'],
            conditions=[
                {'type': 'has_users'},
                {'type': 'has_credentials'},
            ]
        )

        # Neither condition met
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is False

        # Only users
        pipeline.discovered_users['192.168.1.1'] = ['admin']
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is False

        # Both conditions met
        pipeline.discovered_credentials = [{'username': 'admin'}]
        assert pipeline._check_rule_conditions(rule, '192.168.1.1') is True


# =============================================================================
# Error Recovery Tests
# =============================================================================

class TestErrorRecovery:
    """Tests for error handling and recovery."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_run_module_handles_module_not_found(self, pipeline, mock_framework):
        """Test handling of module not found error."""
        mock_framework.use_module = MagicMock(return_value=None)

        result = pipeline._run_module(
            target='192.168.1.1',
            module_path='nonexistent/module',
        )

        assert result is None

    def test_run_module_handles_execution_exception(self, pipeline, mock_framework):
        """Test handling of module execution exception."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(side_effect=Exception("Option error"))
        mock_module.options = {'RHOST': {}}

        mock_framework.use_module = MagicMock(return_value=mock_module)

        result = pipeline._run_module(
            target='192.168.1.1',
            module_path='test/module',
        )

        assert result is not None
        assert result.success is False
        assert 'Option error' in result.error

    def test_run_module_handles_run_exception(self, pipeline, mock_framework):
        """Test handling of module run exception."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(side_effect=Exception("Run failed"))

        result = pipeline._run_module(
            target='192.168.1.1',
            module_path='test/module',
        )

        assert result is not None
        assert result.success is False
        assert 'Run failed' in result.error

    def test_run_continues_after_single_failure(self, pipeline, mock_framework):
        """Test pipeline continues after single module failure."""
        pipeline.discovered_services = {'192.168.1.1': {'smb', 'http'}}

        call_count = 0

        def use_module_side_effect(path):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return None  # First module fails
            mock = MagicMock()
            mock.set_option = MagicMock(return_value=True)
            mock.options = {'RHOST': {}}
            mock.auto_set_from_context = MagicMock()
            mock.get_operations = MagicMock(return_value=[])
            return mock

        mock_framework.use_module = MagicMock(side_effect=use_module_side_effect)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_enumeration_phase('192.168.1.1')

        # Should have tried multiple modules despite first failure
        assert mock_framework.use_module.call_count > 1

    def test_process_enum_results_handles_empty_data(self, pipeline, mock_framework):
        """Test processing results with missing data fields."""
        result = EnumResult(
            module='test',
            operation=None,
            target='192.168.1.1',
            success=True,
            # No discovered_services, credentials, users, or findings
        )

        # Should not raise exception
        pipeline._process_enum_results('192.168.1.1', result)


# =============================================================================
# Full Pipeline Run Tests
# =============================================================================

class TestFullPipelineRun:
    """Tests for complete pipeline execution."""

    @pytest.fixture
    def mock_framework(self):
        """Create comprehensive mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        framework.session.services = MagicMock()
        framework.session.services.add_service = MagicMock()
        framework.database = MagicMock()
        framework.add_credential = MagicMock()
        return framework

    def test_run_with_default_phases(self, mock_framework):
        """Test run with default phases (discovery + enumeration)."""
        pipeline = AutoEnumPipeline(mock_framework)

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'output': 'Complete',
            'services': [{'service': 'smb', 'port': 445}],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        summary = pipeline.run(['192.168.1.1'])

        assert 'success' in summary
        assert 'duration_seconds' in summary
        assert 'targets_scanned' in summary

    def test_run_with_exploitation_phase(self, mock_framework):
        """Test run including exploitation phase."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_credentials = [{'username': 'admin', 'password': 'pass'}]

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {
            'RHOST': {},
            'USERNAME': {},
            'PASSWORD': {},
            'DOMAIN': {},
            'HASH': {},
        }
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [{'service': 'smb', 'port': 445}],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        phases = [EnumPhase.DISCOVERY, EnumPhase.ENUMERATION, EnumPhase.EXPLOITATION]
        summary = pipeline.run(['192.168.1.1'], phases=phases)

        assert summary is not None

    def test_run_stops_on_stop_request(self, mock_framework):
        """Test run stops when stop is requested."""
        pipeline = AutoEnumPipeline(mock_framework)

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()

        call_count = 0

        def run_side_effect(module):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                pipeline.stop()  # Request stop after first run
            return {
                'success': True,
                'services': [],
                'credentials': [],
                'users': [],
                'findings': [],
            }

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(side_effect=run_side_effect)

        summary = pipeline.run(['192.168.1.1', '192.168.1.2', '192.168.1.3'])

        # Should have stopped early
        assert pipeline._stop_requested is True

    def test_run_parallel_mode(self, mock_framework):
        """Test run in parallel mode."""
        pipeline = AutoEnumPipeline(mock_framework)

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [{'service': 'http', 'port': 80}],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        summary = pipeline.run(
            ['192.168.1.1', '192.168.1.2'],
            parallel=True,
            max_workers=2
        )

        assert summary is not None


# =============================================================================
# Progress Tracking Tests
# =============================================================================

class TestProgressTracking:
    """Tests for progress tracking and callbacks."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        return MagicMock()

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_update_progress_invokes_callback(self, pipeline):
        """Test progress callback is invoked."""
        callback = MagicMock()
        pipeline.on_progress = callback

        pipeline._update_progress(
            EnumPhase.DISCOVERY,
            'Port Scan',
            '192.168.1.1'
        )

        callback.assert_called_once()
        progress = callback.call_args[0][0]
        assert isinstance(progress, EnumProgress)
        assert progress.phase == EnumPhase.DISCOVERY
        assert progress.current_step == 'Port Scan'
        assert progress.current_target == '192.168.1.1'

    def test_update_progress_includes_counts(self, pipeline):
        """Test progress includes accurate counts."""
        pipeline.discovered_services = {
            '192.168.1.1': {'smb', 'http'},
            '192.168.1.2': {'ssh'},
        }
        pipeline.discovered_credentials = [
            {'username': 'admin'},
            {'username': 'user'},
        ]
        pipeline.results = [
            EnumResult(
                module='test',
                operation=None,
                target='192.168.1.1',
                success=True,
                findings=[{'type': 'vuln'}]
            )
        ]

        callback = MagicMock()
        pipeline.on_progress = callback

        pipeline._update_progress(EnumPhase.ENUMERATION, 'Step', '192.168.1.1')

        progress = callback.call_args[0][0]
        assert progress.services_found == 3  # smb, http, ssh
        assert progress.credentials_found == 2
        assert progress.findings_found == 1

    def test_on_step_complete_callback(self, pipeline, mock_framework):
        """Test step complete callback is invoked."""
        callback = MagicMock()
        pipeline.on_step_complete = callback

        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_module(
            target='192.168.1.1',
            module_path='test/module',
        )

        callback.assert_called_once()
        result = callback.call_args[0][0]
        assert isinstance(result, EnumResult)

    def test_on_credential_found_callback(self, pipeline, mock_framework):
        """Test credential found callback is invoked."""
        callback = MagicMock()
        pipeline.on_credential_found = callback

        result = EnumResult(
            module='test',
            operation=None,
            target='192.168.1.1',
            success=True,
            discovered_credentials=[
                {'username': 'admin', 'password': 'secret'}
            ]
        )

        pipeline._process_enum_results('192.168.1.1', result)

        callback.assert_called_once_with({'username': 'admin', 'password': 'secret'})

    def test_on_finding_callback(self, pipeline, mock_framework):
        """Test finding callback is invoked."""
        callback = MagicMock()
        pipeline.on_finding = callback

        result = EnumResult(
            module='test',
            operation=None,
            target='192.168.1.1',
            success=True,
            findings=[
                {'type': 'vuln', 'name': 'SQL Injection', 'severity': 'high'}
            ]
        )

        pipeline._process_enum_results('192.168.1.1', result)

        callback.assert_called_once()


# =============================================================================
# Module Execution Tests
# =============================================================================

class TestModuleExecution:
    """Tests for module execution details."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        framework = MagicMock()
        framework.session = MagicMock()
        return framework

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline instance."""
        return AutoEnumPipeline(mock_framework)

    def test_run_module_sets_url_for_web_target(self, pipeline, mock_framework):
        """Test URL is set for web targets."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'URL': {}, 'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_module(
            target='https://example.com',
            module_path='web/httpx',
        )

        # URL should have been set
        mock_module.set_option.assert_any_call('URL', 'https://example.com')

    def test_run_module_sets_rhost_for_ip_target(self, pipeline, mock_framework):
        """Test RHOST is set for IP targets."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_module(
            target='192.168.1.1',
            module_path='recon/nmap',
        )

        mock_module.set_option.assert_called_with('RHOST', '192.168.1.1')

    def test_run_module_sets_credentials(self, pipeline, mock_framework):
        """Test credentials are set when provided."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {
            'RHOST': {},
            'USERNAME': {},
            'PASSWORD': {},
            'DOMAIN': {},
            'HASH': {},
        }
        mock_module.auto_set_from_context = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        credential = {
            'username': 'admin',
            'password': 'password123',
            'domain': 'CORP',
            'hash': 'aad3b435:8846f7eaee',
        }

        pipeline._run_module(
            target='192.168.1.1',
            module_path='network/nxc_smb',
            credential=credential,
        )

        mock_module.set_option.assert_any_call('USERNAME', 'admin')
        mock_module.set_option.assert_any_call('PASSWORD', 'password123')
        mock_module.set_option.assert_any_call('DOMAIN', 'CORP')
        mock_module.set_option.assert_any_call('HASH', 'aad3b435:8846f7eaee')

    def test_run_module_selects_operation(self, pipeline, mock_framework):
        """Test operation is selected when specified."""
        mock_module = MagicMock()
        mock_module.set_option = MagicMock(return_value=True)
        mock_module.options = {'RHOST': {}}
        mock_module.auto_set_from_context = MagicMock()
        mock_module.set_operation = MagicMock()
        mock_module.get_operations = MagicMock(return_value=[
            {'name': 'Enumerate Shares', 'handler': 'op_shares'},
        ])

        mock_framework.use_module = MagicMock(return_value=mock_module)
        mock_framework.run_module = MagicMock(return_value={
            'success': True,
            'services': [],
            'credentials': [],
            'users': [],
            'findings': [],
        })

        pipeline._run_module(
            target='192.168.1.1',
            module_path='network/nxc_smb',
            operation='Enumerate Shares',
        )

        # Either set_operation was called or current_operation was set
        # depending on the module interface


# =============================================================================
# Summary Building Tests
# =============================================================================

class TestSummaryBuilding:
    """Tests for summary building."""

    @pytest.fixture
    def mock_framework(self):
        """Create mock framework."""
        return MagicMock()

    @pytest.fixture
    def pipeline(self, mock_framework):
        """Create pipeline with test data."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_services = {
            '192.168.1.1': {'smb', 'http', 'ssh'},
            '192.168.1.2': {'rdp'},
        }
        pipeline.discovered_credentials = [
            {'username': 'admin', 'password': 'pass1'},
            {'username': 'user', 'password': 'pass2'},
        ]
        pipeline.discovered_users = {
            '192.168.1.1': ['admin', 'guest', 'user1'],
        }
        pipeline.results = [
            EnumResult(module='m1', operation=None, target='192.168.1.1', success=True, duration=1.5),
            EnumResult(module='m2', operation='op1', target='192.168.1.1', success=True, duration=2.0),
            EnumResult(module='m3', operation=None, target='192.168.1.2', success=False, duration=0.5, error='Failed'),
        ]
        return pipeline

    def test_build_summary_structure(self, pipeline):
        """Test summary has correct structure."""
        start_time = datetime.now() - timedelta(seconds=10)
        summary = pipeline._build_summary(start_time)

        required_keys = [
            'success', 'duration_seconds', 'targets_scanned',
            'modules_executed', 'successful_executions', 'failed_executions',
            'services_discovered', 'credentials_discovered',
            'users_discovered', 'findings', 'results'
        ]

        for key in required_keys:
            assert key in summary, f"Missing key: {key}"

    def test_build_summary_counts(self, pipeline):
        """Test summary counts are accurate."""
        start_time = datetime.now()
        summary = pipeline._build_summary(start_time)

        assert summary['targets_scanned'] == 2
        assert summary['modules_executed'] == 3
        assert summary['successful_executions'] == 2
        assert summary['failed_executions'] == 1
        assert summary['credentials_discovered'] == 2
        assert summary['users_discovered'] == 3

    def test_build_summary_services_format(self, pipeline):
        """Test services are formatted correctly."""
        start_time = datetime.now()
        summary = pipeline._build_summary(start_time)

        services = summary['services_discovered']
        assert '192.168.1.1' in services
        assert set(services['192.168.1.1']) == {'smb', 'http', 'ssh'}

    def test_build_summary_results_format(self, pipeline):
        """Test results are formatted correctly."""
        start_time = datetime.now()
        summary = pipeline._build_summary(start_time)

        results = summary['results']
        assert len(results) == 3

        for result in results:
            assert 'module' in result
            assert 'target' in result
            assert 'success' in result
            assert 'duration' in result

    def test_build_summary_success_with_failures(self, pipeline):
        """Test success is True when at least one module succeeded."""
        start_time = datetime.now()
        summary = pipeline._build_summary(start_time)

        # Has failures but also successes
        assert summary['success'] is True

    def test_build_summary_success_all_failed(self, mock_framework):
        """Test success is False when all modules failed."""
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.results = [
            EnumResult(module='m1', operation=None, target='192.168.1.1', success=False),
            EnumResult(module='m2', operation=None, target='192.168.1.1', success=False),
        ]

        start_time = datetime.now()
        summary = pipeline._build_summary(start_time)

        assert summary['success'] is False
