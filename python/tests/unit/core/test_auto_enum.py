"""
Tests for purplesploit.core.auto_enum module.
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime

from purplesploit.core.auto_enum import (
    AutoEnumPipeline,
    create_auto_enum,
    EnumPhase,
    EnumScope,
    ServiceRule,
    EnumResult,
    EnumProgress,
)


class TestEnumScope:
    """Tests for EnumScope enum."""

    def test_all_scopes_exist(self):
        """Test all expected scopes exist."""
        expected = ["passive", "light", "normal", "aggressive", "stealth"]
        for scope in expected:
            assert EnumScope(scope) is not None


class TestEnumPhase:
    """Tests for EnumPhase enum."""

    def test_all_phases_exist(self):
        """Test all expected phases exist."""
        expected = ["discovery", "enumeration", "exploitation", "post_exploitation"]
        for phase in expected:
            assert EnumPhase(phase) is not None


class TestServiceRule:
    """Tests for ServiceRule dataclass."""

    def test_basic_rule(self):
        """Test creating a basic service rule."""
        rule = ServiceRule(
            service="smb",
            ports=[445, 139],
            modules=["network/nxc_smb"],
            phase=EnumPhase.ENUMERATION,
        )

        assert rule.service == "smb"
        assert 445 in rule.ports
        assert "network/nxc_smb" in rule.modules
        assert rule.phase == EnumPhase.ENUMERATION
        assert rule.requires_auth is False
        assert rule.priority == 5

    def test_rule_with_auth(self):
        """Test creating a rule requiring authentication."""
        rule = ServiceRule(
            service="ssh",
            ports=[22],
            modules=["network/nxc_ssh"],
            requires_auth=True,
            priority=8,
        )

        assert rule.requires_auth is True
        assert rule.priority == 8


class TestEnumResult:
    """Tests for EnumResult dataclass."""

    def test_basic_result(self):
        """Test creating a basic result."""
        result = EnumResult(
            module="recon/nmap",
            operation="Quick Scan",
            target="192.168.1.1",
            success=True,
            output="Port 445/tcp open",
            duration=5.5,
        )

        assert result.module == "recon/nmap"
        assert result.success is True
        assert result.duration == 5.5

    def test_result_with_discoveries(self):
        """Test result with discovered data."""
        result = EnumResult(
            module="network/nxc_smb",
            operation="Enumerate Users",
            target="192.168.1.1",
            success=True,
            discovered_users=["admin", "user1", "user2"],
            discovered_credentials=[{"username": "guest", "password": ""}],
        )

        assert len(result.discovered_users) == 3
        assert len(result.discovered_credentials) == 1


class TestAutoEnumPipelineInit:
    """Tests for AutoEnumPipeline initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default settings."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        assert pipeline.framework == mock_framework
        assert pipeline.scope == EnumScope.NORMAL
        assert len(pipeline.service_rules) > 0
        assert len(pipeline.results) == 0

    def test_init_with_scope(self):
        """Test initialization with custom scope."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework, scope=EnumScope.AGGRESSIVE)

        assert pipeline.scope == EnumScope.AGGRESSIVE


class TestAutoEnumPipelineRules:
    """Tests for service rule management."""

    def test_default_rules_exist(self):
        """Test that default rules are loaded."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        # Check for common service rules
        services = {rule.service for rule in pipeline.service_rules}
        assert "smb" in services
        assert "http" in services
        assert "ldap" in services

    def test_add_custom_rule(self):
        """Test adding a custom rule."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        initial_count = len(pipeline.service_rules)

        pipeline.add_service_rule(ServiceRule(
            service="custom",
            modules=["custom/module"],
            priority=10,
        ))

        assert len(pipeline.service_rules) == initial_count + 1
        # High priority rule should be first
        assert pipeline.service_rules[0].service == "custom"


class TestAutoEnumPipelineControl:
    """Tests for pipeline control (stop, pause, resume)."""

    def test_stop(self):
        """Test stop signal."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        assert pipeline._stop_requested is False
        pipeline.stop()
        assert pipeline._stop_requested is True

    def test_pause_resume(self):
        """Test pause and resume."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        assert pipeline._pause_requested is False
        pipeline.pause()
        assert pipeline._pause_requested is True
        pipeline.resume()
        assert pipeline._pause_requested is False


class TestAutoEnumPipelineCallbacks:
    """Tests for pipeline callbacks."""

    def test_callbacks_can_be_set(self):
        """Test setting callbacks."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        progress_callback = Mock()
        service_callback = Mock()
        credential_callback = Mock()
        finding_callback = Mock()
        step_callback = Mock()

        pipeline.on_progress = progress_callback
        pipeline.on_service_found = service_callback
        pipeline.on_credential_found = credential_callback
        pipeline.on_finding = finding_callback
        pipeline.on_step_complete = step_callback

        assert pipeline.on_progress == progress_callback
        assert pipeline.on_service_found == service_callback


class TestAutoEnumPipelineHelpers:
    """Tests for helper methods."""

    def test_has_credentials_empty(self):
        """Test has_credentials with no credentials."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        assert pipeline._has_credentials() is False

    def test_has_credentials_with_creds(self):
        """Test has_credentials with credentials."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)
        pipeline.discovered_credentials = [{"username": "admin", "password": "pass"}]

        assert pipeline._has_credentials() is True

    def test_is_url(self):
        """Test URL detection."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        assert pipeline._is_url("http://example.com") is True
        assert pipeline._is_url("https://example.com") is True
        assert pipeline._is_url("192.168.1.1") is False
        assert pipeline._is_url("example.com") is False

    def test_get_nmap_operation_by_scope(self):
        """Test nmap operation selection by scope."""
        mock_framework = Mock()

        scopes_operations = {
            EnumScope.LIGHT: "Quick Scan",
            EnumScope.NORMAL: "Service Version",
            EnumScope.AGGRESSIVE: "Full Scan",
            EnumScope.STEALTH: "Stealth Scan",
        }

        for scope, expected_op in scopes_operations.items():
            pipeline = AutoEnumPipeline(mock_framework, scope=scope)
            assert pipeline._get_nmap_operation() == expected_op


class TestAutoEnumPipelineRun:
    """Tests for pipeline execution."""

    def test_build_summary(self):
        """Test summary building."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        # Add some mock data
        pipeline.discovered_services = {
            "192.168.1.1": {"smb", "http"},
            "192.168.1.2": {"ssh"},
        }
        pipeline.discovered_credentials = [
            {"username": "admin", "password": "pass"}
        ]
        pipeline.results = [
            EnumResult(module="recon/nmap", operation=None, target="192.168.1.1", success=True, duration=1.0),
            EnumResult(module="network/nxc_smb", operation="Shares", target="192.168.1.1", success=True, duration=2.0),
            EnumResult(module="recon/nmap", operation=None, target="192.168.1.2", success=False, duration=0.5),
        ]

        summary = pipeline._build_summary(datetime.now())

        assert summary["targets_scanned"] == 2
        assert summary["modules_executed"] == 3
        assert summary["successful_executions"] == 2
        assert summary["failed_executions"] == 1
        assert summary["credentials_discovered"] == 1
        assert "192.168.1.1" in summary["services_discovered"]

    def test_get_applicable_rules(self):
        """Test getting applicable rules for services."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        services = {"smb", "http"}
        rules = pipeline._get_applicable_rules(
            "192.168.1.1",
            services,
            EnumPhase.ENUMERATION
        )

        # Should return rules for both smb and http
        rule_services = {r.service for r in rules}
        assert "smb" in rule_services
        assert "http" in rule_services

    def test_check_rule_conditions_no_conditions(self):
        """Test rule condition checking with no conditions."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        rule = ServiceRule(service="test", modules=["test/module"])

        assert pipeline._check_rule_conditions(rule, "192.168.1.1") is True

    def test_check_rule_conditions_has_credentials(self):
        """Test condition checking for credentials."""
        mock_framework = Mock()
        pipeline = AutoEnumPipeline(mock_framework)

        rule = ServiceRule(
            service="test",
            modules=["test/module"],
            conditions=[{"type": "has_credentials"}]
        )

        # No credentials
        assert pipeline._check_rule_conditions(rule, "192.168.1.1") is False

        # With credentials
        pipeline.discovered_credentials = [{"username": "admin"}]
        assert pipeline._check_rule_conditions(rule, "192.168.1.1") is True


class TestCreateAutoEnum:
    """Tests for factory function."""

    def test_create_with_default_scope(self):
        """Test creating pipeline with default scope."""
        mock_framework = Mock()
        pipeline = create_auto_enum(mock_framework)

        assert isinstance(pipeline, AutoEnumPipeline)
        assert pipeline.scope == EnumScope.NORMAL

    def test_create_with_custom_scope(self):
        """Test creating pipeline with custom scope."""
        mock_framework = Mock()
        pipeline = create_auto_enum(mock_framework, scope="aggressive")

        assert pipeline.scope == EnumScope.AGGRESSIVE

    def test_create_with_invalid_scope(self):
        """Test creating pipeline with invalid scope falls back to normal."""
        mock_framework = Mock()
        pipeline = create_auto_enum(mock_framework, scope="invalid_scope")

        assert pipeline.scope == EnumScope.NORMAL


class TestEnumProgress:
    """Tests for EnumProgress dataclass."""

    def test_progress_creation(self):
        """Test creating progress object."""
        progress = EnumProgress(
            phase=EnumPhase.DISCOVERY,
            current_step="Port Scan",
            total_steps=10,
            completed_steps=3,
            current_target="192.168.1.1",
            start_time=datetime.now(),
            services_found=5,
            credentials_found=2,
        )

        assert progress.phase == EnumPhase.DISCOVERY
        assert progress.completed_steps == 3
        assert progress.services_found == 5
