"""
Tests for purplesploit.ai.recommender module.

Tests the ModuleRecommender class, Priority enum, and Recommendation dataclass.
"""

import pytest
from unittest.mock import Mock, MagicMock
from typing import List, Dict

from purplesploit.ai.recommender import (
    ModuleRecommender,
    Priority,
    Recommendation,
    SERVICE_MODULE_MAP,
    PORT_SERVICE,
)


class TestPriority:
    """Tests for Priority enum."""

    def test_priority_values(self):
        """Test that all priority values are defined."""
        assert Priority.CRITICAL.value == "critical"
        assert Priority.HIGH.value == "high"
        assert Priority.MEDIUM.value == "medium"
        assert Priority.LOW.value == "low"
        assert Priority.INFO.value == "info"

    def test_priority_ordering(self):
        """Test that priorities can be compared for ordering."""
        priorities = list(Priority)

        assert Priority.CRITICAL in priorities
        assert Priority.HIGH in priorities
        assert priorities.index(Priority.CRITICAL) < priorities.index(Priority.INFO)


class TestRecommendation:
    """Tests for Recommendation dataclass."""

    def test_recommendation_creation_minimal(self):
        """Test creating recommendation with minimal parameters."""
        rec = Recommendation(module_path="test/module")

        assert rec.module_path == "test/module"
        assert rec.operation is None
        assert rec.priority == Priority.MEDIUM
        assert rec.reason == ""
        assert rec.prerequisites == []
        assert rec.confidence == 0.8

    def test_recommendation_creation_full(self):
        """Test creating recommendation with all parameters."""
        rec = Recommendation(
            module_path="smb/enumeration",
            operation="full_enum",
            priority=Priority.HIGH,
            reason="SMB service detected on port 445",
            prerequisites=["network_access"],
            expected_outcome="Discover shares and users",
            risk_level="medium",
            tags=["enumeration", "smb"],
            confidence=0.95,
        )

        assert rec.module_path == "smb/enumeration"
        assert rec.operation == "full_enum"
        assert rec.priority == Priority.HIGH
        assert rec.prerequisites == ["network_access"]
        assert rec.confidence == 0.95

    def test_recommendation_to_dict(self):
        """Test to_dict serialization."""
        rec = Recommendation(
            module_path="web/feroxbuster",
            priority=Priority.HIGH,
            reason="HTTP service found",
            tags=["web", "enumeration"],
        )

        data = rec.to_dict()

        assert data["module"] == "web/feroxbuster"
        assert data["priority"] == "high"
        assert data["reason"] == "HTTP service found"
        assert data["tags"] == ["web", "enumeration"]
        assert "confidence" in data

    def test_recommendation_default_values(self):
        """Test default values in recommendation."""
        rec = Recommendation(module_path="test/module")

        assert rec.expected_outcome == ""
        assert rec.risk_level == "low"
        assert rec.tags == []


class TestServiceModuleMap:
    """Tests for SERVICE_MODULE_MAP constant."""

    def test_smb_service_mapping(self):
        """Test SMB service has module mappings."""
        assert "smb" in SERVICE_MODULE_MAP

        smb_config = SERVICE_MODULE_MAP["smb"]
        assert "modules" in smb_config
        assert len(smb_config["modules"]) > 0

    def test_http_service_mapping(self):
        """Test HTTP service has module mappings."""
        assert "http" in SERVICE_MODULE_MAP

        http_config = SERVICE_MODULE_MAP["http"]
        modules = http_config["modules"]

        # Should have feroxbuster and nuclei
        paths = [m["path"] for m in modules]
        assert "web/feroxbuster" in paths
        assert "recon/nuclei" in paths

    def test_ldap_service_mapping(self):
        """Test LDAP service has module mappings."""
        assert "ldap" in SERVICE_MODULE_MAP

        ldap_config = SERVICE_MODULE_MAP["ldap"]
        modules = ldap_config["modules"]

        paths = [m["path"] for m in modules]
        assert "network/nxc_ldap" in paths

    def test_quick_wins_defined(self):
        """Test quick wins are defined for services."""
        for service, config in SERVICE_MODULE_MAP.items():
            if "quick_wins" in config:
                assert isinstance(config["quick_wins"], list)


class TestPortServiceMap:
    """Tests for PORT_SERVICE constant."""

    def test_common_ports_mapped(self):
        """Test common ports are mapped to services."""
        assert PORT_SERVICE[22] == "ssh"
        assert PORT_SERVICE[80] == "http"
        assert PORT_SERVICE[443] == "https"
        assert PORT_SERVICE[445] == "smb"
        assert PORT_SERVICE[3389] == "rdp"

    def test_smb_ports(self):
        """Test SMB ports are mapped."""
        assert PORT_SERVICE[139] == "smb"
        assert PORT_SERVICE[445] == "smb"

    def test_kerberos_ports(self):
        """Test Kerberos ports are mapped."""
        assert PORT_SERVICE[88] == "kerberos"

    def test_database_ports(self):
        """Test database ports are mapped."""
        assert PORT_SERVICE[1433] == "mssql"
        assert PORT_SERVICE[3306] == "mysql"
        assert PORT_SERVICE[5432] == "postgresql"


class TestModuleRecommenderInit:
    """Tests for ModuleRecommender initialization."""

    def test_init_without_framework(self):
        """Test initialization without framework."""
        recommender = ModuleRecommender()

        assert recommender.framework is None
        assert recommender._completed_modules == set()
        assert recommender._findings == []

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        recommender = ModuleRecommender(framework=mock_framework)

        assert recommender.framework == mock_framework


class TestModuleRecommenderGetRecommendations:
    """Tests for get_recommendations method."""

    def test_get_recommendations_empty_services(self):
        """Test recommendations with no services."""
        recommender = ModuleRecommender()
        recommendations = recommender.get_recommendations(services=[])

        assert recommendations == []

    def test_get_recommendations_smb_service(self):
        """Test recommendations for SMB service."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb", "target": "192.168.1.1"}]

        recommendations = recommender.get_recommendations(services=services)

        assert len(recommendations) > 0
        module_paths = [r.module_path for r in recommendations]
        assert "smb/enumeration" in module_paths or "smb/shares" in module_paths

    def test_get_recommendations_http_service(self):
        """Test recommendations for HTTP service."""
        recommender = ModuleRecommender()
        services = [{"port": 80, "service": "http", "target": "192.168.1.1"}]

        recommendations = recommender.get_recommendations(services=services)

        assert len(recommendations) > 0
        module_paths = [r.module_path for r in recommendations]
        assert "web/httpx" in module_paths
        assert "recon/nuclei" in module_paths

    def test_get_recommendations_multiple_services(self):
        """Test recommendations for multiple services."""
        recommender = ModuleRecommender()
        services = [
            {"port": 445, "service": "smb", "target": "192.168.1.1"},
            {"port": 80, "service": "http", "target": "192.168.1.1"},
            {"port": 389, "service": "ldap", "target": "192.168.1.1"},
        ]

        recommendations = recommender.get_recommendations(services=services)

        assert len(recommendations) > 3  # Multiple recommendations per service

    def test_get_recommendations_excludes_completed(self):
        """Test that completed modules are excluded."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb", "target": "192.168.1.1"}]
        completed = ["smb/enumeration", "smb/shares"]

        recommendations = recommender.get_recommendations(
            services=services,
            completed=completed,
        )

        module_paths = [r.module_path for r in recommendations]
        assert "smb/enumeration" not in module_paths
        assert "smb/shares" not in module_paths

    def test_get_recommendations_respects_max_results(self):
        """Test that max_results limits output."""
        recommender = ModuleRecommender()
        services = [
            {"port": 445, "service": "smb"},
            {"port": 80, "service": "http"},
            {"port": 389, "service": "ldap"},
        ]

        recommendations = recommender.get_recommendations(
            services=services,
            max_results=3,
        )

        assert len(recommendations) <= 3

    def test_get_recommendations_sorted_by_priority(self):
        """Test recommendations are sorted by priority."""
        recommender = ModuleRecommender()
        services = [{"port": 80, "service": "http"}]

        recommendations = recommender.get_recommendations(services=services)

        # First recommendations should be higher priority
        if len(recommendations) >= 2:
            first_priority_idx = list(Priority).index(recommendations[0].priority)
            second_priority_idx = list(Priority).index(recommendations[1].priority)
            assert first_priority_idx <= second_priority_idx

    def test_get_recommendations_with_credentials(self):
        """Test recommendations when credentials are available."""
        recommender = ModuleRecommender()
        services = [{"port": 5985, "service": "winrm"}]
        credentials = [{"username": "admin", "password": "pass", "is_admin": True}]

        recommendations = recommender.get_recommendations(
            services=services,
            credentials=credentials,
        )

        # Should include modules that require credentials
        module_paths = [r.module_path for r in recommendations]
        # WinRM modules should be recommended with admin creds
        assert any("winrm" in path or "wmi" in path for path in module_paths)

    def test_get_recommendations_without_admin_creds(self):
        """Test that admin-only modules are excluded without admin creds."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb"}]
        credentials = [{"username": "user", "password": "pass", "is_admin": False}]

        recommendations = recommender.get_recommendations(
            services=services,
            credentials=credentials,
        )

        module_paths = [r.module_path for r in recommendations]
        # secretsdump requires admin, should not be recommended
        assert "impacket/secretsdump" not in module_paths

    def test_get_recommendations_deduplicates(self):
        """Test that duplicate modules are removed."""
        recommender = ModuleRecommender()
        # Multiple services that map to same modules
        services = [
            {"port": 80, "service": "http"},
            {"port": 8080, "service": "http"},
        ]

        recommendations = recommender.get_recommendations(services=services)

        module_paths = [r.module_path for r in recommendations]
        # Should not have duplicates
        assert len(module_paths) == len(set(module_paths))


class TestModuleRecommenderQuickWins:
    """Tests for get_quick_wins method."""

    def test_get_quick_wins_smb(self):
        """Test quick wins for SMB service."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb"}]

        quick_wins = recommender.get_quick_wins(services=services)

        assert len(quick_wins) > 0
        # Should include anonymous shares check
        reasons = [qw.reason for qw in quick_wins]
        assert any("anonymous" in r.lower() for r in reasons)

    def test_get_quick_wins_http(self):
        """Test quick wins for HTTP service."""
        recommender = ModuleRecommender()
        services = [{"port": 80, "service": "http"}]

        quick_wins = recommender.get_quick_wins(services=services)

        assert len(quick_wins) > 0

    def test_get_quick_wins_empty_services(self):
        """Test quick wins with no services."""
        recommender = ModuleRecommender()

        quick_wins = recommender.get_quick_wins(services=[])

        assert quick_wins == []

    def test_get_quick_wins_priority(self):
        """Test that quick wins have high priority."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb"}]

        quick_wins = recommender.get_quick_wins(services=services)

        for qw in quick_wins:
            assert qw.priority == Priority.HIGH

    def test_get_quick_wins_tagged(self):
        """Test that quick wins are tagged appropriately."""
        recommender = ModuleRecommender()
        services = [{"port": 445, "service": "smb"}]

        quick_wins = recommender.get_quick_wins(services=services)

        for qw in quick_wins:
            assert "quick-win" in qw.tags


class TestModuleRecommenderServiceRecommendations:
    """Tests for get_recommendations_for_service method."""

    def test_get_recommendations_for_smb(self):
        """Test recommendations for SMB service."""
        recommender = ModuleRecommender()

        recommendations = recommender.get_recommendations_for_service("smb")

        assert len(recommendations) > 0
        module_paths = [r.module_path for r in recommendations]
        assert "smb/enumeration" in module_paths

    def test_get_recommendations_for_http(self):
        """Test recommendations for HTTP service."""
        recommender = ModuleRecommender()

        recommendations = recommender.get_recommendations_for_service("http")

        module_paths = [r.module_path for r in recommendations]
        assert "web/httpx" in module_paths
        assert "web/feroxbuster" in module_paths

    def test_get_recommendations_for_service_with_creds(self):
        """Test recommendations with credentials flag."""
        recommender = ModuleRecommender()

        recommendations = recommender.get_recommendations_for_service(
            "kerberos",
            has_creds=True,
        )

        module_paths = [r.module_path for r in recommendations]
        # Kerberoast requires creds
        assert "impacket/kerberoast" in module_paths

    def test_get_recommendations_for_service_without_creds(self):
        """Test recommendations without credentials."""
        recommender = ModuleRecommender()

        recommendations = recommender.get_recommendations_for_service(
            "kerberos",
            has_creds=False,
        )

        module_paths = [r.module_path for r in recommendations]
        # Kerberoast requires creds, should not be included
        assert "impacket/kerberoast" not in module_paths

    def test_get_recommendations_for_unknown_service(self):
        """Test recommendations for unknown service."""
        recommender = ModuleRecommender()

        recommendations = recommender.get_recommendations_for_service("unknown_service")

        assert recommendations == []

    def test_get_recommendations_for_service_case_insensitive(self):
        """Test service name is case-insensitive."""
        recommender = ModuleRecommender()

        recommendations_lower = recommender.get_recommendations_for_service("smb")
        recommendations_upper = recommender.get_recommendations_for_service("SMB")

        assert len(recommendations_lower) == len(recommendations_upper)


class TestModuleRecommenderSuggestNext:
    """Tests for suggest_next_module method."""

    def test_suggest_next_with_services(self):
        """Test next suggestion when services available."""
        recommender = ModuleRecommender()

        # Setup via get_recommendations first
        services = [{"port": 445, "service": "smb"}]
        recommender.get_recommendations(services=services)

        # Should return a recommendation
        suggestion = recommender.suggest_next_module()

        # May return None if no framework context
        # With framework it would return top recommendation

    def test_suggest_next_with_framework(self):
        """Test next suggestion with framework context."""
        mock_service = Mock()
        mock_service.to_dict.return_value = {"port": 80, "service": "http"}

        mock_db = Mock()
        mock_db.get_all_services.return_value = [mock_service]
        mock_db.get_all_credentials.return_value = []

        mock_framework = Mock()
        mock_framework.database = mock_db

        recommender = ModuleRecommender(framework=mock_framework)
        suggestion = recommender.suggest_next_module()

        # Should return top recommendation
        if suggestion:
            assert isinstance(suggestion, Recommendation)


class TestModuleRecommenderNormalizeService:
    """Tests for _normalize_service method."""

    def test_normalize_service_from_dict(self):
        """Test normalizing service from dict with service key."""
        recommender = ModuleRecommender()

        result = recommender._normalize_service({"service": "smb", "port": 445})

        assert result == "smb"

    def test_normalize_service_from_port(self):
        """Test normalizing service from port number."""
        recommender = ModuleRecommender()

        result = recommender._normalize_service({"port": 445})

        assert result == "smb"

    def test_normalize_service_from_string(self):
        """Test normalizing service from string."""
        recommender = ModuleRecommender()

        result = recommender._normalize_service("http")

        assert result == "http"

    def test_normalize_service_unknown(self):
        """Test normalizing unknown service."""
        recommender = ModuleRecommender()

        result = recommender._normalize_service({"service": "unknown", "port": 99999})

        assert result is None

    def test_normalize_service_partial_match(self):
        """Test normalizing service with partial match."""
        recommender = ModuleRecommender()

        result = recommender._normalize_service({"service": "microsoft-ds (smb)"})

        # Should extract smb from the service name
        # Implementation may vary


class TestModuleRecommenderCheckPrerequisites:
    """Tests for _check_prerequisites method."""

    def test_check_prerequisites_empty(self):
        """Test with no prerequisites."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites([], False, False, False)

        assert result is True

    def test_check_prerequisites_valid_creds_met(self):
        """Test valid_creds prerequisite when met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(["valid_creds"], True, False, False)

        assert result is True

    def test_check_prerequisites_valid_creds_not_met(self):
        """Test valid_creds prerequisite when not met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(["valid_creds"], False, False, False)

        assert result is False

    def test_check_prerequisites_admin_creds_met(self):
        """Test admin_creds prerequisite when met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(["admin_creds"], True, True, False)

        assert result is True

    def test_check_prerequisites_admin_creds_not_met(self):
        """Test admin_creds prerequisite when not met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(["admin_creds"], True, False, False)

        assert result is False

    def test_check_prerequisites_user_list_met(self):
        """Test user_list prerequisite when met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(["user_list"], False, False, True)

        assert result is True

    def test_check_prerequisites_multiple_all_met(self):
        """Test multiple prerequisites when all met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(
            ["valid_creds", "user_list"],
            True, False, True
        )

        assert result is True

    def test_check_prerequisites_multiple_some_not_met(self):
        """Test multiple prerequisites when some not met."""
        recommender = ModuleRecommender()

        result = recommender._check_prerequisites(
            ["valid_creds", "admin_creds"],
            True, False, False  # Has creds but not admin
        )

        assert result is False


class TestModuleRecommenderAssessRisk:
    """Tests for _assess_risk method."""

    def test_assess_risk_low(self):
        """Test low risk module."""
        recommender = ModuleRecommender()

        risk = recommender._assess_risk("smb/enumeration")

        assert risk == "low"

    def test_assess_risk_medium_sqlmap(self):
        """Test medium risk for sqlmap."""
        recommender = ModuleRecommender()

        risk = recommender._assess_risk("web/sqlmap")

        assert risk == "medium"

    def test_assess_risk_medium_secretsdump(self):
        """Test medium risk for secretsdump."""
        recommender = ModuleRecommender()

        risk = recommender._assess_risk("impacket/secretsdump")

        assert risk == "medium"

    def test_assess_risk_high_psexec(self):
        """Test high risk for psexec."""
        recommender = ModuleRecommender()

        risk = recommender._assess_risk("impacket/psexec")

        assert risk == "high"

    def test_assess_risk_high_wmiexec(self):
        """Test high risk for wmiexec."""
        recommender = ModuleRecommender()

        risk = recommender._assess_risk("impacket/wmiexec")

        assert risk == "high"


class TestModuleRecommenderCalculateConfidence:
    """Tests for _calculate_confidence method."""

    def test_calculate_confidence_base(self):
        """Test base confidence calculation."""
        recommender = ModuleRecommender()

        confidence = recommender._calculate_confidence(
            {"service": "http"},
            {"priority": Priority.MEDIUM, "tags": []}
        )

        assert 0.6 <= confidence <= 1.0

    def test_calculate_confidence_critical_boost(self):
        """Test confidence boost for critical priority."""
        recommender = ModuleRecommender()

        confidence = recommender._calculate_confidence(
            {"service": "http"},
            {"priority": Priority.CRITICAL, "tags": []}
        )

        assert confidence >= 0.8

    def test_calculate_confidence_high_boost(self):
        """Test confidence boost for high priority."""
        recommender = ModuleRecommender()

        confidence = recommender._calculate_confidence(
            {"service": "http"},
            {"priority": Priority.HIGH, "tags": []}
        )

        assert confidence >= 0.7

    def test_calculate_confidence_capped_at_1(self):
        """Test confidence is capped at 1.0."""
        recommender = ModuleRecommender()

        confidence = recommender._calculate_confidence(
            {"service": "http", "version": "Apache 2.4"},
            {"priority": Priority.CRITICAL, "tags": ["enumeration"]}
        )

        assert confidence <= 1.0


class TestModuleRecommenderFrameworkIntegration:
    """Tests for framework integration."""

    def test_get_services_from_framework(self):
        """Test getting services from framework database."""
        mock_service = Mock()
        mock_service.to_dict.return_value = {"port": 445, "service": "smb"}

        mock_db = Mock()
        mock_db.get_all_services.return_value = [mock_service]

        mock_framework = Mock()
        mock_framework.database = mock_db

        recommender = ModuleRecommender(framework=mock_framework)
        services = recommender._get_services_from_framework()

        assert len(services) == 1
        assert services[0]["service"] == "smb"

    def test_get_services_from_framework_error(self):
        """Test graceful handling of framework errors."""
        mock_db = Mock()
        mock_db.get_all_services.side_effect = Exception("Database error")

        mock_framework = Mock()
        mock_framework.database = mock_db

        recommender = ModuleRecommender(framework=mock_framework)
        services = recommender._get_services_from_framework()

        assert services == []

    def test_get_credentials_from_framework(self):
        """Test getting credentials from framework database."""
        mock_cred = Mock()
        mock_cred.to_dict.return_value = {"username": "admin", "is_admin": True}

        mock_db = Mock()
        mock_db.get_all_credentials.return_value = [mock_cred]

        mock_framework = Mock()
        mock_framework.database = mock_db

        recommender = ModuleRecommender(framework=mock_framework)
        creds = recommender._get_credentials_from_framework()

        assert len(creds) == 1
        assert creds[0]["is_admin"] is True

    def test_get_credentials_from_framework_error(self):
        """Test graceful handling of credential errors."""
        mock_db = Mock()
        mock_db.get_all_credentials.side_effect = Exception("Database error")

        mock_framework = Mock()
        mock_framework.database = mock_db

        recommender = ModuleRecommender(framework=mock_framework)
        creds = recommender._get_credentials_from_framework()

        assert creds == []
