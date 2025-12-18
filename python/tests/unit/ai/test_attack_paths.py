"""
Tests for purplesploit.ai.attack_paths module.

Tests the AttackPathAnalyzer, AttackPath, AttackStep classes and related functionality.
"""

import pytest
from unittest.mock import Mock

from purplesploit.ai.attack_paths import (
    AttackPathAnalyzer,
    AttackPath,
    AttackStep,
    AttackCategory,
    ATTACK_PATH_TEMPLATES,
)


class TestAttackCategory:
    """Tests for AttackCategory enum."""

    def test_category_values(self):
        """Test that all category values are defined."""
        assert AttackCategory.INITIAL_ACCESS.value == "initial_access"
        assert AttackCategory.CREDENTIAL_ACCESS.value == "credential_access"
        assert AttackCategory.PRIVILEGE_ESCALATION.value == "privilege_escalation"
        assert AttackCategory.LATERAL_MOVEMENT.value == "lateral_movement"
        assert AttackCategory.PERSISTENCE.value == "persistence"
        assert AttackCategory.DATA_EXFILTRATION.value == "data_exfiltration"


class TestAttackStep:
    """Tests for AttackStep dataclass."""

    def test_step_creation_minimal(self):
        """Test creating step with minimal parameters."""
        step = AttackStep(name="Test Step", module="test/module")

        assert step.name == "Test Step"
        assert step.module == "test/module"
        assert step.operation is None
        assert step.description == ""
        assert step.requirements == []
        assert step.provides == []
        assert step.success_probability == 0.5

    def test_step_creation_full(self):
        """Test creating step with all parameters."""
        step = AttackStep(
            name="Enumerate SMB",
            module="smb/enumeration",
            operation="full_enum",
            description="Enumerate SMB shares and users",
            requirements=["smb_service"],
            provides=["share_list", "user_list"],
            mitre_technique="T1135",
            risk_level="low",
            success_probability=0.9,
        )

        assert step.name == "Enumerate SMB"
        assert step.module == "smb/enumeration"
        assert step.operation == "full_enum"
        assert step.requirements == ["smb_service"]
        assert step.provides == ["share_list", "user_list"]
        assert step.mitre_technique == "T1135"
        assert step.success_probability == 0.9

    def test_step_to_dict(self):
        """Test step serialization."""
        step = AttackStep(
            name="Test",
            module="test/module",
            requirements=["req1"],
            provides=["res1"],
            mitre_technique="T1000",
        )

        data = step.to_dict()

        assert data["name"] == "Test"
        assert data["module"] == "test/module"
        assert data["requirements"] == ["req1"]
        assert data["provides"] == ["res1"]
        assert data["mitre_technique"] == "T1000"
        assert "success_probability" in data


class TestAttackPath:
    """Tests for AttackPath dataclass."""

    def test_path_creation_minimal(self):
        """Test creating path with minimal parameters."""
        path = AttackPath(
            name="Test Path",
            description="A test attack path",
            category=AttackCategory.INITIAL_ACCESS,
        )

        assert path.name == "Test Path"
        assert path.description == "A test attack path"
        assert path.category == AttackCategory.INITIAL_ACCESS
        assert path.steps == []
        assert path.total_probability == 0.0

    def test_path_creation_with_steps(self):
        """Test creating path with steps."""
        steps = [
            AttackStep(name="Step 1", module="mod1", success_probability=0.9),
            AttackStep(name="Step 2", module="mod2", success_probability=0.8),
        ]

        path = AttackPath(
            name="Multi-step Path",
            description="Path with steps",
            category=AttackCategory.CREDENTIAL_ACCESS,
            steps=steps,
        )

        assert len(path.steps) == 2

    def test_calculate_probability_empty_steps(self):
        """Test probability calculation with no steps."""
        path = AttackPath(
            name="Empty",
            description="No steps",
            category=AttackCategory.INITIAL_ACCESS,
        )

        path.calculate_probability()

        assert path.total_probability == 0.0

    def test_calculate_probability_single_step(self):
        """Test probability calculation with one step."""
        step = AttackStep(name="Step", module="mod", success_probability=0.8)
        path = AttackPath(
            name="Single",
            description="One step",
            category=AttackCategory.INITIAL_ACCESS,
            steps=[step],
        )

        path.calculate_probability()

        assert path.total_probability == 0.8

    def test_calculate_probability_multiple_steps(self):
        """Test probability calculation with multiple steps."""
        steps = [
            AttackStep(name="Step 1", module="mod1", success_probability=0.9),
            AttackStep(name="Step 2", module="mod2", success_probability=0.8),
            AttackStep(name="Step 3", module="mod3", success_probability=0.5),
        ]

        path = AttackPath(
            name="Multi",
            description="Multiple steps",
            category=AttackCategory.INITIAL_ACCESS,
            steps=steps,
        )

        path.calculate_probability()

        # 0.9 * 0.8 * 0.5 = 0.36
        assert abs(path.total_probability - 0.36) < 0.001

    def test_path_to_dict(self):
        """Test path serialization."""
        step = AttackStep(name="Step", module="mod")
        path = AttackPath(
            name="Test Path",
            description="Description",
            category=AttackCategory.LATERAL_MOVEMENT,
            steps=[step],
            complexity="medium",
            stealth_level="high",
        )

        data = path.to_dict()

        assert data["name"] == "Test Path"
        assert data["description"] == "Description"
        assert data["category"] == "lateral_movement"
        assert len(data["steps"]) == 1
        assert data["complexity"] == "medium"
        assert data["stealth_level"] == "high"


class TestAttackPathTemplates:
    """Tests for ATTACK_PATH_TEMPLATES constant."""

    def test_smb_anonymous_template_exists(self):
        """Test SMB anonymous path template exists."""
        assert "smb_anonymous_to_creds" in ATTACK_PATH_TEMPLATES

    def test_ldap_asreproast_template_exists(self):
        """Test LDAP to AS-REP roast template exists."""
        assert "ldap_to_asreproast" in ATTACK_PATH_TEMPLATES

    def test_kerberoast_template_exists(self):
        """Test Kerberoasting template exists."""
        assert "kerberoast_path" in ATTACK_PATH_TEMPLATES

    def test_web_rce_template_exists(self):
        """Test Web to RCE template exists."""
        assert "web_to_rce" in ATTACK_PATH_TEMPLATES

    def test_template_structure(self):
        """Test template has required structure."""
        template = ATTACK_PATH_TEMPLATES["smb_anonymous_to_creds"]

        assert "name" in template
        assert "description" in template
        assert "category" in template
        assert "steps" in template
        assert len(template["steps"]) > 0

    def test_template_steps_have_requirements(self):
        """Test template steps have requirements/provides."""
        for name, template in ATTACK_PATH_TEMPLATES.items():
            for step in template["steps"]:
                if isinstance(step, dict):
                    assert "name" in step
                    assert "module" in step
                else:
                    # AttackStep object
                    assert step.name
                    assert step.module


class TestAttackPathAnalyzerInit:
    """Tests for AttackPathAnalyzer initialization."""

    def test_init_without_framework(self):
        """Test initialization without framework."""
        analyzer = AttackPathAnalyzer()

        assert analyzer.framework is None
        assert analyzer._available_resources == set()

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        analyzer = AttackPathAnalyzer(framework=mock_framework)

        assert analyzer.framework == mock_framework


class TestAttackPathAnalyzerAnalyze:
    """Tests for analyze method."""

    def test_analyze_no_services(self):
        """Test analysis with no services."""
        analyzer = AttackPathAnalyzer()

        paths = analyzer.analyze(services=[], credentials=[], findings=[])

        # Should return empty or minimal paths
        assert isinstance(paths, list)

    def test_analyze_smb_service(self):
        """Test analysis with SMB service."""
        analyzer = AttackPathAnalyzer()
        services = [{"port": 445, "service": "smb"}]

        paths = analyzer.analyze(services=services)

        # Should find SMB-based attack paths
        assert len(paths) >= 1
        path_names = [p.name for p in paths]
        assert any("SMB" in name for name in path_names)

    def test_analyze_http_service(self):
        """Test analysis with HTTP service."""
        analyzer = AttackPathAnalyzer()
        services = [{"port": 80, "service": "http"}]

        paths = analyzer.analyze(services=services)

        # Should find web-based attack paths
        path_names = [p.name for p in paths]
        assert any("Web" in name or "RCE" in name for name in path_names)

    def test_analyze_with_credentials(self):
        """Test analysis with credentials available."""
        analyzer = AttackPathAnalyzer()
        services = [{"port": 445, "service": "smb"}]
        credentials = [{"username": "admin", "password": "pass", "is_admin": True}]

        paths = analyzer.analyze(services=services, credentials=credentials)

        # Should find more paths with credentials
        assert len(paths) >= 1

    def test_analyze_sorted_by_probability(self):
        """Test paths are sorted by probability."""
        analyzer = AttackPathAnalyzer()
        services = [
            {"port": 445, "service": "smb"},
            {"port": 80, "service": "http"},
        ]

        paths = analyzer.analyze(services=services)

        # Should be sorted descending by probability
        if len(paths) >= 2:
            assert paths[0].total_probability >= paths[1].total_probability

    def test_analyze_ldap_kerberos(self):
        """Test analysis with LDAP and Kerberos services."""
        analyzer = AttackPathAnalyzer()
        services = [
            {"port": 389, "service": "ldap"},
            {"port": 88, "service": "kerberos"},
        ]

        paths = analyzer.analyze(services=services)

        # Should find AD-related attack paths
        path_names = [p.name for p in paths]
        assert any("LDAP" in name or "Kerber" in name or "AS-REP" in name for name in path_names)


class TestAttackPathAnalyzerGetPath:
    """Tests for get_attack_path method."""

    def test_get_existing_path(self):
        """Test getting an existing path template."""
        analyzer = AttackPathAnalyzer()

        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        assert path is not None
        assert "SMB" in path.name
        assert len(path.steps) > 0

    def test_get_nonexistent_path(self):
        """Test getting a nonexistent path returns None."""
        analyzer = AttackPathAnalyzer()

        path = analyzer.get_attack_path("nonexistent_path")

        assert path is None

    def test_get_path_calculates_probability(self):
        """Test that probability is calculated."""
        analyzer = AttackPathAnalyzer()

        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        assert path.total_probability > 0


class TestAttackPathAnalyzerSuggestNextStep:
    """Tests for suggest_next_step method."""

    def test_suggest_with_smb_resource(self):
        """Test suggestion with SMB service available."""
        analyzer = AttackPathAnalyzer()

        step = analyzer.suggest_next_step(current_resources={"smb_service"})

        # Should suggest SMB-related step
        if step:
            assert isinstance(step, AttackStep)

    def test_suggest_with_no_resources(self):
        """Test suggestion with no resources."""
        analyzer = AttackPathAnalyzer()

        step = analyzer.suggest_next_step(current_resources=set())

        # May return None if no steps are available without requirements
        assert step is None or isinstance(step, AttackStep)

    def test_suggest_with_share_list(self):
        """Test suggestion when share_list is available."""
        analyzer = AttackPathAnalyzer()

        step = analyzer.suggest_next_step(
            current_resources={"smb_service", "share_list"}
        )

        # Should suggest step that uses share_list
        if step:
            # The step should not re-provide share_list (already have it)
            assert "share_list" not in step.provides or len(step.provides) > 1

    def test_suggest_avoids_redundant_steps(self):
        """Test that already-achieved resources are skipped."""
        analyzer = AttackPathAnalyzer()

        # Already have everything from SMB enum
        resources = {
            "smb_service",
            "share_list",
            "sensitive_files",
            "credentials",
        }

        step = analyzer.suggest_next_step(current_resources=resources)

        # Should suggest something that provides new resources
        if step:
            new_resources = set(step.provides) - resources
            assert len(new_resources) > 0 or step is None


class TestAttackPathAnalyzerMitreMapping:
    """Tests for get_mitre_mapping method."""

    def test_mitre_mapping_basic(self):
        """Test basic MITRE mapping."""
        analyzer = AttackPathAnalyzer()
        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        mapping = analyzer.get_mitre_mapping(path)

        assert isinstance(mapping, dict)
        # Should have at least one tactic
        assert len(mapping) > 0

    def test_mitre_mapping_has_techniques(self):
        """Test that mapping includes techniques."""
        analyzer = AttackPathAnalyzer()
        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        mapping = analyzer.get_mitre_mapping(path)

        # Each tactic should have technique list
        for tactic, techniques in mapping.items():
            assert isinstance(techniques, list)
            assert len(techniques) > 0

    def test_mitre_mapping_empty_path(self):
        """Test mapping for path with no MITRE techniques."""
        analyzer = AttackPathAnalyzer()
        path = AttackPath(
            name="Empty",
            description="No MITRE",
            category=AttackCategory.INITIAL_ACCESS,
            steps=[AttackStep(name="Step", module="mod")],
        )

        mapping = analyzer.get_mitre_mapping(path)

        # Should return empty or minimal mapping
        assert isinstance(mapping, dict)


class TestAttackPathAnalyzerGenerateReport:
    """Tests for generate_report method."""

    def test_generate_report_single_path(self):
        """Test report generation for single path."""
        analyzer = AttackPathAnalyzer()
        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        report = analyzer.generate_report([path])

        assert "ATTACK PATH ANALYSIS REPORT" in report
        assert path.name in report

    def test_generate_report_multiple_paths(self):
        """Test report generation for multiple paths."""
        analyzer = AttackPathAnalyzer()
        paths = [
            analyzer.get_attack_path("smb_anonymous_to_creds"),
            analyzer.get_attack_path("web_to_rce"),
        ]

        report = analyzer.generate_report(paths)

        # Should include both paths
        assert "[1]" in report
        assert "[2]" in report

    def test_generate_report_includes_steps(self):
        """Test that report includes step details."""
        analyzer = AttackPathAnalyzer()
        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        report = analyzer.generate_report([path])

        assert "Steps:" in report
        # Should have numbered steps
        assert "1." in report

    def test_generate_report_includes_metadata(self):
        """Test that report includes path metadata."""
        analyzer = AttackPathAnalyzer()
        path = analyzer.get_attack_path("smb_anonymous_to_creds")

        report = analyzer.generate_report([path])

        assert "Category:" in report
        assert "Probability:" in report or "Success Probability:" in report
        assert "Complexity:" in report

    def test_generate_report_empty_list(self):
        """Test report generation for empty path list."""
        analyzer = AttackPathAnalyzer()

        report = analyzer.generate_report([])

        # Should still have header
        assert "ATTACK PATH ANALYSIS REPORT" in report


class TestAttackPathAnalyzerDetermineResources:
    """Tests for _determine_resources method."""

    def test_determine_resources_smb_service(self):
        """Test resource determination from SMB service."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[{"port": 445, "service": "smb"}],
            credentials=[],
            findings=[],
        )

        assert "smb_service" in resources

    def test_determine_resources_http_service(self):
        """Test resource determination from HTTP service."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[{"port": 80, "service": "http"}],
            credentials=[],
            findings=[],
        )

        assert "http_service" in resources

    def test_determine_resources_with_credentials(self):
        """Test resource determination with credentials."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[],
            credentials=[{"username": "user", "password": "pass"}],
            findings=[],
        )

        assert "credentials" in resources
        assert "valid_credentials" in resources

    def test_determine_resources_with_admin_creds(self):
        """Test resource determination with admin credentials."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[],
            credentials=[{"username": "admin", "password": "pass", "is_admin": True}],
            findings=[],
        )

        assert "admin_credentials" in resources
        assert "admin_access" in resources

    def test_determine_resources_from_findings(self):
        """Test resource determination from findings."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[],
            credentials=[],
            findings=[{"type": "user_list", "data": ["user1", "user2"]}],
        )

        assert "user_list" in resources

    def test_determine_resources_multiple_services(self):
        """Test resource determination from multiple services."""
        analyzer = AttackPathAnalyzer()

        resources = analyzer._determine_resources(
            services=[
                {"port": 445, "service": "smb"},
                {"port": 389, "service": "ldap"},
                {"port": 88, "service": "kerberos"},
            ],
            credentials=[],
            findings=[],
        )

        assert "smb_service" in resources
        assert "ldap_service" in resources
        assert "kerberos_service" in resources


class TestAttackPathAnalyzerEvaluateTemplate:
    """Tests for _evaluate_template method."""

    def test_evaluate_template_viable(self):
        """Test template evaluation when viable."""
        analyzer = AttackPathAnalyzer()
        analyzer._available_resources = {"smb_service"}

        template = ATTACK_PATH_TEMPLATES["smb_anonymous_to_creds"]
        path = analyzer._evaluate_template(template)

        assert path is not None
        assert isinstance(path, AttackPath)

    def test_evaluate_template_not_viable(self):
        """Test template evaluation when not viable."""
        analyzer = AttackPathAnalyzer()
        analyzer._available_resources = set()  # No resources

        # Kerberoast requires valid_credentials
        template = ATTACK_PATH_TEMPLATES["kerberoast_path"]
        path = analyzer._evaluate_template(template)

        assert path is None

    def test_evaluate_template_calculates_probability(self):
        """Test that evaluated template has probability calculated."""
        analyzer = AttackPathAnalyzer()
        analyzer._available_resources = {"smb_service"}

        template = ATTACK_PATH_TEMPLATES["smb_anonymous_to_creds"]
        path = analyzer._evaluate_template(template)

        assert path.total_probability > 0
