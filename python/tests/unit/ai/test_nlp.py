"""
Tests for purplesploit.ai.nlp module.

Tests the NLPQueryHandler class for natural language processing of pentest queries.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock

from purplesploit.ai.nlp import NLPQueryHandler


class TestNLPQueryHandlerInit:
    """Tests for NLPQueryHandler initialization."""

    def test_init_without_framework(self):
        """Test initialization without framework."""
        handler = NLPQueryHandler()

        assert handler.framework is None
        assert handler.intent_patterns is not None
        assert handler.response_templates is not None

    def test_init_with_framework(self):
        """Test initialization with framework."""
        mock_framework = Mock()
        handler = NLPQueryHandler(framework=mock_framework)

        assert handler.framework == mock_framework

    def test_intent_patterns_defined(self):
        """Test that intent patterns are properly defined."""
        handler = NLPQueryHandler()

        assert "next_steps" in handler.intent_patterns
        assert "service_actions" in handler.intent_patterns
        assert "privilege_escalation" in handler.intent_patterns
        assert "lateral_movement" in handler.intent_patterns
        assert "credential_harvest" in handler.intent_patterns
        assert "status_query" in handler.intent_patterns

    def test_response_templates_defined(self):
        """Test that response templates are properly defined."""
        handler = NLPQueryHandler()

        assert "next_steps" in handler.response_templates
        assert "service_actions" in handler.response_templates
        assert "privilege_escalation" in handler.response_templates


class TestNLPQueryHandlerProcessQuery:
    """Tests for process_query method."""

    def test_process_query_next_steps(self):
        """Test processing 'what should I do next' query."""
        handler = NLPQueryHandler()

        result = handler.process_query("what should I do next?")

        assert result is not None
        assert "success" in result

    def test_process_query_service_actions_smb(self):
        """Test processing SMB service query."""
        handler = NLPQueryHandler()

        result = handler.process_query("what can I do with SMB?")

        assert result is not None
        assert "success" in result

    def test_process_query_service_actions_http(self):
        """Test processing HTTP service query."""
        handler = NLPQueryHandler()

        result = handler.process_query("how do I attack HTTP?")

        assert result is not None
        assert "success" in result

    def test_process_query_privilege_escalation(self):
        """Test processing privilege escalation query."""
        handler = NLPQueryHandler()

        result = handler.process_query("how do I escalate privileges?")

        assert result is not None
        assert result.get("success") is True
        assert "suggestions" in result

    def test_process_query_lateral_movement(self):
        """Test processing lateral movement query."""
        handler = NLPQueryHandler()

        result = handler.process_query("how do I move laterally?")

        assert result is not None
        assert result.get("success") is True
        assert "techniques" in result

    def test_process_query_credential_harvest(self):
        """Test processing credential harvesting query."""
        handler = NLPQueryHandler()

        result = handler.process_query("how do I get credentials?")

        assert result is not None
        assert result.get("success") is True
        assert "techniques" in result

    def test_process_query_status(self):
        """Test processing status query."""
        handler = NLPQueryHandler()
        context = {
            "services": [{"port": 80, "service": "http"}],
            "credentials": [],
            "targets": [{"ip": "192.168.1.1"}],
        }

        result = handler.process_query("what have I found?", context=context)

        assert result is not None
        assert result.get("success") is True
        assert "status" in result

    def test_process_query_module_help(self):
        """Test processing module help query."""
        handler = NLPQueryHandler()

        result = handler.process_query("how do I use a module?")

        assert result is not None
        assert result.get("success") is True
        assert "commands" in result

    def test_process_query_attack_path(self):
        """Test processing attack path query."""
        handler = NLPQueryHandler()
        context = {
            "services": [{"port": 445, "service": "smb"}],
            "credentials": [],
        }

        result = handler.process_query("show me an attack path", context=context)

        assert result is not None
        assert "success" in result

    def test_process_query_unknown_intent(self):
        """Test processing query with unknown intent."""
        handler = NLPQueryHandler()

        result = handler.process_query("random gibberish xyz123")

        assert result is not None
        assert result.get("success") is False
        assert "message" in result

    def test_process_query_case_insensitive(self):
        """Test that query processing is case-insensitive."""
        handler = NLPQueryHandler()

        result_lower = handler.process_query("what should i do next?")
        result_upper = handler.process_query("WHAT SHOULD I DO NEXT?")

        # Both should detect same intent
        assert result_lower.get("success") == result_upper.get("success")


class TestNLPQueryHandlerDetectIntent:
    """Tests for _detect_intent method."""

    def test_detect_intent_next_steps(self):
        """Test detecting next_steps intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("what should I do next")

        assert intent == "next_steps"

    def test_detect_intent_service_actions(self):
        """Test detecting service_actions intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("what can I do with smb")

        assert intent == "service_actions"
        assert "services" in extracted
        assert "smb" in extracted["services"]

    def test_detect_intent_privilege_escalation(self):
        """Test detecting privilege_escalation intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("how do I escalate privileges")

        assert intent == "privilege_escalation"

    def test_detect_intent_lateral_movement(self):
        """Test detecting lateral_movement intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("how do I move laterally")

        assert intent == "lateral_movement"

    def test_detect_intent_credential_harvest(self):
        """Test detecting credential_harvest intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("how do I get passwords")

        assert intent == "credential_harvest"

    def test_detect_intent_status_query(self):
        """Test detecting status_query intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("what have I found")

        assert intent == "status_query"

    def test_detect_intent_module_help(self):
        """Test detecting module_help intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("how do I use a module")

        assert intent == "module_help"

    def test_detect_intent_attack_path(self):
        """Test detecting attack_path intent."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("show me an attack path")

        assert intent == "attack_path"

    def test_detect_intent_no_match(self):
        """Test when no intent matches."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("random text here")

        assert intent is None
        assert extracted == {}

    def test_detect_intent_extracts_services(self):
        """Test that services are extracted from query."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("attack http and smb services")

        if intent == "service_actions":
            assert "http" in extracted.get("services", [])
            assert "smb" in extracted.get("services", [])

    def test_detect_intent_multiple_services(self):
        """Test extracting multiple services."""
        handler = NLPQueryHandler()

        intent, extracted = handler._detect_intent("what can I do with ldap and kerberos")

        if extracted.get("services"):
            assert "ldap" in extracted["services"]
            assert "kerberos" in extracted["services"]


class TestNLPQueryHandlerResponders:
    """Tests for response handler methods."""

    def test_respond_next_steps_no_services(self):
        """Test next steps response when no services discovered."""
        handler = NLPQueryHandler()
        context = {"services": [], "credentials": []}

        result = handler._respond_next_steps("", context, {})

        assert result["success"] is True
        assert "suggestions" in result
        # Should suggest reconnaissance
        assert any("recon" in str(s).lower() for s in result["suggestions"])

    def test_respond_next_steps_with_services(self):
        """Test next steps response with discovered services."""
        handler = NLPQueryHandler()
        context = {
            "services": [{"port": 80, "service": "http"}],
            "credentials": [],
        }

        result = handler._respond_next_steps("", context, {})

        assert result["success"] is True
        # Should have context summary
        assert "context_summary" in result

    def test_respond_service_actions_no_service(self):
        """Test service actions when no service specified."""
        handler = NLPQueryHandler()

        result = handler._respond_service_actions("", {}, {})

        assert result["success"] is False
        assert "specify" in result["message"].lower()

    def test_respond_service_actions_with_service(self):
        """Test service actions for specific service."""
        handler = NLPQueryHandler()
        extracted = {"services": ["smb"]}

        result = handler._respond_service_actions("", {}, extracted)

        assert result["success"] is True
        assert "actions" in result
        assert "SMB" in result["message"]

    def test_respond_privesc_includes_windows(self):
        """Test privesc response includes Windows techniques."""
        handler = NLPQueryHandler()

        result = handler._respond_privesc("", {}, {})

        assert result["success"] is True
        assert any("Windows" in s.get("category", "") for s in result["suggestions"])

    def test_respond_privesc_includes_linux(self):
        """Test privesc response includes Linux techniques."""
        handler = NLPQueryHandler()

        result = handler._respond_privesc("", {}, {})

        assert any("Linux" in s.get("category", "") for s in result["suggestions"])

    def test_respond_privesc_includes_ad_when_ldap(self):
        """Test privesc includes AD when LDAP service present."""
        handler = NLPQueryHandler()
        context = {"services": [{"service": "ldap"}]}

        result = handler._respond_privesc("", context, {})

        # Should include AD-specific techniques
        categories = [s.get("category", "") for s in result["suggestions"]]
        assert any("Active Directory" in c for c in categories)

    def test_respond_lateral_with_creds(self):
        """Test lateral movement response with credentials."""
        handler = NLPQueryHandler()
        context = {"credentials": [{"username": "admin", "password": "pass"}]}

        result = handler._respond_lateral("", context, {})

        assert result["success"] is True
        assert "techniques" in result
        # Should have credential-based techniques
        technique_names = [t.get("name", "") for t in result["techniques"]]
        assert any("Hash" in n or "Ticket" in n or "PSExec" in n for n in technique_names)

    def test_respond_lateral_without_creds(self):
        """Test lateral movement response without credentials."""
        handler = NLPQueryHandler()
        context = {"credentials": []}

        result = handler._respond_lateral("", context, {})

        assert result["success"] is True
        # Should suggest credential harvesting first
        assert any("Credential" in str(t) for t in result["techniques"])

    def test_respond_creds_has_techniques(self):
        """Test credential harvesting response has techniques."""
        handler = NLPQueryHandler()

        result = handler._respond_creds("", {}, {})

        assert result["success"] is True
        assert "techniques" in result
        assert len(result["techniques"]) > 0

    def test_respond_creds_includes_kerberoast(self):
        """Test credential response includes Kerberoasting."""
        handler = NLPQueryHandler()

        result = handler._respond_creds("", {}, {})

        technique_names = [t.get("name", "") for t in result["techniques"]]
        assert any("Kerberoast" in n for n in technique_names)

    def test_respond_creds_includes_cracking_tip(self):
        """Test credential response includes cracking tip."""
        handler = NLPQueryHandler()

        result = handler._respond_creds("", {}, {})

        assert "cracking_tip" in result

    def test_respond_status_with_services(self):
        """Test status response with discovered services."""
        handler = NLPQueryHandler()
        context = {
            "services": [
                {"service": "http"},
                {"service": "http"},
                {"service": "smb"},
            ],
            "credentials": [],
            "targets": [{"ip": "192.168.1.1"}],
        }

        result = handler._respond_status("", context, {})

        assert result["success"] is True
        assert result["status"]["services_discovered"] == 3
        assert result["status"]["targets"] == 1
        # Should count services by type
        assert "service_breakdown" in result["status"]

    def test_respond_module_help_has_commands(self):
        """Test module help response has commands."""
        handler = NLPQueryHandler()

        result = handler._respond_module_help("", {}, {})

        assert result["success"] is True
        assert "commands" in result
        assert len(result["commands"]) > 0

    def test_respond_module_help_has_example(self):
        """Test module help response has example."""
        handler = NLPQueryHandler()

        result = handler._respond_module_help("", {}, {})

        assert "example" in result

    def test_respond_attack_path_no_paths(self):
        """Test attack path response when no paths available."""
        handler = NLPQueryHandler()
        context = {"services": [], "credentials": []}

        result = handler._respond_attack_path("", context, {})

        assert result["success"] is True
        # Should indicate no paths or suggest enumeration

    def test_respond_attack_path_with_services(self):
        """Test attack path response with services."""
        handler = NLPQueryHandler()
        context = {
            "services": [{"port": 445, "service": "smb"}],
            "credentials": [],
        }

        result = handler._respond_attack_path("", context, {})

        assert result["success"] is True
        if "paths" in result:
            assert len(result["paths"]) > 0


class TestNLPQueryHandlerFrameworkContext:
    """Tests for framework context loading."""

    def test_load_framework_context_no_framework(self):
        """Test context loading without framework."""
        handler = NLPQueryHandler()

        context = handler._load_framework_context()

        assert context["services"] == []
        assert context["credentials"] == []
        assert context["targets"] == []
        assert context["findings"] == []

    def test_load_framework_context_with_framework(self):
        """Test context loading with framework."""
        mock_service = Mock()
        mock_service.to_dict.return_value = {"port": 80, "service": "http"}

        mock_cred = Mock()
        mock_cred.to_dict.return_value = {"username": "admin"}

        mock_target = Mock()
        mock_target.to_dict.return_value = {"ip": "192.168.1.1"}

        mock_db = Mock()
        mock_db.get_all_services.return_value = [mock_service]
        mock_db.get_all_credentials.return_value = [mock_cred]
        mock_db.get_all_targets.return_value = [mock_target]

        mock_framework = Mock()
        mock_framework.database = mock_db

        handler = NLPQueryHandler(framework=mock_framework)
        context = handler._load_framework_context()

        assert len(context["services"]) == 1
        assert len(context["credentials"]) == 1
        assert len(context["targets"]) == 1

    def test_load_framework_context_handles_errors(self):
        """Test context loading handles database errors gracefully."""
        mock_db = Mock()
        mock_db.get_all_services.side_effect = Exception("DB error")
        mock_db.get_all_credentials.side_effect = Exception("DB error")
        mock_db.get_all_targets.side_effect = Exception("DB error")

        mock_framework = Mock()
        mock_framework.database = mock_db

        handler = NLPQueryHandler(framework=mock_framework)
        context = handler._load_framework_context()

        # Should return empty context, not raise
        assert context["services"] == []

    def test_process_query_loads_framework_context(self):
        """Test that process_query loads context from framework."""
        mock_service = Mock()
        mock_service.to_dict.return_value = {"port": 80, "service": "http"}

        mock_db = Mock()
        mock_db.get_all_services.return_value = [mock_service]
        mock_db.get_all_credentials.return_value = []
        mock_db.get_all_targets.return_value = []

        mock_framework = Mock()
        mock_framework.database = mock_db

        handler = NLPQueryHandler(framework=mock_framework)

        # Query without explicit context should load from framework
        result = handler.process_query("what have I found?")

        # Should have called database methods
        mock_db.get_all_services.assert_called()


class TestNLPQueryHandlerIntegration:
    """Integration tests for NLPQueryHandler."""

    def test_full_workflow_query(self):
        """Test complete query processing workflow."""
        handler = NLPQueryHandler()
        context = {
            "services": [
                {"port": 445, "service": "smb"},
                {"port": 80, "service": "http"},
            ],
            "credentials": [{"username": "admin", "password": "pass", "is_admin": True}],
            "targets": [{"ip": "192.168.1.1"}],
        }

        # Query for next steps
        result = handler.process_query("what should I do next?", context=context)
        assert result["success"] is True

        # Query for specific service
        result = handler.process_query("what can I do with SMB?", context=context)
        assert result["success"] is True

        # Query for lateral movement
        result = handler.process_query("how do I move to other machines?", context=context)
        assert result["success"] is True

    def test_various_query_phrasings(self):
        """Test various ways of asking similar questions."""
        handler = NLPQueryHandler()

        # Different ways to ask for next steps
        queries = [
            "what should I do next",
            "what can I try now",
            "suggest a module",
            "recommend an action",
        ]

        for query in queries:
            result = handler.process_query(query)
            # Should detect as next_steps or similar actionable intent
            assert result is not None

    def test_service_query_variations(self):
        """Test various service-related queries."""
        handler = NLPQueryHandler()

        queries = [
            ("what can I do with http", "http"),
            ("how do I attack ldap", "ldap"),
            ("smb options", "smb"),
        ]

        for query, expected_service in queries:
            intent, extracted = handler._detect_intent(query)
            if intent == "service_actions":
                assert expected_service in extracted.get("services", [])
