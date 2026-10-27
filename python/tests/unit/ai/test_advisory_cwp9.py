"""Advisory contracts tested offline against a live framework registry."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from jsonschema import ValidationError

from purplesploit.ai.advisory import AdvisoryService
from purplesploit.ai.providers import (
    AdvisoryProvider,
    DEFAULT_MODELS,
    provider_from_environment,
)
from purplesploit.ai.recommender import ModuleRecommender
from purplesploit.ai.attack_paths import AttackPathAnalyzer, ATTACK_PATH_TEMPLATES
from purplesploit.ai.nlp import NLPQueryHandler
from purplesploit.core.execution import Observation
from purplesploit.core.framework import Framework
from purplesploit.core.module import BaseModule
from purplesploit.core.workflow import WorkflowEngine
from purplesploit.modules.ai.ai_automation import AIAutomationModule


class ProbeModule(BaseModule):
    name = "Fixture HTTP probe"
    description = "Offline manifest fixture"
    author = "Test"
    category = "web"

    def _init_options(self):
        self.options = {"URL": {"value": None, "required": True}}

    def get_operations(self):
        return [{"id": "probe", "name": "Probe URL", "handler": self.op_probe}]

    def op_probe(self):
        raise AssertionError("AI must never execute a module")

    def run(self):
        raise AssertionError("AI must never execute a module")


@pytest.fixture
def framework(tmp_path):
    framework = Framework(db_path=str(tmp_path / "framework.db"),
                          plugins_dir=tmp_path / "plugins", plugin_config_dir=tmp_path / "plugin-config")
    framework.register_module("web/httpx", ProbeModule)
    framework.session.module_history = [{"execution": {"observations": [
        Observation("service", "192.0.2.1", port=80, service="http").to_dict(),
    ]}}]
    framework.execute_request = Mock(side_effect=AssertionError("AI must never execute"))
    framework.run_module = Mock(side_effect=AssertionError("AI must never execute"))
    return framework


def valid_step(**changes):
    return {"module": "web/httpx", "operation": "probe", "reason": "Observed HTTP service",
            "options": {"URL": "http://192.0.2.1"}, **changes}


def test_recommendations_follow_live_registry_operations_and_canonical_observations(framework):
    recommender = ModuleRecommender(framework)
    result = recommender.get_recommendations()
    assert [(item.module_path, item.operation) for item in result] == [("web/httpx", "probe")]
    assert [item.module_path for item in recommender.get_quick_wins()] == ["web/httpx"]
    framework.unregister_module("web/httpx")
    assert recommender.get_recommendations() == []
    assert recommender.get_quick_wins() == []


def test_explicit_empty_observations_do_not_fall_back_to_session(framework):
    assert ModuleRecommender(framework).get_recommendations(observations=[]) == []


def test_local_analysis_and_workflow_draft_persist_without_execution(framework, tmp_path):
    service = AdvisoryService(framework, storage_path=tmp_path / "workflows")
    analysis = service.analyze()
    assert analysis["mode"] == "local"
    assert analysis["analysis"]["recommendations"][0]["operation"] == "probe"
    draft = service.propose_workflow()
    assert draft["draft"] and not draft["executed"]
    assert draft["workflow"]["status"] == "created"
    assert "draft" in draft["workflow"]["tags"]
    restored = WorkflowEngine(framework, tmp_path / "workflows").load_workflow(draft["workflow"]["id"])
    assert restored.steps[0].module == "web/httpx"
    framework.execute_request.assert_not_called()
    framework.run_module.assert_not_called()


def test_provider_receives_live_inventory_and_typed_observations(framework, tmp_path):
    provider = Mock()
    provider.generate.return_value = {"summary": "HTTP observed", "recommendations": [valid_step()]}
    service = AdvisoryService(framework, provider, storage_path=tmp_path / "workflows")
    assert service.analyze(consent=True)["mode"] == "provider"
    context = provider.generate.call_args.args[1]
    assert context["inventory"][0]["path"] == "web/httpx"
    assert context["inventory"][0]["operations"][0]["id"] == "probe"
    assert context["observations"][0]["observation_id"]


@pytest.mark.parametrize("step,error", [
    (valid_step(module="post/fake_privesc"), ValueError),
    (valid_step(operation="fake-operation"), ValueError),
    (valid_step(options={"NONEXISTENT": "x"}), ValueError),
    ({"module": "web/httpx"}, ValidationError),
])
def test_invalid_provider_workflow_cannot_be_saved(framework, tmp_path, step, error):
    provider = Mock()
    provider.generate.return_value = {"name": "Draft", "description": "Fixture", "steps": [step]}
    service = AdvisoryService(framework, provider, storage_path=tmp_path / "workflows")
    with pytest.raises(error):
        service.propose_workflow(consent=True)
    assert service.workflows.list_workflows() == []
    framework.execute_request.assert_not_called()


@pytest.mark.parametrize("provider_name", ["openai", "anthropic"])
def test_current_provider_boundaries_and_distinct_default_models(provider_name):
    client = Mock()
    value = '{"summary":"fixture","recommendations":[]}'
    client.responses.create.return_value = SimpleNamespace(output_text=value)
    client.messages.create.return_value = SimpleNamespace(content=[SimpleNamespace(type="text", text=value)])
    provider = AdvisoryProvider(provider_name, client=client)
    assert provider.generate("analysis", {}, {"type": "object"})["summary"] == "fixture"
    call = client.responses.create if provider_name == "openai" else client.messages.create
    assert call.call_args.kwargs["model"] == DEFAULT_MODELS[provider_name]
    assert DEFAULT_MODELS["openai"] != DEFAULT_MODELS["anthropic"]
    assert ("input" if provider_name == "openai" else "messages") in call.call_args.kwargs


def test_provider_override_unknown_provider_and_bad_json():
    client = Mock()
    client.responses.create.return_value.output_text = "not JSON"
    provider = AdvisoryProvider("openai", "explicit-model", client=client)
    with pytest.raises(ValueError):
        provider.generate("analysis", {}, {})
    assert client.responses.create.call_args.kwargs["model"] == "explicit-model"
    with pytest.raises(ValueError, match="Unknown provider"):
        AdvisoryProvider("unknown")


def test_provider_can_be_selected_for_application_surfaces(monkeypatch):
    monkeypatch.setenv("PURPLESPLOIT_AI_PROVIDER", "anthropic")
    monkeypatch.setenv("PURPLESPLOIT_AI_MODEL", "fixture-model")
    provider = provider_from_environment()
    assert provider.provider == "anthropic"
    assert provider.model == "fixture-model"
    monkeypatch.delenv("PURPLESPLOIT_AI_PROVIDER")
    assert provider_from_environment() is None


def test_module_handlers_use_advisory_and_proposal_never_runs(framework, tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    module = AIAutomationModule(framework)
    service = AdvisoryService(framework, storage_path=tmp_path / "workflows")
    monkeypatch.setattr(module, "_advisory", lambda: service)
    assert module.get_option("MODEL") is None
    assert module.op_analyze()["analysis"]["recommendations"]
    assert module.op_automate()["executed"] is False
    assert any(item["name"] == "Propose Workflow" for item in module.get_operations())
    framework.execute_request.assert_not_called()


def test_legacy_attack_paths_keep_manual_stages_without_unregistered_modules(framework):
    analyzer = AttackPathAnalyzer(framework)
    for name in ATTACK_PATH_TEMPLATES:
        path = analyzer.get_attack_path(name)
        for step in path.steps:
            assert step.module is None or step.module in framework.modules
            if step.module is None:
                assert not step.available and step.operation is None
            else:
                assert step.operation == "probe"
    step = analyzer.suggest_next_step({"http_service", "valid_credentials", "kerberos_service", "asrep_hashes"})
    assert step is None or step.module in framework.modules
    for path in analyzer.analyze(services=[{"service": "http"}, {"service": "smb"}]):
        assert all(step.module is None or step.module in framework.modules for step in path.steps)


@pytest.mark.parametrize("query", ["How do I escalate privileges?", "How do I move laterally?", "How do I harvest credentials?", "What should I do next?"])
def test_legacy_public_nlp_never_returns_unregistered_modules(framework, query):
    def check(value):
        if isinstance(value, list):
            for item in value:
                check(item)
        elif isinstance(value, dict):
            if value.get("module"):
                assert value["module"] in framework.modules
            if "modules" in value:
                assert set(value["modules"]) <= set(framework.modules)
            for item in value.values():
                check(item)

    check(NLPQueryHandler(framework).process_query(query, {"credentials": [{"username": "fixture"}]}))
