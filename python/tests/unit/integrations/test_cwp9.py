"""Offline capability checks at adapter boundaries, including restart behavior."""

import json
from unittest.mock import Mock

import pytest

from purplesploit.core.findings import Finding
from purplesploit.integrations.base import IntegrationStatus
from purplesploit.integrations.manager import IntegrationManager, INTEGRATION_REGISTRY
from purplesploit.integrations.service import IntegrationService
from purplesploit.core.secrets import EncryptedFileSecretProvider


def response(status=201, **body):
    return Mock(status_code=status, json=Mock(return_value=body), text="fixture")


@pytest.mark.parametrize("kind,config", [
    ("jira", {"server_url": "https://jira.invalid", "project_key": "LAB", "api_key": "jira-key"}),
    ("github", {"owner": "lab", "repo": "findings", "api_key": "github-key"}),
    ("slack", {"bot_token": "bot-key"}),
    ("teams", {"webhook_url": "https://teams.invalid"}),
    ("siem_webhook", {"webhook_url": "https://siem.invalid", "custom_headers": {"X-Key": "test"}}),
    ("splunk", {"hec_token": "hec-key", "hec_url": "https://splunk.invalid"}),
    ("elasticsearch", {"api_url": "https://elastic.invalid", "api_key_id": "id", "api_key_secret": "secret"}),
])
def test_all_adapters_round_trip_without_connecting(tmp_path, kind, config):
    path = tmp_path / "integrations.json"
    manager = IntegrationManager(config_path=path)
    manager.config.batch_interval = 42
    assert manager.configure_integration("lab", {"name": "old", **config}, kind)["success"]
    restored = IntegrationManager(config_path=path)
    assert type(restored.integrations["lab"]) is INTEGRATION_REGISTRY[kind]["class"]
    assert vars(restored.integrations["lab"].config) == vars(manager.integrations["lab"].config)
    assert restored.config.batch_interval == 42
    assert restored.list_configured()[0]["type"] == kind
    assert restored.get_status("lab")["status"] == "disconnected"
    assert path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize("kind,config,remote_key,remote_id,create_suffix,update_suffix", [
    ("jira", {"server_url": "https://jira.invalid", "project_key": "LAB"}, "key", "LAB-9", "/issue", "/issue/LAB-9/comment"),
    ("github", {"owner": "lab", "repo": "findings"}, "number", 9, "/issues", "/issues/9/comments"),
])
def test_canonical_finding_sync_reuses_remote_ticket_after_restart(tmp_path, monkeypatch, kind, config, remote_key, remote_id, create_suffix, update_suffix):
    import requests
    calls = []

    def post(url, **kwargs):
        calls.append((url, kwargs))
        return response(**{remote_key: remote_id, "html_url": "https://ticket.invalid/9"})

    monkeypatch.setattr(requests, "post", post)
    path = tmp_path / "integrations.json"
    manager = IntegrationManager(config_path=path)
    manager.configure_integration(kind, config)
    manager.config.ticketing_channels = [kind]
    manager.config.notification_channels = []
    manager.integrations[kind].status = IntegrationStatus.CONNECTED
    finding = Finding(id="F-9", title="Fixture finding", severity="high", target="192.0.2.1")
    store = Mock(get=Mock(return_value=finding))
    result = IntegrationService(manager, store).send_finding(finding.id, send_to_siem=False)
    assert result["success"]
    assert calls[-1][0].endswith(create_suffix)
    manager = IntegrationManager(config_path=path)
    manager.integrations[kind].status = IntegrationStatus.CONNECTED
    assert manager.send_finding(finding, create_ticket=True, send_to_siem=False)["success"]
    assert calls[-1][0].endswith(update_suffix)
    assert manager.remote_ids[kind][finding.id] == remote_id
    restored = IntegrationService(IntegrationManager(config_path=path), store)
    assert len(restored.deliveries(finding.id)) == 2
    assert restored.mappings()[kind][finding.id] == remote_id


@pytest.mark.parametrize("kind,config,status,body", [
    ("slack", {"webhook_url": "https://slack.invalid"}, 200, {}),
    ("teams", {"webhook_url": "https://teams.invalid"}, 200, {}),
    ("siem_webhook", {"webhook_url": "https://siem.invalid"}, 202, {}),
    ("splunk", {"hec_url": "https://splunk.invalid", "hec_token": "test"}, 200, {"code": 0}),
    ("elasticsearch", {"api_url": "https://elastic.invalid"}, 201, {"_id": "event-1"}),
])
def test_notification_and_siem_adapters_record_delivery(tmp_path, monkeypatch, kind, config, status, body):
    import requests
    post = Mock(return_value=response(status, **body))
    monkeypatch.setattr(requests, "post", post)
    manager = IntegrationManager(config_path=tmp_path / "integrations.json")
    manager.configure_integration(kind, config)
    manager.integrations[kind].status = IntegrationStatus.CONNECTED
    manager.config.notification_channels = [kind]
    result = manager.send_finding(Finding(title="Test", severity="critical"), send_to_siem=False)
    assert result["notifications"][kind]["success"]
    assert post.call_count == 1
    assert len(manager.list_deliveries()) == 1


def test_failures_disabled_and_missing_channels_are_observable(tmp_path):
    manager = IntegrationManager(config_path=tmp_path / "integrations.json")
    manager.config.ticketing_channels = ["absent"]
    result = manager.send_finding(Finding(id="F-1"), create_ticket=True, send_to_siem=False)
    assert not result["success"]
    assert result["tickets"]["absent"]["error"] == "Not configured"
    assert manager.list_deliveries("F-1")[0]["result"]["success"] is False
    manager.config.enabled = False
    assert not manager.send_finding(Finding())["success"]


def test_legacy_config_and_failure_status(tmp_path):
    path = tmp_path / "integrations.json"
    path.write_text(json.dumps({"integrations": {"slack": {"name": "slack", "bot_token": "key"}}}))
    manager = IntegrationManager(config_path=path)
    manager.integrations["slack"].connect = Mock(return_value=False)
    assert manager.connect("slack")["status"] == "error"
    manager.integrations["slack"].connect = Mock(return_value=True)
    assert manager.connect("slack")["status"] == "connected"
    assert manager.get_status("slack")["error"] is None


def test_slack_bot_thread_mapping_remains_stable_across_restart(tmp_path, monkeypatch):
    import requests
    post = Mock(side_effect=[response(200, ok=True, ts="100.1"), response(200, ok=True, ts="100.2")])
    monkeypatch.setattr(requests, "post", post)
    path = tmp_path / "integrations.json"
    manager = IntegrationManager(config_path=path)
    manager.configure_integration("slack", {"bot_token": "test"})
    manager.config.notification_channels = ["slack"]
    manager.integrations["slack"].status = IntegrationStatus.CONNECTED
    finding = Finding(id="F-1", title="Test", severity="critical")
    manager.send_finding(finding, send_to_siem=False)
    restored = IntegrationManager(config_path=path)
    restored.integrations["slack"].status = IntegrationStatus.CONNECTED
    restored.send_finding(finding, send_to_siem=False)
    assert post.call_args.kwargs["json"]["thread_ts"] == "100.1"
    assert restored.remote_ids["slack"][finding.id] == "100.1"


def test_config_changes_do_not_reuse_previous_destination_ids(tmp_path):
    manager = IntegrationManager(config_path=tmp_path / "integrations.json")
    manager.configure_integration("github", {"owner": "lab", "repo": "first"})
    manager.remote_ids["github"] = {"F-1": 1}
    manager.configure_integration("github", {"owner": "lab", "repo": "second"})
    assert "github" not in manager.remote_ids


def test_configuration_persistence_error_is_reported(tmp_path, monkeypatch):
    manager = IntegrationManager(config_path=tmp_path / "integrations.json")
    monkeypatch.setattr(manager, "_save_config", lambda: False)
    result = manager.configure_integration("slack", {"bot_token": "test"})
    assert not result["success"]
    assert "persist" in result["error"]


def test_secret_provider_keeps_integration_values_out_of_normal_config(tmp_path):
    provider = EncryptedFileSecretProvider(tmp_path / "secrets.vault")
    path = tmp_path / "integrations.json"
    manager = IntegrationManager(config_path=path, secret_provider=provider)
    assert manager.configure_integration(
        "lab", {"bot_token": "sensitive-bot-token"}, "slack"
    )["success"]
    persisted = path.read_text()
    assert "sensitive-bot-token" not in persisted
    assert "secret://local/" in persisted
    restored = IntegrationManager(config_path=path, secret_provider=provider)
    assert restored.integrations["lab"].config.bot_token == "sensitive-bot-token"


def test_idempotency_retry_and_mapping_conflict_controls(tmp_path):
    delays = []
    manager = IntegrationManager(
        config_path=tmp_path / "integrations.json", sleeper=delays.append
    )
    manager.configure_integration("slack", {"bot_token": "fixture"})
    manager.config.notification_channels = ["slack"]
    integration = manager.integrations["slack"]
    integration.status = IntegrationStatus.CONNECTED
    integration.send_notification = Mock(side_effect=[
        {"success": False, "status_code": 503, "error": "temporary"},
        {"success": True, "ts": "remote-1"},
    ])
    finding = Finding(id="F-idempotent", title="Test", severity="critical")
    first = manager.send_finding(
        finding, send_to_siem=False, idempotency_key="delivery-1"
    )["notifications"]["slack"]
    assert first["success"] and first["attempts"] == 2
    assert delays == [manager.config.retry_base_delay]
    second = manager.send_finding(
        finding, send_to_siem=False, idempotency_key="delivery-1"
    )["notifications"]["slack"]
    assert second["duplicate"] and integration.send_notification.call_count == 2

    conflict = manager.send_finding(
        finding,
        send_to_siem=False,
        expected_remote_ids={"slack": "stale-remote"},
    )["notifications"]["slack"]
    assert conflict["conflict"] and not conflict["success"]
    assert integration.send_notification.call_count == 2
