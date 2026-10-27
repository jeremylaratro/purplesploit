"""Application boundary for persisted integration configuration and finding sync."""

from copy import deepcopy

from .manager import IntegrationManager


class IntegrationService:
    def __init__(self, manager=None, findings=None, config_path=None, secret_provider=None):
        self.manager = manager if manager is not None else IntegrationManager(
            config_path=config_path, secret_provider=secret_provider
        )
        self.findings = findings

    def list_available(self):
        return self.manager.list_available()

    def list_configured(self):
        return self.manager.list_configured()

    def configure(self, name, config, integration_type=None):
        return self.manager.configure_integration(name, config, integration_type)

    def connect(self, name):
        return self.manager.connect(name)

    def disconnect(self, name):
        return self.manager.disconnect(name)

    def test_connection(self, name):
        return self.manager.test_connection(name)

    def status(self, name=None):
        return self.manager.get_status(name)

    def remove(self, name):
        return self.manager.remove_integration(name)

    def send_finding(self, finding_id, *, create_ticket=True, send_to_siem=True,
                     idempotency_key=None, expected_remote_ids=None):
        finding = self.findings.get(finding_id) if self.findings is not None else None
        if finding is None:
            return {"success": False, "error": f"Finding not found: {finding_id}"}
        return self.manager.send_finding(
            finding, create_ticket=create_ticket, send_to_siem=send_to_siem,
            idempotency_key=idempotency_key, expected_remote_ids=expected_remote_ids,
        )

    def deliveries(self, finding_id=None):
        return deepcopy(self.manager.list_deliveries(finding_id))

    def mappings(self):
        return deepcopy(self.manager.remote_ids)
