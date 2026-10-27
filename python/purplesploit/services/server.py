"""Fail-closed production service entry point for PurpleSploit 7."""

from __future__ import annotations

import json
import os
from pathlib import Path

from purplesploit.ai import AdvisoryPolicy, provider_from_environment
from purplesploit.core.framework import Framework
from purplesploit.core.policy import PolicyEngine
from purplesploit.distributed.security import AgentMessageAuthenticator
from purplesploit.plugins.security import PluginTrustStore
from purplesploit.services.api import create_app
from purplesploit.services.application import PurpleSploitServices
from purplesploit.services.security import (
    ApplicationSecurity,
    SecurityAuditLog,
    SecurityConfig,
    TokenAuthority,
)


def _private_json(path: str | Path) -> dict:
    path = Path(path)
    if path.stat().st_mode & 0o077:
        raise PermissionError(f"Sensitive configuration must have mode 0600: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"Configuration must be a JSON object: {path}")
    return value


def _trust_store(directory: str | Path | None) -> PluginTrustStore:
    trust = PluginTrustStore()
    if directory:
        for path in sorted(Path(directory).glob("*.pem")):
            trust.add_pem(path.stem, path.read_bytes())
    return trust


def build_application(
    *,
    api_token: str | None = None,
    data_dir: str | Path | None = None,
    allowed_origins: tuple[str, ...] | None = None,
    agent_records: dict | None = None,
):
    """Build the supported service. No network listener is started here."""
    api_token = api_token or os.getenv("PURPLESPLOIT_API_TOKEN")
    if not api_token:
        raise RuntimeError("PURPLESPLOIT_API_TOKEN is required")
    if len(api_token) < 16:
        raise RuntimeError("PURPLESPLOIT_API_TOKEN must contain at least 16 characters")
    root = Path(data_dir or os.getenv("PURPLESPLOIT_DATA_DIR", ".data"))
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    root.chmod(0o700)

    trust_dir = os.getenv("PURPLESPLOIT_PLUGIN_TRUST_DIR")
    framework = Framework(
        db_path=str(root / "framework.db"),
        plugins_dir=root / "plugins",
        plugin_config_dir=root / "plugin-state",
        plugin_manager_kwargs={
            "strict_security": True,
            "trust_store": _trust_store(trust_dir),
        },
    )
    framework.discover_modules()
    if agent_records is None:
        config_path = os.getenv("PURPLESPLOIT_AGENT_CONFIG")
        agent_records = _private_json(config_path) if config_path else {}
    agent_auth = AgentMessageAuthenticator(agent_records)
    advisory_policy = AdvisoryPolicy(
        provider_consent=os.getenv("PURPLESPLOIT_AI_PROVIDER_CONSENT", "false").lower() == "true"
    )
    services = PurpleSploitServices(
        framework,
        root / "application",
        advisory_provider=provider_from_environment(),
        advisory_policy=advisory_policy,
        policy=PolicyEngine(),
        agent_authenticator=agent_auth,
    )
    origins = allowed_origins or tuple(
        item.strip()
        for item in os.getenv(
            "PURPLESPLOIT_ALLOWED_ORIGINS", "http://localhost,http://127.0.0.1"
        ).split(",")
        if item.strip()
    )
    security = ApplicationSecurity(
        SecurityConfig(allowed_origins=origins),
        TokenAuthority(api_token),
        audit=SecurityAuditLog(root / "application" / "security-audit.jsonl", services.redactor),
    )
    return create_app(services, security)


def main():
    import uvicorn

    host = os.getenv("PURPLESPLOIT_HOST", "127.0.0.1")
    port = int(os.getenv("PURPLESPLOIT_PORT", "5000"))
    uvicorn.run(build_application(), host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
