"""Redacted, deterministic support bundle generation."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import tempfile
import zipfile

from purplesploit import __version__


def create_support_bundle(services, output_path: str | Path) -> dict:
    """Create diagnostics without databases, evidence, secrets, targets, or findings."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    verification = services.store.verify()
    document = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "purplesploit_version": __version__,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "canonical_store": verification,
        "policy_enforced": services.policy.enforce,
        "agent_authentication": services.coordinator.authenticator is not None,
        "module_count": len(services.framework.modules),
        "job_summary": {
            "total": len(services.jobs.list()),
            "by_status": {
                status: sum(1 for job in services.jobs.list() if job["status"] == status)
                for status in sorted({job["status"] for job in services.jobs.list()})
            },
        },
    }
    descriptor, temporary_name = tempfile.mkstemp(
        dir=output_path.parent, prefix=f".{output_path.name}.", suffix=".tmp"
    )
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.chmod(0o600)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(
                "diagnostics.json",
                json.dumps(document, indent=2, sort_keys=True) + "\n",
            )
            archive.writestr(
                "README.txt",
                "Redacted diagnostics only. Databases, evidence, credentials, targets, "
                "findings, configuration values, and logs are intentionally excluded.\n",
            )
        os.replace(temporary, output_path)
        output_path.chmod(0o600)
    finally:
        temporary.unlink(missing_ok=True)
    return {
        "path": str(output_path),
        "size": output_path.stat().st_size,
        "redacted": True,
    }
