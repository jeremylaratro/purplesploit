"""Shared hardened SSH deployment boundary for legacy deployment modules."""

from __future__ import annotations

import os
from pathlib import Path
import shlex

from purplesploit.core.remote import SecureSSHRunner


def deploy_over_ssh(
    module,
    *,
    host,
    username,
    local_file,
    remote_path,
    arguments=None,
    execute=True,
    background=False,
    timeout=120,
):
    """Deploy with key/agent authentication and a verified host-key database."""
    identity = module.get_option("SSH_KEY") if "SSH_KEY" in module.options else None
    password = module.get_option("PASSWORD") if "PASSWORD" in module.options else None
    if password and not identity:
        return {
            "success": False,
            "error": "Password SSH is disabled because it exposes secrets to helper processes; use SSH_KEY or an SSH agent",
        }
    known_hosts = os.getenv(
        "PURPLESPLOIT_KNOWN_HOSTS", str(Path.home() / ".ssh" / "known_hosts")
    )
    try:
        runner = SecureSSHRunner(
            str(host), str(username), known_hosts=known_hosts,
            identity_file=identity or None,
        )
        return runner.deploy(
            local_file,
            remote_path,
            arguments=list(arguments or []),
            execute=bool(execute),
            background=background,
            timeout=timeout,
        )
    except (OSError, TypeError, ValueError) as exc:
        return {"success": False, "error": f"Secure SSH deployment rejected: {exc}"}


def split_arguments(value):
    try:
        return shlex.split(value or "")
    except ValueError as exc:
        raise ValueError(f"Invalid execution arguments: {exc}") from exc
