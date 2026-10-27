from pathlib import Path
import subprocess

import pytest

from purplesploit.core.remote import SecureSSHRunner


def runner(tmp_path, responses=None):
    known = tmp_path / "known_hosts"
    known.write_text("fixture ssh-ed25519 AAAAC3NzaFixture\n")
    known.chmod(0o600)
    key = tmp_path / "id_ed25519"
    key.write_text("fixture-private-key")
    key.chmod(0o600)
    calls = []
    responses = iter(responses or [subprocess.CompletedProcess([], 0, "ok", "")])

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return next(responses)

    return SecureSSHRunner(
        "192.0.2.10", "operator", known_hosts=known,
        identity_file=key, executor=execute,
    ), calls


def test_upload_and_execution_verify_host_and_never_expose_password(tmp_path):
    local = tmp_path / "payload with spaces"
    local.write_text("fixture")
    remote, calls = runner(tmp_path, [
        subprocess.CompletedProcess([], 0, "uploaded", ""),
        subprocess.CompletedProcess([], 0, "chmod", ""),
        subprocess.CompletedProcess([], 0, "executed", ""),
    ])
    result = remote.deploy(
        local, "/tmp/payload", arguments=["argument with spaces", "; touch /tmp/no"],
    )
    assert result["success"] and result["output"] == "executed"
    flattened = "\n".join(" ".join(argv) for argv, _ in calls)
    assert "StrictHostKeyChecking=yes" in flattened
    assert "PasswordAuthentication=no" in flattened
    assert "sshpass" not in flattened and "fixture-private-key" not in flattened
    command = calls[-1][0][-1]
    assert "argument with spaces" in command and "'; touch /tmp/no'" in command
    assert all(kwargs["check"] is False for _, kwargs in calls)


def test_nonzero_result_is_authoritative_and_failed_execution_cleans_up(tmp_path):
    local = tmp_path / "payload"
    local.write_text("fixture")
    remote, calls = runner(tmp_path, [
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 0, "", ""),
        subprocess.CompletedProcess([], 9, "", "denied"),
        subprocess.CompletedProcess([], 0, "", ""),
    ])
    result = remote.deploy(local, "/tmp/payload")
    assert not result["success"] and result["execution"]["exit_code"] == 9
    assert result["cleanup"]["success"]
    assert "rm -f -- /tmp/payload" in calls[-1][0][-1]


def test_rejects_missing_or_unsafe_trust_material_and_paths(tmp_path):
    with pytest.raises(FileNotFoundError, match="known_hosts"):
        SecureSSHRunner("host", "user", known_hosts=tmp_path / "absent")
    known = tmp_path / "known_hosts"
    known.write_text("fixture")
    known.chmod(0o666)
    with pytest.raises(PermissionError, match="known_hosts"):
        SecureSSHRunner("host", "user", known_hosts=known)
    known.chmod(0o600)
    remote = SecureSSHRunner("host", "user", known_hosts=known)
    with pytest.raises(ValueError, match="absolute"):
        remote.upload(__file__, "relative/path")
