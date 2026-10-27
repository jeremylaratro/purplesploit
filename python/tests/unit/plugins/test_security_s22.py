"""S22 plugin trust-root, signature, and permission admission tests."""

import json
import shutil

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from purplesploit.plugins.manager import PluginManager
from purplesploit.plugins.security import PluginTrustStore, sign_directory
from purplesploit.core.execution import ExecutionRequest
from purplesploit.core.framework import Framework


def _signed_plugin(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    sample = tmp_path / "hello-demo"
    source = __import__("pathlib").Path(__file__).resolve().parents[4] / "examples/plugins/hello-demo"
    shutil.copytree(source, sample)
    private = Ed25519PrivateKey.generate()
    manifest_path = sample / "plugin.json"
    manifest = json.loads(manifest_path.read_text())
    manifest.update(signed=True, signing_key_id="fixture-publisher", permissions=[])
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    manifest["signature"] = sign_directory(sample, private)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    trust = PluginTrustStore()
    trust.add_pem(
        "fixture-publisher",
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )
    return sample, trust


def test_strict_plugin_requires_valid_independent_signature(tmp_path):
    source, trust = _signed_plugin(tmp_path)
    manager = PluginManager(
        tmp_path / "installed",
        tmp_path / "state",
        trust_store=trust,
        strict_security=True,
    )
    installed = manager.install_local(source)
    assert installed.manifest.signing_key_id == "fixture-publisher"
    assert installed.manifest.signature

    tampered, trust = _signed_plugin(tmp_path / "other")
    (tampered / "hello.py").write_text("raise RuntimeError('tampered')\n")
    manager = PluginManager(
        tmp_path / "installed-2",
        tmp_path / "state-2",
        trust_store=trust,
        strict_security=True,
    )
    with pytest.raises(PermissionError, match="signature"):
        manager.install_local(tampered)


def test_permissions_are_declared_and_checked_before_import(tmp_path):
    source, _ = _signed_plugin(tmp_path)
    with (source / "hello.py").open("a") as stream:
        stream.write("\nimport subprocess\n")
    manager = PluginManager(tmp_path / "installed", tmp_path / "state")
    with pytest.raises(PermissionError, match="subprocess"):
        manager.install_local(source)


def test_strict_mode_rejects_unsigned_and_host_dependency_install(tmp_path):
    source = __import__("pathlib").Path(__file__).resolve().parents[4] / "examples/plugins/hello-demo"
    manager = PluginManager(
        tmp_path / "installed", tmp_path / "state", strict_security=True
    )
    with pytest.raises(PermissionError, match="trusted signature"):
        manager.install_local(source)


def test_strict_plugin_executes_through_isolated_process_proxy(tmp_path):
    source, trust = _signed_plugin(tmp_path / "source")
    framework = Framework(
        db_path=str(tmp_path / "db.sqlite"),
        plugins_dir=tmp_path / "installed",
        plugin_config_dir=tmp_path / "state",
        plugin_manager_kwargs={"strict_security": True, "trust_store": trust},
    )
    plugin = framework.plugin_manager.install_local(source)
    metadata = framework.get_module("plugin/hello-demo/hello")
    assert metadata.instance.isolated_plugin is True
    result = framework.execute_request(ExecutionRequest(
        module_path="plugin/hello-demo/hello", operation_name="greet"
    ))
    assert result.success
    assert result.raw_result["message"] == "Hello from hello-demo"
    assert plugin.status.value == "installed"
