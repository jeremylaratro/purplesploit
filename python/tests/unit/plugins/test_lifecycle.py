"""Exercise local plugin capabilities through a real Framework, not a mock registry."""

import json
import shutil
import sys
from pathlib import Path

import pytest

from purplesploit.core.execution import ExecutionRequest
from purplesploit.core.framework import Framework
from purplesploit.plugins.models import PluginStatus
from purplesploit.plugins.repository import LocalPluginRepository


SAMPLE = Path(__file__).resolve().parents[4] / "examples/plugins/hello-demo"
MODULE = "plugin/hello-demo/hello"


@pytest.fixture
def framework(tmp_path):
    return Framework(
        modules_path=str(tmp_path / "modules"), db_path=str(tmp_path / "db.sqlite"),
        plugins_dir=tmp_path / "plugins", plugin_config_dir=tmp_path / "config",
    )


def test_local_plugin_installs_executes_disables_enables_uninstalls_and_restores(framework):
    manager = framework.plugin_manager
    plugin = manager.install_local(SAMPLE)
    assert plugin.status is PluginStatus.INSTALLED
    assert framework.get_module(MODULE)
    result = framework.execute_request(ExecutionRequest(module_path=MODULE, operation_name="greet"))
    assert result.success
    assert result.raw_result["message"] == "Hello from hello-demo"
    framework.use_module(MODULE)
    imported = manager._loaded[plugin.name][2]
    assert manager.disable(plugin.name)
    assert framework.get_module(MODULE) is None
    assert framework.session.current_module is None
    assert not any(key.startswith(imported) for key in sys.modules)
    assert not framework.execute_request(ExecutionRequest(module_path=MODULE)).success
    assert manager.enable(plugin.name)
    assert framework.get_module(MODULE)
    assert manager.uninstall(plugin.name)
    assert framework.get_module(MODULE) is None
    assert not Path(plugin.install_path).exists()
    assert manager.last_uninstall_path.joinpath("hello.py").exists()
    manager.install_local(manager.last_uninstall_path)
    assert framework.execute_request(ExecutionRequest(module_path=MODULE, operation_name="greet")).success


def test_startup_discovers_directories_and_preserves_disabled_state(tmp_path):
    directory = tmp_path / "plugins" / "hello-demo"
    shutil.copytree(SAMPLE, directory)
    kwargs = dict(db_path=str(tmp_path / "db.sqlite"), plugins_dir=directory.parent,
                  plugin_config_dir=tmp_path / "config")
    first = Framework(**kwargs)
    assert first.get_module(MODULE)
    first.plugin_manager.disable("hello-demo")
    second = Framework(**kwargs)
    assert second.get_module(MODULE) is None
    assert second.plugin_manager.list_installed()[0].enabled is False
    assert second.plugin_manager.enable("hello-demo")


def test_broken_plugin_is_reported_without_false_registration(framework):
    directory = framework.plugin_manager.plugins_dir / "hello-demo"
    shutil.copytree(SAMPLE, directory)
    (directory / "hello.py").write_text("raise RuntimeError('cannot import')\n")
    manager = framework.plugin_manager
    manager.discover_plugins()
    assert manager.load_plugin_modules() == []
    plugin = manager.list_installed()[0]
    assert plugin.status is PluginStatus.BROKEN
    assert "cannot import" in plugin.last_error
    assert framework.get_module(MODULE) is None


def test_failed_update_restores_running_installation(framework, tmp_path):
    manager = framework.plugin_manager
    manager.install_local(SAMPLE)
    replacement = tmp_path / "replacement"
    shutil.copytree(SAMPLE, replacement)
    (replacement / "hello.py").write_text("raise RuntimeError('broken update')\n")
    with pytest.raises(RuntimeError, match="broken update"):
        manager.install_local(replacement, force=True)
    assert framework.execute_request(ExecutionRequest(module_path=MODULE, operation_name="greet")).success
    assert "HelloModule" in (manager.plugins_dir / "hello-demo/hello.py").read_text()


def test_uninstall_state_failure_restores_files_and_registration(framework, monkeypatch):
    manager = framework.plugin_manager
    manager.install_local(SAMPLE)
    monkeypatch.setattr(manager, "_save_state", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        manager.uninstall("hello-demo")
    assert (manager.plugins_dir / "hello-demo/hello.py").exists()
    assert framework.execute_request(ExecutionRequest(module_path=MODULE, operation_name="greet")).success


def test_local_repository_returns_real_archive_and_install_registers(framework, tmp_path):
    repository_path = tmp_path / "repository"
    shutil.copytree(SAMPLE, repository_path / "plugins/hello-demo")
    repository = LocalPluginRepository(str(repository_path))
    plugin = repository.get_plugin("hello-demo")
    package = repository.download_plugin(plugin)
    assert package.is_file()
    assert package.name == "hello-demo-1.0.0.tar.gz"
    manager = framework.plugin_manager
    manager._repositories = {repository.name: repository}
    manager.install("hello-demo")
    assert framework.execute_request(ExecutionRequest(module_path=MODULE, operation_name="greet")).success


def test_src_layout_and_relative_imports(framework, tmp_path):
    source = tmp_path / "source"
    shutil.copytree(SAMPLE, source)
    (source / "src").mkdir()
    (source / "hello.py").rename(source / "src/hello.py")
    with (source / "src/hello.py").open("a") as output:
        output.write("\nfrom .helper import VALUE\nHelloModule.description = VALUE\n")
    (source / "src/helper.py").write_text("VALUE = 'relative import works'\n")
    framework.plugin_manager.install_local(source)
    assert framework.get_module(MODULE).description == "relative import works"


def test_uninstall_rejects_unrelated_directory(framework, tmp_path):
    plugin = framework.plugin_manager.install_local(SAMPLE)
    plugin.install_path = str(tmp_path)
    with pytest.raises(ValueError, match="does not match"):
        framework.plugin_manager.uninstall(plugin.name)
    assert framework.get_module(MODULE)


def test_invalid_entrypoint_does_not_publish_install(framework, tmp_path):
    source = tmp_path / "invalid"
    shutil.copytree(SAMPLE, source)
    manifest = json.loads((source / "plugin.json").read_text())
    manifest["main_class"] = "MissingClass"
    (source / "plugin.json").write_text(json.dumps(manifest))
    with pytest.raises(AttributeError):
        framework.plugin_manager.install_local(source)
    assert framework.get_module(MODULE) is None
    assert framework.plugin_manager.list_installed() == []
    assert not (framework.plugin_manager.plugins_dir / "hello-demo").exists()


def test_idempotent_loading_and_registry_collision_preserve_existing_module(framework):
    manager = framework.plugin_manager
    manager.install_local(SAMPLE)
    metadata = framework.get_module(MODULE)
    assert manager.load_plugin_modules() == [MODULE]
    assert framework.get_module(MODULE) is metadata
    manager.disable("hello-demo")
    # An unrelated owner has now occupied the path; enabling cannot overwrite it.
    framework.register_module(MODULE, metadata.instance)
    assert manager.enable("hello-demo") is False
    assert framework.get_module(MODULE).instance is metadata.instance
    assert manager.list_installed()[0].status is PluginStatus.BROKEN


def test_failed_install_state_write_rolls_back_files_and_registry(framework, monkeypatch):
    manager = framework.plugin_manager
    monkeypatch.setattr(manager, "_save_state", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        manager.install_local(SAMPLE)
    assert manager.list_installed() == []
    assert framework.get_module(MODULE) is None
    assert not (manager.plugins_dir / "hello-demo").exists()


def test_enable_disable_state_write_failure_restores_registry(framework, monkeypatch):
    manager = framework.plugin_manager
    plugin = manager.install_local(SAMPLE)
    save_state = manager._save_state
    monkeypatch.setattr(manager, "_save_state", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        manager.disable(plugin.name)
    assert plugin.enabled
    assert framework.get_module(MODULE)
    monkeypatch.setattr(manager, "_save_state", save_state)
    manager.disable(plugin.name)
    monkeypatch.setattr(manager, "_save_state", lambda: (_ for _ in ()).throw(OSError("disk full")))
    with pytest.raises(OSError, match="disk full"):
        manager.enable(plugin.name)
    assert not plugin.enabled
    assert framework.get_module(MODULE) is None
