"""Isolated-process runtime for strictly admitted plugins.

The host sends one JSON request on stdin and receives one JSON result on stdout.
No host framework, database, secret provider, or environment is exposed.
"""

from __future__ import annotations

import contextlib
import importlib
import io
import json
from pathlib import Path
import sys
import types
import uuid


class _Database:
    @staticmethod
    def get_module_defaults(_name):
        return {}


class _Framework:
    database = _Database()

    @staticmethod
    def log(_message, _level="info"):
        return None


def _load(request):
    # The runner is trusted package code; the plugin root is the only added import root.
    package_root = str(Path(__file__).resolve().parents[2])
    if package_root not in sys.path:
        sys.path.insert(0, package_root)
    from purplesploit.core.module import BaseModule

    directory = Path(request["directory"]).resolve()
    source = directory / "src" if (directory / "src").is_dir() else directory
    namespace = f"_purplesploit_isolated_{uuid.uuid4().hex}"
    package = types.ModuleType(namespace)
    package.__path__ = [str(source)]
    package.__package__ = namespace
    sys.modules[namespace] = package
    module = importlib.import_module(f"{namespace}.{request['module_path']}")
    cls = getattr(module, request["main_class"])
    if not isinstance(cls, type) or not issubclass(cls, BaseModule) or cls is BaseModule:
        raise TypeError("main_class must be a BaseModule subclass")
    return cls(_Framework())


def _result(request):
    plugin = _load(request)
    if request["action"] == "inspect":
        operations = []
        for operation in plugin.get_operation_manifest():
            operations.append({key: value for key, value in operation.items() if key != "handler"})
        return {
            "name": plugin.name,
            "description": plugin.description,
            "author": plugin.author,
            "category": plugin.category,
            "options": plugin.options,
            "operations": operations,
        }
    for key, value in request.get("options", {}).items():
        if not plugin.set_option(key, value):
            raise ValueError(f"Unknown plugin option: {key}")
    operation_id = request.get("operation")
    if not operation_id:
        return plugin.run()
    selected = next(
        (item for item in plugin.get_operation_manifest() if item["id"] == operation_id), None
    )
    if selected is None:
        raise ValueError(f"Unknown plugin operation: {operation_id}")
    handler = selected["handler"]
    method = getattr(plugin, handler) if isinstance(handler, str) else handler
    return method()


def main():
    captured = io.StringIO()
    try:
        request = json.loads(sys.stdin.read())
        with contextlib.redirect_stdout(captured), contextlib.redirect_stderr(captured):
            value = _result(request)
        response = {"success": True, "result": value, "plugin_output": captured.getvalue()}
    except Exception as exc:
        response = {"success": False, "error": f"{type(exc).__name__}: {exc}",
                    "plugin_output": captured.getvalue()}
    sys.stdout.write(json.dumps(response, default=str))


if __name__ == "__main__":
    main()
