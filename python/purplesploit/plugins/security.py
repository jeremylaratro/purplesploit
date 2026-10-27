"""Cryptographic admission and permission policy for third-party plugins."""

from __future__ import annotations

import ast
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Iterable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


KNOWN_PERMISSIONS = frozenset(
    {
        "network",
        "filesystem_read",
        "filesystem_write",
        "subprocess",
        "secrets",
        "native_code",
        "dynamic_code",
    }
)

_IMPORT_PERMISSIONS = {
    "socket": "network",
    "http": "network",
    "urllib": "network",
    "requests": "network",
    "aiohttp": "network",
    "subprocess": "subprocess",
    "multiprocessing": "subprocess",
    "pty": "subprocess",
    "os": "filesystem_read",
    "pathlib": "filesystem_read",
    "shutil": "filesystem_write",
    "tempfile": "filesystem_write",
    "keyring": "secrets",
    "ctypes": "native_code",
    "cffi": "native_code",
    "importlib": "dynamic_code",
}


def _manifest_path(directory: Path) -> Path:
    for name in ("plugin.json", "plugin.yaml"):
        path = directory / name
        if path.is_file():
            return path
    raise ValueError("Plugin manifest is missing")


def _manifest_data(path: Path) -> dict:
    if path.suffix == ".json":
        return json.loads(path.read_text(encoding="utf-8"))
    import yaml

    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Plugin manifest must be an object")
    return value


def signed_payload(directory: str | Path) -> bytes:
    """Return a stable payload covering security-relevant metadata and every source file."""
    root = Path(directory).resolve()
    manifest_path = _manifest_path(root)
    manifest = _manifest_data(manifest_path)
    for key in ("signature", "signed", "trusted_author"):
        manifest.pop(key, None)
    files = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Plugin contains a symbolic link: {path.relative_to(root)}")
        if not path.is_file() or path == manifest_path or path.name == "plugin.sig":
            continue
        relative = path.relative_to(root).as_posix()
        files[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return json.dumps(
        {"manifest": manifest, "files": files},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


class PluginTrustStore:
    """Independent, public-key-only plugin trust root."""

    def __init__(self, keys: dict[str, Ed25519PublicKey] | None = None):
        self._keys = dict(keys or {})

    def add_pem(self, key_id: str, public_key_pem: bytes) -> None:
        key = serialization.load_pem_public_key(public_key_pem)
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError("Plugin trust roots must be Ed25519 public keys")
        self._keys[key_id] = key

    def verify(self, directory: str | Path, *, key_id: str, signature: str) -> None:
        key = self._keys.get(key_id)
        if key is None:
            raise PermissionError(f"Unknown plugin signing key: {key_id}")
        try:
            decoded = base64.b64decode(signature, validate=True)
            key.verify(decoded, signed_payload(directory))
        except Exception as exc:
            raise PermissionError("Plugin signature verification failed") from exc


def sign_directory(directory: str | Path, key: Ed25519PrivateKey) -> str:
    """Test/release helper. Private keys never enter the trust store."""
    return base64.b64encode(key.sign(signed_payload(directory))).decode("ascii")


def isolated_call(directory, manifest, action, *, options=None, operation=None, timeout=60):
    """Run admitted plugin code outside the host process with a minimal environment."""
    runner = Path(__file__).with_name("runner.py")
    request = {
        "directory": str(Path(directory).resolve()),
        "module_path": manifest.module_path.removesuffix(".py").replace("/", "."),
        "main_class": manifest.main_class,
        "permissions": list(manifest.permissions),
        "action": action,
        "options": options or {},
        "operation": operation,
    }
    completed = subprocess.run(
        [sys.executable, "-I", str(runner)],
        input=json.dumps(request),
        text=True,
        capture_output=True,
        timeout=min(max(float(timeout), 1), 3600),
        cwd=str(Path(directory).resolve()),
        env={"PATH": os.environ.get("PATH", ""), "LANG": "C.UTF-8"},
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Plugin runner exited {completed.returncode}: {completed.stderr}")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("Plugin runner returned malformed output") from exc
    if not response.get("success"):
        raise RuntimeError(response.get("error", "Plugin runner failed"))
    return response


def isolated_plugin_class(directory, manifest):
    """Build a host-safe proxy whose implementation always runs in the runner process."""
    from copy import deepcopy
    from purplesploit.core.module import BaseModule

    metadata = isolated_call(directory, manifest, "inspect")["result"]

    def _init_options(self):
        self.options = deepcopy(metadata["options"])

    def get_operations(self):
        return [
            {**deepcopy(item), "handler": "_execute_isolated_operation"}
            for item in metadata["operations"]
        ]

    def _invoke(self, operation):
        timeout = getattr(getattr(self, "execution_request", None), "timeout_s", None) or 60
        response = isolated_call(
            directory,
            manifest,
            "execute",
            options={key: self.get_option(key) for key in self.options},
            operation=operation,
            timeout=timeout,
        )
        result = response["result"]
        if not isinstance(result, dict):
            result = {"success": True, "output": str(result)}
        if response.get("plugin_output"):
            result.setdefault("plugin_output", response["plugin_output"])
        return result

    def run(self):
        return _invoke(self, None)

    def execute_operation(self):
        request = getattr(self, "execution_request", None)
        return _invoke(self, getattr(request, "operation_name", None))

    attributes = {
        "name": metadata["name"],
        "description": metadata["description"],
        "author": metadata["author"],
        "category": metadata["category"],
        "_init_options": _init_options,
        "get_operations": get_operations,
        "_execute_isolated_operation": execute_operation,
        "run": run,
        "isolated_plugin": True,
    }
    return type(f"Isolated_{manifest.name.replace('-', '_')}", (BaseModule,), attributes)


class PluginPermissionPolicy:
    """Reject undeclared high-impact imports before trusted code enters the host."""

    def validate(self, directory: str | Path, permissions: Iterable[str]) -> None:
        declared = set(permissions)
        unknown = declared - KNOWN_PERMISSIONS
        if unknown:
            raise PermissionError(f"Unknown plugin permissions: {', '.join(sorted(unknown))}")
        root = Path(directory).resolve()
        for path in root.rglob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    required = _IMPORT_PERMISSIONS.get(name.split(".", 1)[0])
                    if required and required not in declared:
                        raise PermissionError(
                            f"{path.name} imports {name}, which requires '{required}' permission"
                        )
