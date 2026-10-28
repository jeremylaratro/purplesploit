"""Aranum service enumeration adapter and portable-bundle handoff."""

from functools import partial
import json
from pathlib import Path
import re
import shlex
from typing import Any

from purplesploit.core.module import ExternalToolModule
from purplesploit.interop.aranum import import_aranum_bundle


ARANUM_OWNED_BASELINES: tuple[str, ...] = (
    "smb",
    "ldap",
    "winrm",
    "rdp",
    "ssh",
    "mssql",
    "dns",
    "http",
)

# Aranum is enumeration-only unless an operator explicitly invokes it otherwise.
# PurpleSploit deliberately exposes no invasive Aranum switches through this adapter.
DEFAULT_ARGV: tuple[str, ...] = ()

_DISPATCHER_MANIFEST = Path(__file__).with_name("aranum_dispatchers.json")
_DISPATCHER_NAME = re.compile(r"^[a-z0-9][a-z0-9-]*$")


def _dispatcher_names() -> tuple[str, ...]:
    """Load published dispatchers, retaining a useful offline fallback."""
    try:
        document = json.loads(_DISPATCHER_MANIFEST.read_text(encoding="utf-8"))
        entries = document.get("dispatchers", [])
        names = tuple(
            dict.fromkeys(
                str(entry.get("name", "")).strip().lower()
                for entry in entries
                if isinstance(entry, dict)
                and _DISPATCHER_NAME.fullmatch(str(entry.get("name", "")).strip().lower())
            )
        )
        if names:
            return names
    except (OSError, UnicodeError, json.JSONDecodeError, AttributeError, TypeError, ValueError):
        pass
    return ARANUM_OWNED_BASELINES


class AranumModule(ExternalToolModule):
    """Run selected Aranum dispatchers and import the resulting bundle."""

    tool_name = "aranum"

    def __init__(self, framework):
        super().__init__(framework)
        # ExternalToolModule initializes these as instance attributes.
        self.tool_name = "aranum"
        # This adapter intentionally has no arbitrary-switch escape hatch: every
        # invocation remains on Aranum's enumeration-only selected-service path.
        self.options.pop("SWITCHES", None)

    @property
    def name(self) -> str:
        return "Aranum Enumeration"

    @property
    def description(self) -> str:
        return "Run one or more Aranum service enumerators and import their bundle"

    @property
    def author(self) -> str:
        return "PurpleSploit Team"

    @property
    def category(self) -> str:
        return "recon"

    def _init_options(self):
        super()._init_options()
        definitions = {
            "TARGET": (None, "Target host, network, or whitespace-separated targets"),
            "RHOST": (None, "Alias for TARGET"),
            "SERVICES": (None, "Comma/space-separated Aranum services"),
            "OUTPUT": (None, "Aranum bundle output root"),
            "OUTPUT_ROOT": (None, "Alias for OUTPUT"),
        }
        for key, (value, description) in definitions.items():
            self.options[key] = {
                "value": value,
                "default": value,
                "required": False,
                "description": description,
            }

    def get_operations(self) -> list[dict[str, Any]]:
        operations: list[dict[str, Any]] = [
            {
                "id": "run-selected-services",
                "name": "Run Selected Services",
                "description": "Coalesce selected service enumeration into one Aranum run",
                "handler": "op_run_selected_services",
                "subcategory": "coalesced",
                "background": False,
                "emits": ["host", "service", "finding"],
                "tool": "aranum",
            }
        ]
        operations.extend(
            {
                "id": f"enum-{dispatcher}",
                "name": f"Enumerate {dispatcher}",
                "description": f"Run the published Aranum {dispatcher} dispatcher",
                "handler": partial(self.op_enumerate_service, dispatcher),
                "service": dispatcher,
                "subcategory": "dispatcher",
                "background": False,
                "emits": ["host", "service", "finding"],
                "tool": "aranum",
            }
            for dispatcher in _dispatcher_names()
        )
        return operations

    @staticmethod
    def _split_values(value: Any) -> list[str]:
        if value in (None, ""):
            return []
        values = list(value) if isinstance(value, (list, tuple, set)) else shlex.split(str(value))
        result = []
        for item in values:
            result.extend(part for part in str(item).split(",") if part)
        return [item.strip() for item in result if item.strip()]

    def _targets(self) -> list[str]:
        value = self.get_option("TARGET") or self.get_option("RHOST")
        targets = self._split_values(value)
        if any(target.startswith("-") for target in targets):
            raise ValueError("Targets must not begin with '-'")
        return targets

    def _services(self, value: Any = None) -> tuple[str, ...]:
        configured = self.get_option("SERVICES") if value is None else value
        services = self._split_values(configured) or list(ARANUM_OWNED_BASELINES)
        normalized = tuple(dict.fromkeys(service.lower() for service in services))
        if any(not _DISPATCHER_NAME.fullmatch(service) for service in normalized):
            raise ValueError("SERVICES contains an invalid dispatcher name")
        return normalized

    def _output_root(self) -> Path:
        value = self.get_option("OUTPUT_ROOT") or self.get_option("OUTPUT")
        if value in (None, ""):
            request = self.execution_request or getattr(self, "_execution_context_request", None)
            value = getattr(request, "run_dir", None)
        if value in (None, ""):
            raise ValueError("OUTPUT or OUTPUT_ROOT is required")
        return Path(str(value)).expanduser()

    def validate_options(self) -> tuple[bool, str]:
        try:
            if not self._targets():
                return False, "TARGET or RHOST is required"
            self._services()
            self._output_root()
        except (OSError, TypeError, ValueError) as exc:
            return False, str(exc)
        return True, ""

    def build_argv(self, services: Any = None) -> list[str]:
        """Build the safe selected-service invocation without running it."""
        executable = self.tool_path or self.tool_name
        selected = ",".join(self._services(services))
        output_root = self._output_root()
        return [
            executable,
            *DEFAULT_ARGV,
            "--only",
            selected,
            "--service-parallel",
            "-o",
            str(output_root),
            *self._targets(),
        ]

    def build_command(self) -> str:
        return shlex.join(self.build_argv())

    @staticmethod
    def _locate_bundle(output_root: Path) -> Path:
        direct = output_root / "bundle-manifest.json"
        if direct.is_file():
            return output_root
        manifests = [path for path in output_root.rglob("bundle-manifest.json") if path.is_file()]
        if not manifests:
            raise FileNotFoundError(f"Aranum produced no bundle below {output_root}")
        manifests.sort(key=lambda path: (path.stat().st_mtime_ns, path.as_posix()))
        return manifests[-1].parent

    @staticmethod
    def _serialize(value: Any) -> Any:
        converter = getattr(value, "to_dict", None)
        return converter() if callable(converter) else value

    def _run_services(self, services: Any = None) -> dict[str, Any]:
        valid, error = self.validate_options()
        if not valid:
            return {"success": False, "error": error, "observations": [], "findings": []}
        if not self.tool_path and not self.check_tool_installed():
            return {
                "success": False,
                "error": f"Tool not found: {self.tool_name}. Please install it first.",
                "observations": [],
                "findings": [],
            }

        argv = self.build_argv(services)
        result = self.execute_command(argv)
        returncode = result.get("returncode")
        if returncode not in (0, 4):
            result.update(success=False, observations=[], findings=[])
            result.setdefault("error", f"Aranum exited with status {returncode}")
            return result

        # ExternalToolModule and the framework normally reserve success for rc=0.
        # Preserve Aranum's real status while normalizing its documented partial
        # report-chain status so the imported bundle follows the normal result path.
        if returncode == 4:
            result["aranum_returncode"] = 4
            result["returncode"] = 0
            execution = result.get("execution")
            if isinstance(execution, dict):
                execution.update(
                    exit_code=0,
                    aranum_returncode=4,
                    success=True,
                    outcome="success",
                    error=None,
                )
            if self.execution_records:
                self.execution_records[-1] = execution or self.execution_records[-1]

        try:
            bundle_root = self._locate_bundle(self._output_root())
            bundle = import_aranum_bundle(bundle_root)
        except (OSError, TypeError, ValueError) as exc:
            result.update(
                success=False,
                error=f"Unable to import Aranum bundle: {exc}",
                observations=[],
                findings=[],
            )
            return result

        result.update(
            success=True,
            bundle_root=str(bundle_root),
            bundle_status=bundle.status,
            observations=[self._serialize(item) for item in bundle.observations],
            findings=[self._serialize(item) for item in bundle.findings],
        )
        return result

    def op_run_selected_services(self) -> dict[str, Any]:
        return self._run_services()

    def op_enumerate_service(self, service: str) -> dict[str, Any]:
        return self._run_services((service,))

    def run(self) -> dict[str, Any]:
        return self.op_run_selected_services()
