"""Serializable technical execution and observation contracts.

These records describe what ran and what it observed; they do not implement
engagement authorization or an execution policy.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import ast
import inspect
import json
import re
import textwrap
from typing import Any, Literal
from uuid import NAMESPACE_URL, uuid4, uuid5


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ExecutionOutcome(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    RUNNING = "running"
    REJECTED = "rejected"
    ERROR = "error"


@dataclass
class ExecutionRequest:
    module_path: str
    operation_name: str | None = None
    options: dict[str, Any] = field(default_factory=dict)
    options_locked: set[str] = field(default_factory=set)
    argv: list[str] = field(default_factory=list)
    cwd: str | None = None
    run_dir: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    timeout_s: float | None = None
    background: bool = False
    stdin: Literal["none", "inherit"] = "none"
    engagement_id: str | None = None
    job_id: str | None = None
    correlation_id: str = field(default_factory=lambda: str(uuid4()))
    request_id: str = field(default_factory=lambda: str(uuid4()))
    targets: list[str] = field(default_factory=list)
    resolved_targets: list[str] = field(default_factory=list)
    redirect_chain: list[str] = field(default_factory=list)
    proxy: str | None = None
    action_risk: str | None = None
    side_effects: list[str] = field(default_factory=list)
    approval_id: str | None = None
    explain_only: bool = False

    def __post_init__(self):
        self.options = {str(key).upper(): value for key, value in self.options.items()}
        self.options_locked = {str(key).upper() for key in self.options_locked}
        if self.stdin not in {"none", "inherit"}:
            raise ValueError("stdin must be 'none' or 'inherit'")
        if self.timeout_s is not None and self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        for name in ("targets", "resolved_targets", "redirect_chain", "side_effects"):
            value = getattr(self, name)
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                raise ValueError(f"{name} must be a list of strings")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["options_locked"] = sorted(self.options_locked)
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExecutionRequest":
        return cls(**value)


ObservationKind = Literal[
    "host", "service", "http_endpoint", "http_request", "form", "parameter",
    "technology", "path", "user", "group", "computer", "domain", "session",
    "share", "credential", "identity", "role", "policy", "resource", "finding", "note",
]


@dataclass
class Observation:
    kind: ObservationKind
    target: str
    port: int | None = None
    protocol: str | None = None
    service: str | None = None
    version: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    source_execution_id: str = ""
    module_path: str = ""
    operation_name: str | None = None
    observed_at: str = field(default_factory=utc_now)
    confidence: Literal["observed", "inferred"] = "observed"
    engagement_id: str | None = None
    observation_id: str = ""

    def __post_init__(self):
        if not self.observation_id:
            identity = [self.source_execution_id, self.kind, self.target, self.port,
                        self.protocol, self.service, self.attributes]
            self.observation_id = str(uuid5(NAMESPACE_URL, json.dumps(identity, sort_keys=True)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Observation":
        return cls(**value)


@dataclass
class ExecutionResult:
    request_id: str
    outcome: ExecutionOutcome = ExecutionOutcome.FAILED
    success: bool = False
    module_path: str = ""
    operation_name: str | None = None
    correlation_id: str | None = None
    engagement_id: str | None = None
    job_id: str | None = None
    argv_display: list[str] = field(default_factory=list)
    exit_code: int | None = None
    timed_out: bool = False
    cancelled: bool = False
    started_at: str = field(default_factory=utc_now)
    finished_at: str | None = None
    stdout_ref: str | None = None
    stderr_ref: str | None = None
    tool: str | None = None
    tool_version: str | None = None
    pid: int | None = None
    observations: list[Observation] = field(default_factory=list)
    artifacts: list[str] = field(default_factory=list)
    error: str | None = None
    raw_result: dict[str, Any] = field(default_factory=dict)

    @property
    def handle(self):
        """Runtime-only process handle; deliberately absent from serialization."""
        return getattr(self, '_handle', None)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["outcome"] = self.outcome.value
        return result

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExecutionResult":
        data = dict(value)
        data["outcome"] = ExecutionOutcome(data.get("outcome", "failed"))
        data["observations"] = [Observation.from_dict(item) for item in data.get("observations", [])]
        return cls(**data)


class ExecutionHandle:
    """A launched process remains pending until poll/wait observes its exit."""

    def __init__(self, process, result: ExecutionResult):
        self.process = process
        self.result = result

    def _complete(self, exit_code):
        if exit_code is not None:
            self.result.exit_code = exit_code
            self.result.finished_at = utc_now()
            self.result.success = exit_code == 0 and not self.result.cancelled
            self.result.outcome = (
                ExecutionOutcome.CANCELLED if self.result.cancelled else
                ExecutionOutcome.SUCCESS if self.result.success else ExecutionOutcome.FAILED
            )
        return self.result

    def status(self) -> ExecutionResult:
        return self._complete(self.process.poll())

    def wait(self, timeout: float | None = None) -> ExecutionResult:
        return self._complete(self.process.wait(timeout=timeout))

    def cancel(self) -> ExecutionResult:
        if self.process.poll() is None:
            self.process.terminate()
            self.result.cancelled = True
        return self.status()


def normalize_operation(operation: dict[str, Any], module=None) -> dict[str, Any]:
    """Add catalog fields to an existing operation without changing its handler."""
    result = dict(operation)
    handler = result.get("handler")
    handler_name = handler if isinstance(handler, str) else getattr(handler, "__name__", "")
    stable_name = handler_name.removeprefix("op_") or str(result.get("name", ""))
    result.setdefault("id", re.sub(r"[^a-z0-9]+", "-", stable_name.lower()).strip("-"))
    result.setdefault("name", result["id"])
    result.setdefault("handler", handler)
    result.setdefault("description", "")
    interactive = False
    method = getattr(module, handler_name, None) if module is not None else handler
    if callable(method):
        try:
            tree = ast.parse(textwrap.dedent(inspect.getsource(method)))
            interactive = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == 'input' for node in ast.walk(tree))
        except (OSError, TypeError, SyntaxError):
            pass
    result.setdefault("interactive", interactive)
    result.setdefault("background", False)
    required = [key for key, option in getattr(module, "options", {}).items() if option.get("required")]
    result.setdefault("requires", required)
    result.setdefault("optional", [key for key in getattr(module, "options", {}) if key not in result["requires"]])
    for key in ("emits", "supported_tool_versions", "standards"):
        result.setdefault(key, [])
    result.setdefault("tool", getattr(module, "tool_name", None))
    result.setdefault("subcategory", "")
    return result


def normalize_observations(result: dict[str, Any], request: ExecutionRequest) -> list[Observation]:
    """Bridge current parser keys to observations, preserving original payloads.

    Prefer first-class observations. Only structured legacy records are adapted;
    stdout and summary counts are never interpreted as observations.
    """
    target = str(request.options.get("RHOST") or request.options.get("TARGET") or request.options.get("URL") or "")
    observations = []

    def add(kind, value, default_target=target):
        if isinstance(value, Observation):
            data = value.to_dict()
        elif isinstance(value, dict):
            data = dict(value)
        elif isinstance(value, str):
            data = {"attributes": {"value": value}}
        else:
            return
        fields = Observation.__dataclass_fields__
        attributes = dict(data.get("attributes") or {})
        attributes.update({key: item for key, item in data.items() if key not in fields})
        normalized = {key: item for key, item in data.items() if key in fields}
        normalized.update(kind=data.get("kind", kind), target=str(data.get("target") or data.get("host") or data.get("ip") or data.get("url") or default_target), attributes=attributes)
        normalized.setdefault("source_execution_id", request.request_id)
        normalized.setdefault("module_path", request.module_path)
        normalized.setdefault("operation_name", request.operation_name)
        normalized.setdefault("engagement_id", request.engagement_id)
        if not normalized["source_execution_id"]:
            normalized["source_execution_id"] = request.request_id
        if not normalized["module_path"]:
            normalized["module_path"] = request.module_path
        observations.append(Observation(**normalized))

    explicit = result.get("observations")
    if isinstance(explicit, list):
        for item in explicit:
            add("note", item)
    else:
        containers = [result]
        for key in ("parsed", "parsed_results", "data"):
            if isinstance(result.get(key), dict):
                containers.append(result[key])
        keys = {"hosts": "host", "services": "service", "users": "user", "groups": "group", "shares": "share", "credentials": "credential", "findings": "finding", "forms": "form", "endpoints": "http_endpoint"}
        for container in containers:
            for key, kind in keys.items():
                values = container.get(key)
                if not isinstance(values, list):
                    continue
                for value in values:
                    add(kind, value)
                    if kind == "host" and isinstance(value, dict):
                        host = str(value.get("ip") or value.get("host") or value.get("target") or target)
                        for service in value.get("services", value.get("ports", [])):
                            if isinstance(service, dict) and service.get("state", "open") == "open":
                                add("service", service, host)
    return list({item.observation_id: item for item in observations}.values())
