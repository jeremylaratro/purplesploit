"""In-process coordinator for the version 1 fixture-lab protocol.

Leases permit reassignment after a disconnect, so execution is at least once.
State is intentionally process-local. Authentication, trust, replay protection,
durable recovery and production execution policy belong to later hardening.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import base64
import hashlib
import hmac
from pathlib import PurePath
from threading import RLock
import time
from uuid import uuid4

from purplesploit.core.execution import ExecutionOutcome, ExecutionRequest, ExecutionResult
from purplesploit.core.findings import Finding
from purplesploit.distributed.task import Task, TaskPriority, TaskStatus

PROTOCOL_VERSION = 1


class ProtocolConflict(ValueError):
    """The message conflicts with the current task/lease state."""


@dataclass
class CoordinatorConfig:
    lease_seconds: float = 30.0
    heartbeat_timeout: float = 60.0
    max_artifact_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        if self.lease_seconds <= 0 or self.heartbeat_timeout <= 0 or self.max_artifact_bytes <= 0:
            raise ValueError("Lease and heartbeat durations must be positive")


class Coordinator:
    """One task per agent, with renewable leases and observable cancellation."""

    def __init__(self, config=None, *, clock=time.time, on_result=None, on_findings=None,
                 policy=None, authenticator=None):
        self.config = config or CoordinatorConfig()
        self.clock = clock
        self.on_result = on_result
        self.on_findings = on_findings
        self.policy = policy
        self.authenticator = authenticator
        self._lock = RLock()
        self._agents = {}
        self._tasks = {}
        self._findings = {}

    def health(self):
        return {"success": True, "protocol_version": PROTOCOL_VERSION,
                "storage": "in_process", "delivery": "at_least_once",
                "cancellation": "cooperative",
                "security_hardened": self.authenticator is not None}

    def register(self, agent_id=None, capabilities=None, **metadata):
        with self._lock:
            agent_id = agent_id or str(uuid4())
            previous = self._agents.get(agent_id, {})
            self._agents[agent_id] = {
                "agent_id": agent_id, "capabilities": list(capabilities or []),
                "last_seen": self.clock(), "registrations": previous.get("registrations", 0) + 1,
                "metadata": metadata,
            }
            return {"success": True, "protocol_version": PROTOCOL_VERSION,
                    "agent_id": agent_id, "lease_seconds": self.config.lease_seconds}

    def agents(self):
        with self._lock:
            now = self.clock()
            return [deepcopy(dict(agent, status="online" if now - agent["last_seen"] <
                                  self.config.heartbeat_timeout else "offline"))
                    for agent in self._agents.values()]

    def _agent(self, agent_id):
        if agent_id not in self._agents:
            raise KeyError(f"Unknown agent: {agent_id}")
        self._agents[agent_id]["last_seen"] = self.clock()
        return self._agents[agent_id]

    def submit(self, request, priority=2, name=""):
        request = ExecutionRequest.from_dict(request.to_dict() if isinstance(request, ExecutionRequest) else request)
        if self.policy is not None:
            self.policy.authorize(request, reserve=False)
        with self._lock:
            task = Task(name=name, module=request.module_path, operation=request.operation_name,
                        priority=TaskPriority(priority), status=TaskStatus.QUEUED)
            self._tasks[task.id] = {"task": task, "request": request, "lease_id": None,
                                    "lease_expires_at": None, "attempt": 0,
                                    "cancel_requested": False, "execution_result": None,
                                    "artifacts": {}}
            return self._view(self._tasks[task.id])

    def _expire(self):
        for item in self._tasks.values():
            if (item["task"].is_running and item["lease_expires_at"] <= self.clock()):
                # Cancelled leases are not reassigned: execution might still be
                # running on the disconnected agent. This state is observable.
                if item["cancel_requested"]:
                    item["task"].cancel()
                else:
                    item["task"].status = TaskStatus.QUEUED
                item["task"].assigned_agent = None
                item["lease_id"] = None
                item["lease_expires_at"] = None

    def claim(self, agent_id):
        with self._lock:
            agent = self._agent(agent_id)
            self._expire()
            # Re-register/reconnect returns the current lease, not a new task.
            for item in self._tasks.values():
                if item["task"].assigned_agent == agent_id and item["task"].is_running:
                    return {"success": True, "task": self._view(item)}
            pending = [item for item in self._tasks.values() if item["task"].status == TaskStatus.QUEUED
                       and (not agent["capabilities"] or item["request"].module_path in agent["capabilities"])]
            pending.sort(key=lambda item: -item["task"].priority.value)
            if not pending:
                return {"success": True, "task": None}
            item = pending[0]
            item["task"].assign(agent_id)
            item["lease_id"] = str(uuid4())
            item["lease_expires_at"] = self.clock() + self.config.lease_seconds
            item["attempt"] += 1
            return {"success": True, "task": self._view(item)}

    def _lease(self, task_id, agent_id, lease_id):
        self._agent(agent_id)
        self._expire()
        item = self._tasks[task_id]
        if item["task"].assigned_agent != agent_id or item["lease_id"] != lease_id:
            raise ProtocolConflict("Lease expired or belongs to another attempt")
        return item

    def heartbeat(self, agent_id, leases=None):
        with self._lock:
            self._agent(agent_id)
            self._expire()
            renewed, lost, cancelled = [], [], []
            for lease in leases or []:
                try:
                    item = self._lease(lease["task_id"], agent_id, lease["lease_id"])
                except (KeyError, ProtocolConflict):
                    lost.append(lease["task_id"])
                    continue
                if item["task"].is_running:
                    item["lease_expires_at"] = self.clock() + self.config.lease_seconds
                    item["task"].status = TaskStatus.RUNNING
                    renewed.append(item["task"].id)
                    if item["cancel_requested"]:
                        cancelled.append(item["task"].id)
            return {"success": True, "renewed": renewed, "lost": lost, "cancel": cancelled}

    def result(self, task_id, agent_id, lease_id, result):
        result = ExecutionResult.from_dict(result.to_dict() if isinstance(result, ExecutionResult) else result)
        if result.outcome == ExecutionOutcome.RUNNING:
            raise ValueError("Submit a terminal ExecutionResult")
        with self._lock:
            item = self._lease(task_id, agent_id, lease_id)
            if result.request_id != item["request"].request_id or result.module_path != item["request"].module_path:
                raise ProtocolConflict("ExecutionResult does not match the assigned request")
            if item["execution_result"] is not None:
                if item["execution_result"] != result.to_dict():
                    raise ProtocolConflict("A different terminal result is already recorded")
                return {"success": True, "duplicate": True, "task": self._view(item)}
            if self.on_result:
                self.on_result(result)
            item["execution_result"] = result.to_dict()
            item["task"].status = (TaskStatus.CANCELLED if result.outcome == ExecutionOutcome.CANCELLED else
                                    TaskStatus.COMPLETED if result.success else TaskStatus.FAILED)
            return {"success": True, "duplicate": False, "task": self._view(item)}

    def cancel(self, task_id):
        with self._lock:
            self._expire()
            item = self._tasks[task_id]
            if not item["task"].is_complete:
                item["cancel_requested"] = True
                if not item["task"].is_running:
                    item["task"].cancel()
            return self._view(item)

    def status(self, task_id=None):
        with self._lock:
            self._expire()
            return self._view(self._tasks[task_id]) if task_id else [self._view(item) for item in self._tasks.values()]

    def _view(self, item):
        task = item["task"]
        status = task.status.value
        if item["cancel_requested"] and task.is_running:
            status = "cancelling"
        elif item["cancel_requested"] and item["attempt"] and task.status == TaskStatus.CANCELLED and item["execution_result"] is None:
            status = "cancel_unconfirmed"
        return deepcopy({"id": task.id, "name": task.name,
                         "status": status,
                         "request": item["request"].to_dict(), "priority": task.priority.value,
                         "agent_id": task.assigned_agent, "lease_id": item["lease_id"],
                         "lease_expires_at": item["lease_expires_at"], "attempt": item["attempt"],
                         "cancel_requested": item["cancel_requested"], "result": item["execution_result"],
                         "artifacts": [{key: value for key, value in artifact.items() if key != "content_base64"}
                                       for artifact in item["artifacts"].values()]})

    def put_artifact(self, task_id, agent_id, lease_id, name, content_base64, sha256=None):
        content = base64.b64decode(content_base64, validate=True)
        if len(content) > self.config.max_artifact_bytes:
            raise ValueError("Artifact exceeds the configured size limit")
        if PurePath(name).name != name or name in {"", ".", ".."}:
            raise ValueError("Artifact name must be a plain file name")
        digest = hashlib.sha256(content).hexdigest()
        if self.authenticator is not None and not sha256:
            raise ValueError("Authenticated artifact uploads require sha256")
        if sha256 and not hmac.compare_digest(str(sha256).lower(), digest):
            raise ValueError("Artifact sha256 does not match content")
        with self._lock:
            item = self._lease(task_id, agent_id, lease_id)
            if item["execution_result"] is not None:
                raise ProtocolConflict("Upload artifacts before the terminal result")
            artifact_id = str(uuid4())
            item["artifacts"][artifact_id] = {"id": artifact_id, "name": name, "size": len(content),
                                               "sha256": digest,
                                               "content_base64": content_base64}
            return {"success": True, "artifact_id": artifact_id}

    def artifact(self, task_id, artifact_id):
        with self._lock:
            return deepcopy(self._tasks[task_id]["artifacts"][artifact_id])

    def sync_findings(self, agent_id, findings):
        values = [Finding.from_dict(value).to_dict() for value in findings]
        with self._lock:
            self._agent(agent_id)
            if self.on_findings:
                self.on_findings(values)
            for value in values:
                self._findings[value["id"]] = value
            return {"success": True, "finding_ids": [value["id"] for value in values]}

    def findings(self):
        with self._lock:
            return deepcopy(list(self._findings.values()))

    def dispatch(self, message_type, data):
        """Shared HTTP/WebSocket envelope operations (not an authorization layer)."""
        handlers = {"register": self.register, "heartbeat": self.heartbeat, "task_request": self.claim,
                    "task_submit": self.submit, "task_result": self.result, "task_cancel": self.cancel,
                    "task_status": self.status, "artifact_upload": self.put_artifact,
                    "findings_sync": self.sync_findings}
        if message_type not in handlers:
            raise ValueError(f"Unknown message type: {message_type}")
        return handlers[message_type](**data)
