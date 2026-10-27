"""Single-worker polling agent for the process-local lab coordinator.

An agent retains its ID and unsent completion across transport reconnects within
this process. A local process restart does not recover a running execution.
Cancellation is cooperative: background ExecutionHandles can be terminated;
synchronous module handlers must return before the agent can acknowledge them.
"""

from __future__ import annotations

import base64
import hashlib
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from threading import Event
import time
from uuid import uuid4

from purplesploit.core.execution import ExecutionOutcome, ExecutionRequest, ExecutionResult, utc_now


class AgentStatus(str, Enum):
    DISCONNECTED = "disconnected"
    IDLE = "idle"
    RUNNING = "running"
    SUBMITTING = "submitting"
    LEASE_LOST = "lease_lost"


@dataclass
class AgentConfig:
    agent_id: str = field(default_factory=lambda: str(uuid4()))
    capabilities: list[str] = field(default_factory=list)
    heartbeat_interval: float = 1.0
    poll_interval: float = 1.0

    def __post_init__(self):
        if self.heartbeat_interval <= 0 or self.poll_interval <= 0:
            raise ValueError("Agent intervals must be positive")


class Agent:
    def __init__(self, transport, executor, config=None):
        """executor is framework.execute_request or a compatible callable."""
        self.transport = transport
        self.executor = executor
        self.config = config or AgentConfig()
        self.status = AgentStatus.DISCONNECTED
        self.last_error = None
        self.pending_result = None
        self._registered = False
        self._cancel = Event()
        self._stop = Event()

    def connect(self):
        if not self.transport.is_connected and not self.transport.connect():
            self.last_error = self.transport._last_error
            return False
        response = self.transport.send("register", {"agent_id": self.config.agent_id,
                                                    "capabilities": self.config.capabilities})
        self._registered = bool(response.get("success"))
        self.status = AgentStatus.IDLE if self._registered else AgentStatus.DISCONNECTED
        self.last_error = response.get("error")
        return self._registered

    def _send(self, kind, data):
        response = self.transport.send(kind, data)
        if not response.get("success"):
            self.last_error = response.get("error", "Coordinator rejected message")
            if response.get("status_code", 0) not in (404, 409, 422):
                self.transport.disconnect()
                self._registered = False
                self.status = AgentStatus.DISCONNECTED
        return response

    def _execute(self, task):
        request = ExecutionRequest.from_dict(task["request"])
        if self._cancel.is_set():
            return ExecutionResult(request_id=request.request_id, module_path=request.module_path,
                                   outcome=ExecutionOutcome.CANCELLED, cancelled=True, finished_at=utc_now())
        try:
            result = self.executor(request)
            if isinstance(result, dict):
                result = ExecutionResult.from_dict(result)
            if result.outcome == ExecutionOutcome.RUNNING:
                if result.handle is None:
                    raise ValueError("Running ExecutionResult has no local ExecutionHandle")
                handle = result.handle
                while result.outcome == ExecutionOutcome.RUNNING:
                    if self._cancel.is_set():
                        handle.cancel()
                    result = handle.status()
                    if result.outcome == ExecutionOutcome.RUNNING:
                        time.sleep(self.config.heartbeat_interval)
            return result
        except Exception as exc:
            return ExecutionResult(request_id=request.request_id, module_path=request.module_path,
                                   outcome=ExecutionOutcome.ERROR, error=str(exc), finished_at=utc_now())

    def _complete(self):
        pending = self.pending_result
        task, result = pending["task"], pending["result"]
        lease = {"task_id": task["id"], "agent_id": self.config.agent_id, "lease_id": task["lease_id"]}
        self.status = AgentStatus.SUBMITTING
        for artifact in pending["artifacts"]:
            if artifact.get("uploaded"):
                continue
            response = self._send("artifact_upload", {**lease, "name": artifact["name"],
                                                      "content_base64": artifact["content_base64"]})
            if not response.get("success"):
                if response.get("status_code") == 409:
                    self.status = AgentStatus.LEASE_LOST
                return response
            artifact["uploaded"] = True
        response = self._send("task_result", {**lease, "result": result.to_dict()})
        if response.get("success"):
            self.pending_result = None
            self.status = AgentStatus.IDLE
        elif response.get("status_code") == 409:
            # Retain the unaccepted result for inspection; never claim that an
            # expired attempt was successfully submitted.
            self.status = AgentStatus.LEASE_LOST
        return response

    def run_once(self):
        """Run or resume one task; return an observable protocol response."""
        if not self._registered and not self.connect():
            return {"success": False, "error": self.last_error}
        if self.pending_result is not None:
            return self._complete()
        response = self._send("task_request", {"agent_id": self.config.agent_id})
        if not response.get("success") or response.get("task") is None:
            return response
        task = response["task"]
        self._cancel.clear()
        if task["cancel_requested"] or self._stop.is_set():
            self._cancel.set()
        self.status = AgentStatus.RUNNING
        lost = False
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="purplesploit-agent") as pool:
            future = pool.submit(self._execute, task)
            while not future.done():
                heartbeat = self._send("heartbeat", {"agent_id": self.config.agent_id,
                    "leases": [{"task_id": task["id"], "lease_id": task["lease_id"]}]})
                if task["id"] in heartbeat.get("cancel", []) or self._stop.is_set():
                    self._cancel.set()
                if task["id"] in heartbeat.get("lost", []):
                    self._cancel.set()
                    lost = True
                if not heartbeat.get("success"):
                    # Reconnect and renew this exact lease; no new task is
                    # claimed while the current worker is still running.
                    if self.connect():
                        self.status = AgentStatus.RUNNING
                time.sleep(self.config.heartbeat_interval)
            result = future.result()
        artifacts = []
        for path in dict.fromkeys([*result.artifacts, result.stdout_ref, result.stderr_ref]):
            try:
                if path and Path(path).is_file():
                    content = Path(path).read_bytes()
                    artifacts.append({"name": Path(path).name,
                                      "content_base64": base64.b64encode(content).decode("ascii"),
                                      "sha256": hashlib.sha256(content).hexdigest()})
            except OSError as exc:
                result.raw_result.setdefault("artifact_transfer_errors", []).append({"path": path, "error": str(exc)})
        self.pending_result = {"task": task, "result": result, "artifacts": artifacts}
        if lost:
            self.status = AgentStatus.LEASE_LOST
            return {"success": False, "status_code": 409, "error": "Lease lost; local result retained"}
        if not self._registered and not self.connect():
            return {"success": False, "error": self.last_error}
        return self._complete()

    def sync_findings(self, findings):
        if not self._registered and not self.connect():
            return {"success": False, "error": self.last_error}
        return self._send("findings_sync", {"agent_id": self.config.agent_id,
                                            "findings": [item.to_dict() if hasattr(item, "to_dict") else item
                                                         for item in findings]})

    def run(self):
        """Poll until stop(); expired unsent results require operator recovery."""
        while not self._stop.is_set():
            self.run_once()
            if self.status == AgentStatus.LEASE_LOST:
                break
            self._stop.wait(self.config.poll_interval)

    def stop(self):
        self._stop.set()
        self._cancel.set()

    def disconnect(self):
        self._registered = False
        self.status = AgentStatus.DISCONNECTED
        return self.transport.disconnect()
