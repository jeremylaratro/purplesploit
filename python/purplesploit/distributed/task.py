"""
Task Management for Distributed PurpleSploit

Defines tasks that can be distributed across agents.
"""

from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
from enum import Enum
import uuid
import json


class TaskStatus(Enum):
    """Task execution status."""
    PENDING = "pending"
    QUEUED = "queued"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class TaskPriority(Enum):
    """Task priority levels."""
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TaskResult:
    """Result from a completed task."""
    task_id: str
    success: bool
    data: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    execution_time: float = 0.0
    agent_id: Optional[str] = None
    findings: List[Dict[str, Any]] = field(default_factory=list)
    credentials: List[Dict[str, Any]] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    completed_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "task_id": self.task_id,
            "success": self.success,
            "data": self.data,
            "error": self.error,
            "execution_time": self.execution_time,
            "agent_id": self.agent_id,
            "findings": self.findings,
            "credentials": self.credentials,
            "services": self.services,
            "completed_at": self.completed_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskResult":
        if isinstance(data.get("completed_at"), str):
            data["completed_at"] = datetime.fromisoformat(data["completed_at"])
        return cls(**data)


@dataclass
class Task:
    """
    A distributable task definition.

    Tasks can be:
    - Module executions
    - Workflow steps
    - Custom scripts
    - Scan operations
    """
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:12])
    name: str = ""
    task_type: str = "module"  # module, workflow, script, scan
    module: Optional[str] = None
    operation: Optional[str] = None
    options: Dict[str, Any] = field(default_factory=dict)
    target: Optional[str] = None
    targets: List[str] = field(default_factory=list)
    priority: TaskPriority = TaskPriority.NORMAL
    status: TaskStatus = TaskStatus.PENDING
    timeout: int = 3600  # seconds
    retry_count: int = 0
    max_retries: int = 3
    assigned_agent: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[TaskResult] = None
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # Task IDs this depends on
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.name and self.module:
            self.name = f"{self.module}"
            if self.operation:
                self.name += f":{self.operation}"

    @property
    def is_pending(self) -> bool:
        return self.status in (TaskStatus.PENDING, TaskStatus.QUEUED)

    @property
    def is_running(self) -> bool:
        return self.status in (TaskStatus.ASSIGNED, TaskStatus.RUNNING)

    @property
    def is_complete(self) -> bool:
        return self.status in (TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED)

    @property
    def can_retry(self) -> bool:
        return (
            self.status == TaskStatus.FAILED and
            self.retry_count < self.max_retries
        )

    def assign(self, agent_id: str) -> None:
        """Assign task to an agent."""
        self.assigned_agent = agent_id
        self.status = TaskStatus.ASSIGNED

    def start(self) -> None:
        """Mark task as started."""
        self.status = TaskStatus.RUNNING
        self.started_at = datetime.utcnow()

    def complete(self, result: TaskResult) -> None:
        """Mark task as completed."""
        self.status = TaskStatus.COMPLETED if result.success else TaskStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.result = result

    def fail(self, error: str) -> None:
        """Mark task as failed."""
        self.status = TaskStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.result = TaskResult(
            task_id=self.id,
            success=False,
            error=error,
        )

    def cancel(self) -> None:
        """Cancel the task."""
        self.status = TaskStatus.CANCELLED
        self.completed_at = datetime.utcnow()

    def retry(self) -> bool:
        """Attempt to retry the task."""
        if not self.can_retry:
            return False
        self.retry_count += 1
        self.status = TaskStatus.PENDING
        self.assigned_agent = None
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "task_type": self.task_type,
            "module": self.module,
            "operation": self.operation,
            "options": self.options,
            "target": self.target,
            "targets": self.targets,
            "priority": self.priority.value,
            "status": self.status.value,
            "timeout": self.timeout,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "assigned_agent": self.assigned_agent,
            "created_at": self.created_at.isoformat(),
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "result": self.result.to_dict() if self.result else None,
            "tags": self.tags,
            "dependencies": self.dependencies,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Task":
        # Convert enums
        if isinstance(data.get("priority"), int):
            data["priority"] = TaskPriority(data["priority"])
        if isinstance(data.get("status"), str):
            data["status"] = TaskStatus(data["status"])

        # Convert datetimes
        for field_name in ["created_at", "started_at", "completed_at"]:
            if data.get(field_name) and isinstance(data[field_name], str):
                data[field_name] = datetime.fromisoformat(data[field_name])

        # Convert result
        if data.get("result"):
            data["result"] = TaskResult.from_dict(data["result"])

        return cls(**data)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_json(cls, json_str: str) -> "Task":
        return cls.from_dict(json.loads(json_str))


class TaskQueue:
    """Priority queue for tasks."""

    def __init__(self):
        self._tasks: Dict[str, Task] = {}
        self._queue: List[str] = []  # Task IDs in priority order

    def add(self, task: Task) -> None:
        """Add a task to the queue."""
        self._tasks[task.id] = task
        task.status = TaskStatus.QUEUED
        self._insert_by_priority(task.id)

    def _insert_by_priority(self, task_id: str) -> None:
        """Insert task ID in priority order."""
        task = self._tasks[task_id]
        insert_pos = len(self._queue)

        for i, existing_id in enumerate(self._queue):
            existing_task = self._tasks.get(existing_id)
            if existing_task and task.priority.value > existing_task.priority.value:
                insert_pos = i
                break

        self._queue.insert(insert_pos, task_id)

    def get_next(self, agent_capabilities: Optional[List[str]] = None) -> Optional[Task]:
        """
        Get the next available task.

        Args:
            agent_capabilities: Optional list of modules the agent can run

        Returns:
            Next available task or None
        """
        for task_id in self._queue[:]:
            task = self._tasks.get(task_id)
            if not task or task.status != TaskStatus.QUEUED:
                continue

            # Check dependencies
            if task.dependencies:
                deps_complete = all(
                    self._tasks.get(dep_id) and
                    self._tasks[dep_id].status == TaskStatus.COMPLETED
                    for dep_id in task.dependencies
                )
                if not deps_complete:
                    continue

            # Check agent capabilities
            if agent_capabilities and task.module:
                if task.module not in agent_capabilities:
                    continue

            return task

        return None

    def remove(self, task_id: str) -> Optional[Task]:
        """Remove a task from the queue."""
        if task_id in self._queue:
            self._queue.remove(task_id)
        return self._tasks.pop(task_id, None)

    def get(self, task_id: str) -> Optional[Task]:
        """Get a task by ID."""
        return self._tasks.get(task_id)

    def get_all(self, status: Optional[TaskStatus] = None) -> List[Task]:
        """Get all tasks, optionally filtered by status."""
        tasks = list(self._tasks.values())
        if status:
            tasks = [t for t in tasks if t.status == status]
        return tasks

    def get_pending_count(self) -> int:
        """Get count of pending tasks."""
        return sum(1 for t in self._tasks.values() if t.is_pending)

    def get_running_count(self) -> int:
        """Get count of running tasks."""
        return sum(1 for t in self._tasks.values() if t.is_running)

    def clear_completed(self) -> int:
        """Remove completed tasks and return count."""
        completed_ids = [
            task_id for task_id, task in self._tasks.items()
            if task.is_complete
        ]
        for task_id in completed_ids:
            self.remove(task_id)
        return len(completed_ids)
