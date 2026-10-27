"""In-process jobs with cooperative control at explicit safe boundaries.

Job records are deliberately not durable. After process loss an absent ID is
unknown, never evidence of completion. ``interrupt`` records a known lost runner.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import asdict, dataclass, field, is_dataclass
from enum import Enum
from threading import Condition, RLock, Thread
from typing import Any, Callable
from uuid import uuid4

from .execution import utc_now


def serializable(value):
    if isinstance(value, Enum):
        return value.value
    if hasattr(value, "to_dict"):
        return serializable(value.to_dict())
    if is_dataclass(value):
        return serializable(asdict(value))
    if isinstance(value, dict):
        return {str(k): serializable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serializable(v) for v in value]
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return value


class _Stopped(BaseException):
    pass


TERMINAL = frozenset({"completed", "failed", "error", "stopped", "interrupted"})


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    progress: dict = field(default_factory=dict)
    result: Any = None
    result_handle: str | None = None
    outcome: str | None = None
    error: str | None = None
    created_at: str = field(default_factory=utc_now)
    started_at: str | None = None
    finished_at: str | None = None
    updated_at: str = field(default_factory=utc_now)
    revision: int = 0
    control: str | None = None


class JobContext:
    def __init__(self, manager: JobManager, job_id: str):
        self.manager = manager
        self.job_id = job_id

    def checkpoint(self, progress: dict | None = None):
        """Acknowledge a control request before the next unit of work."""
        manager = self.manager
        with manager._condition:
            job = manager._jobs[self.job_id]
            if progress is not None:
                job.progress = serializable(progress)
                manager._changed(job)
            while job.control == "pause" and job.status not in TERMINAL:
                if job.status != "paused":
                    job.status = "paused"
                    manager._changed(job)
                manager._condition.wait()
            if job.control == "stop" or job.status == "interrupted":
                raise _Stopped()
            if job.status not in TERMINAL and job.status != "running":
                job.status = "running"
                manager._changed(job)


class JobManager:
    """Thread runners with deterministic polling and an ordered event journal."""

    def __init__(self):
        self._condition = Condition(RLock())
        self._jobs: dict[str, Job] = {}
        self._events: dict[str, list[dict]] = {}
        self._threads: dict[str, Thread] = {}

    def _changed(self, job):
        job.revision += 1
        job.updated_at = utc_now()
        self._events[job.id].append(serializable(asdict(job)))
        self._condition.notify_all()

    def submit(self, kind: str, runner: Callable[[JobContext], Any]) -> dict:
        with self._condition:
            job = Job(str(uuid4()), kind)
            self._jobs[job.id] = job
            self._events[job.id] = []
            self._changed(job)
            thread = Thread(target=self._run, args=(job.id, runner), daemon=True,
                            name=f"purplesploit-{job.id}")
            self._threads[job.id] = thread
            thread.start()
            return self.get(job.id)

    def _run(self, job_id, runner):
        with self._condition:
            job = self._jobs[job_id]
            job.started_at = utc_now()
            self._changed(job)
        context = JobContext(self, job_id)
        try:
            context.checkpoint()
            value = runner(context)
            # A background launch is pending work. Wait on its actual handle.
            handle = getattr(value, "handle", None)
            if handle is not None:
                value = handle.wait()
            result = serializable(value)
            status = result.get("status", result.get("outcome", "")) if isinstance(result, dict) else ""
            nested = result.get("execution", {}) if isinstance(result, dict) else {}
            nested = nested if isinstance(nested, dict) else {}
            background = isinstance(result, dict) and result.get("background")
            if status in {"running", "queued", "paused", "pending"} or background or nested.get("outcome") == "running":
                raise RuntimeError("Runner returned pending work without a completed result handle")
            with self._condition:
                if job.status == "interrupted":
                    return
                job.result = result
                job.result_handle = f"jobs/{job_id}/result"
                success = result.get("success") if isinstance(result, dict) else None
                job.status = ("stopped" if status in {"stopped", "cancelled"}
                              else "interrupted" if status in {"interrupted", "unknown"}
                              else "error" if status == "error"
                              else "completed" if status in {"partial", "skipped"}
                              else "failed" if success is False or status in {"failed", "rejected", "timed_out"}
                              else "completed")
                job.outcome = str(status or ("success" if job.status == "completed" else job.status))
                if isinstance(result, dict):
                    job.error = result.get("error") or ("; ".join(result.get("errors", [])) or None)
        except _Stopped:
            with self._condition:
                if job.status != "interrupted":
                    job.status = "stopped"
                    job.outcome = "cancelled"
        except Exception as exc:
            with self._condition:
                if job.status != "interrupted":
                    job.status = "error"
                    job.outcome = "error"
                    job.error = f"{type(exc).__name__}: {exc}"
        finally:
            with self._condition:
                job.finished_at = job.finished_at or utc_now()
                job.control = None
                self._changed(job)

    def get(self, job_id: str) -> dict:
        with self._condition:
            if job_id not in self._jobs:
                raise KeyError(f"Unknown in-process job: {job_id}")
            return deepcopy(serializable(asdict(self._jobs[job_id])))

    def list(self) -> list[dict]:
        with self._condition:
            return [self.get(key) for key in self._jobs]

    def events(self, job_id: str, after: int = 0) -> list[dict]:
        with self._condition:
            self.get(job_id)
            return deepcopy([event for event in self._events[job_id] if event["revision"] > after])

    def control(self, job_id: str, action: str) -> dict:
        if action not in {"pause", "resume", "stop"}:
            raise ValueError("Expected pause, resume, or stop")
        with self._condition:
            self.get(job_id)
            job = self._jobs[job_id]
            if job.status in TERMINAL:
                raise ValueError(f"Job is terminal: {job.status}")
            if job.control == "stop":
                raise ValueError("Job is stopping")
            if action == "resume":
                if job.control != "pause":
                    raise ValueError("Job is not paused or pausing")
                job.control = None
                job.status = "running"
            else:
                job.control = action
                job.status = "pausing" if action == "pause" else "stopping"
            self._changed(job)
            return self.get(job_id)

    def interrupt(self, job_id: str, reason: str = "Runner lost") -> dict:
        with self._condition:
            self.get(job_id)
            job = self._jobs[job_id]
            if job.status not in TERMINAL:
                job.status = "interrupted"
                job.outcome = "unknown"
                job.error = reason
                job.finished_at = utc_now()
                self._changed(job)
            return self.get(job_id)

    def wait(self, job_id: str, timeout: float | None = None) -> dict:
        self.get(job_id)
        self._threads[job_id].join(timeout)
        return self.get(job_id)
