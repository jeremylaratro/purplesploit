"""Real cooperative runners: requests are distinct from acknowledgements."""

from threading import Event

import pytest

from purplesploit.core.execution import ExecutionResult, ExecutionOutcome
from purplesploit.core.jobs import JobManager


def wait_status(manager, job_id, status):
    # Condition-backed synchronization avoids timing-dependent sleeps.
    with manager._condition:
        assert manager._condition.wait_for(lambda: manager.get(job_id)["status"] == status, timeout=3)


def test_pause_resume_stop_at_safe_boundary():
    manager = JobManager()
    entered, release, next_boundary = Event(), Event(), Event()

    def runner(context):
        entered.set()
        assert release.wait(3)
        context.checkpoint({"completed": 1, "total": 2})
        next_boundary.set()
        context.checkpoint()
        return {"success": True}

    job = manager.submit("test", runner)
    assert entered.wait(3)
    assert manager.control(job["id"], "pause")["status"] == "pausing"
    assert not next_boundary.is_set()
    release.set()
    wait_status(manager, job["id"], "paused")
    assert manager.get(job["id"])["progress"]["completed"] == 1
    manager.control(job["id"], "stop")
    result = manager.wait(job["id"], 3)
    assert result["status"] == "stopped" and result["outcome"] == "cancelled"
    assert not next_boundary.is_set()
    assert result["finished_at"] and result["started_at"] and result["created_at"]


def test_resume_continues_same_runner_and_retains_result():
    manager = JobManager()
    entered, release = Event(), Event()

    def runner(context):
        entered.set()
        assert release.wait(3)
        context.checkpoint({"completed": 1})
        return {"success": True, "answer": 42}

    job_id = manager.submit("test", runner)["id"]
    assert entered.wait(3)
    manager.control(job_id, "pause")
    release.set()
    wait_status(manager, job_id, "paused")
    manager.control(job_id, "resume")
    result = manager.wait(job_id, 3)
    assert result["id"] == job_id and result["status"] == "completed"
    assert result["result"] == {"success": True, "answer": 42}
    assert result["result_handle"] == f"jobs/{job_id}/result"
    revisions = [event["revision"] for event in manager.events(job_id)]
    assert revisions == sorted(set(revisions))
    assert manager.events(job_id, result["revision"]) == []
    with pytest.raises(ValueError, match="terminal"):
        manager.control(job_id, "resume")


@pytest.mark.parametrize("returned, expected", [
    ({"success": False, "status": "partial"}, "completed"),
    ({"success": False, "status": "skipped"}, "completed"),
    ({"success": True, "status": "running"}, "error"),
    ({"success": True, "background": True}, "error"),
    ({"success": True, "execution": {"outcome": "running"}}, "error"),
    ({"status": "error", "errors": ["tool unavailable"]}, "error"),
])
def test_outcome_is_not_background_launch_success(returned, expected):
    manager = JobManager()
    job = manager.submit("test", lambda context: returned)
    assert manager.wait(job["id"], 3)["status"] == expected


def test_errors_unknown_and_interrupted():
    manager = JobManager()

    def broken(context):
        raise RuntimeError("external failure")

    job = manager.submit("test", broken)
    assert "external failure" in manager.wait(job["id"], 3)["error"]
    with pytest.raises(KeyError, match="Unknown"):
        manager.get("lost-on-restart")
    entered, release = Event(), Event()

    def waiting(context):
        entered.set()
        release.wait(3)
        return {"success": True}

    job_id = manager.submit("test", waiting)["id"]
    assert entered.wait(3)
    manager.interrupt(job_id)
    release.set()
    result = manager.wait(job_id, 3)
    assert result["status"] == "interrupted" and result["outcome"] == "unknown"
    assert result["result"] is None


def test_background_execution_waits_for_actual_handle():
    manager = JobManager()
    entered, release = Event(), Event()
    execution = ExecutionResult("request", outcome=ExecutionOutcome.RUNNING)

    class ExternalHandle:
        def wait(self):
            entered.set()
            assert release.wait(3)
            execution.outcome = ExecutionOutcome.FAILED
            execution.success = False
            return execution

    execution._handle = ExternalHandle()
    job_id = manager.submit("process", lambda context: execution)["id"]
    assert entered.wait(3)
    assert manager.get(job_id)["status"] == "running"
    release.set()
    assert manager.wait(job_id, 3)["status"] == "failed"
