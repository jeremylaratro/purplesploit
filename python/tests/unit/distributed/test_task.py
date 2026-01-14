"""
Unit tests for purplesploit.distributed.task module.

Tests cover:
- TaskStatus enum
- TaskPriority enum
- TaskResult dataclass
- Task dataclass (initialization, properties, state methods, serialization)
- TaskQueue class (add, remove, priority ordering, capabilities, dependencies)
"""

import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import json

from purplesploit.distributed.task import (
    TaskStatus,
    TaskPriority,
    TaskResult,
    Task,
    TaskQueue,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def sample_task_result():
    """Create a basic TaskResult for testing."""
    return TaskResult(task_id="test-123", success=True)


@pytest.fixture
def sample_task_result_failed():
    """Create a failed TaskResult for testing."""
    return TaskResult(
        task_id="test-456",
        success=False,
        error="Test error occurred",
    )


@pytest.fixture
def sample_task_result_full():
    """Create a TaskResult with all fields populated."""
    return TaskResult(
        task_id="test-789",
        success=True,
        data={"key": "value"},
        error=None,
        execution_time=1.5,
        agent_id="agent-001",
        findings=[{"type": "vuln", "id": "CVE-2024-0001"}],
        credentials=[{"username": "admin", "password": "hash"}],
        services=[{"port": 22, "service": "ssh"}],
    )


@pytest.fixture
def basic_task():
    """Create a basic Task for testing."""
    return Task(name="test-task", module="nmap", operation="scan")


@pytest.fixture
def task_with_dependencies():
    """Create a Task with dependencies."""
    return Task(
        id="dependent-task",
        name="dependent",
        module="exploit",
        dependencies=["dep-1", "dep-2"],
    )


@pytest.fixture
def task_queue():
    """Create an empty TaskQueue for testing."""
    return TaskQueue()


@pytest.fixture
def populated_task_queue():
    """Create a TaskQueue with various tasks of different priorities."""
    queue = TaskQueue()
    queue.add(Task(id="low-1", name="low-task", priority=TaskPriority.LOW, module="mod_a"))
    queue.add(Task(id="normal-1", name="normal-task", priority=TaskPriority.NORMAL, module="mod_b"))
    queue.add(Task(id="high-1", name="high-task", priority=TaskPriority.HIGH, module="mod_c"))
    queue.add(Task(id="critical-1", name="critical-task", priority=TaskPriority.CRITICAL, module="mod_d"))
    return queue


# =============================================================================
# TaskStatus Enum Tests
# =============================================================================

class TestTaskStatus:
    """Tests for TaskStatus enum."""

    def test_all_values_exist(self):
        """Test all status values are accessible."""
        statuses = [
            TaskStatus.PENDING,
            TaskStatus.QUEUED,
            TaskStatus.ASSIGNED,
            TaskStatus.RUNNING,
            TaskStatus.COMPLETED,
            TaskStatus.FAILED,
            TaskStatus.CANCELLED,
            TaskStatus.TIMEOUT,
        ]
        assert len(statuses) == 8

    def test_value_property_returns_string(self):
        """Test .value returns correct strings."""
        assert TaskStatus.PENDING.value == "pending"
        assert TaskStatus.QUEUED.value == "queued"
        assert TaskStatus.ASSIGNED.value == "assigned"
        assert TaskStatus.RUNNING.value == "running"
        assert TaskStatus.COMPLETED.value == "completed"
        assert TaskStatus.FAILED.value == "failed"
        assert TaskStatus.CANCELLED.value == "cancelled"
        assert TaskStatus.TIMEOUT.value == "timeout"

    def test_enum_from_value(self):
        """Test creating enum from string value."""
        assert TaskStatus("pending") == TaskStatus.PENDING
        assert TaskStatus("completed") == TaskStatus.COMPLETED

    def test_invalid_value_raises(self):
        """Test invalid string raises ValueError."""
        with pytest.raises(ValueError):
            TaskStatus("invalid")

    def test_enum_equality(self):
        """Test enum comparison works correctly."""
        assert TaskStatus.PENDING == TaskStatus.PENDING
        assert TaskStatus.PENDING != TaskStatus.RUNNING


# =============================================================================
# TaskPriority Enum Tests
# =============================================================================

class TestTaskPriority:
    """Tests for TaskPriority enum."""

    def test_all_values_exist(self):
        """Test all priority values are accessible with correct ints."""
        assert TaskPriority.LOW.value == 1
        assert TaskPriority.NORMAL.value == 2
        assert TaskPriority.HIGH.value == 3
        assert TaskPriority.CRITICAL.value == 4

    def test_value_property_returns_int(self):
        """Test .value returns correct integers."""
        assert isinstance(TaskPriority.LOW.value, int)
        assert isinstance(TaskPriority.CRITICAL.value, int)

    def test_enum_from_int(self):
        """Test creating enum from int value."""
        assert TaskPriority(1) == TaskPriority.LOW
        assert TaskPriority(4) == TaskPriority.CRITICAL

    def test_invalid_int_raises(self):
        """Test invalid int raises ValueError."""
        with pytest.raises(ValueError):
            TaskPriority(5)
        with pytest.raises(ValueError):
            TaskPriority(0)

    def test_priority_ordering_via_value(self):
        """Test priority comparison via .value."""
        assert TaskPriority.CRITICAL.value > TaskPriority.HIGH.value
        assert TaskPriority.HIGH.value > TaskPriority.NORMAL.value
        assert TaskPriority.NORMAL.value > TaskPriority.LOW.value

    def test_negative_int_raises(self):
        """Test negative int raises ValueError."""
        with pytest.raises(ValueError):
            TaskPriority(-1)


# =============================================================================
# TaskResult Dataclass Tests
# =============================================================================

class TestTaskResult:
    """Tests for TaskResult dataclass."""

    def test_init_required_fields(self):
        """Test creating TaskResult with only required fields."""
        result = TaskResult(task_id="test-id", success=True)
        assert result.task_id == "test-id"
        assert result.success is True

    def test_init_all_defaults(self):
        """Test default values are set correctly."""
        result = TaskResult(task_id="test-id", success=False)
        assert result.data == {}
        assert result.error is None
        assert result.execution_time == 0.0
        assert result.agent_id is None
        assert result.findings == []
        assert result.credentials == []
        assert result.services == []
        assert isinstance(result.completed_at, datetime)

    def test_completed_at_default_is_datetime(self):
        """Test completed_at default is a datetime close to now."""
        result = TaskResult(task_id="test", success=True)
        now = datetime.utcnow()
        assert isinstance(result.completed_at, datetime)
        # Should be within 1 second of now
        assert abs((now - result.completed_at).total_seconds()) < 1

    def test_result_with_error_message(self):
        """Test result with error message."""
        result = TaskResult(task_id="test", success=False, error="Connection failed")
        assert result.error == "Connection failed"
        assert result.success is False

    def test_result_with_populated_findings(self):
        """Test result with findings populated."""
        findings = [{"vuln": "CVE-2024-0001"}]
        result = TaskResult(task_id="test", success=True, findings=findings)
        assert len(result.findings) == 1
        assert result.findings[0]["vuln"] == "CVE-2024-0001"

    def test_result_with_populated_credentials(self):
        """Test result with credentials populated."""
        creds = [{"user": "admin", "pass": "secret"}]
        result = TaskResult(task_id="test", success=True, credentials=creds)
        assert len(result.credentials) == 1

    def test_result_with_populated_services(self):
        """Test result with services populated."""
        services = [{"port": 22, "name": "ssh"}]
        result = TaskResult(task_id="test", success=True, services=services)
        assert len(result.services) == 1


class TestTaskResultSerialization:
    """Tests for TaskResult serialization methods."""

    def test_to_dict_all_fields(self, sample_task_result_full):
        """Test to_dict includes all fields."""
        data = sample_task_result_full.to_dict()
        assert "task_id" in data
        assert "success" in data
        assert "data" in data
        assert "error" in data
        assert "execution_time" in data
        assert "agent_id" in data
        assert "findings" in data
        assert "credentials" in data
        assert "services" in data
        assert "completed_at" in data

    def test_to_dict_completed_at_iso_format(self, sample_task_result):
        """Test completed_at is serialized as ISO format string."""
        data = sample_task_result.to_dict()
        assert isinstance(data["completed_at"], str)
        # Should be parseable as ISO datetime
        datetime.fromisoformat(data["completed_at"])

    def test_from_dict_basic(self):
        """Test from_dict creates TaskResult correctly."""
        data = {
            "task_id": "test-id",
            "success": True,
            "data": {},
            "error": None,
            "execution_time": 1.0,
            "agent_id": None,
            "findings": [],
            "credentials": [],
            "services": [],
            "completed_at": "2024-01-15T12:00:00",
        }
        result = TaskResult.from_dict(data)
        assert result.task_id == "test-id"
        assert result.success is True

    def test_from_dict_with_datetime_string(self):
        """Test from_dict handles ISO datetime string."""
        data = {
            "task_id": "test",
            "success": True,
            "data": {},
            "error": None,
            "execution_time": 0.0,
            "agent_id": None,
            "findings": [],
            "credentials": [],
            "services": [],
            "completed_at": "2024-01-15T10:30:00",
        }
        result = TaskResult.from_dict(data)
        assert isinstance(result.completed_at, datetime)
        assert result.completed_at.hour == 10
        assert result.completed_at.minute == 30

    def test_from_dict_with_datetime_object(self):
        """Test from_dict handles datetime object directly."""
        dt = datetime(2024, 1, 15, 12, 0, 0)
        data = {
            "task_id": "test",
            "success": True,
            "data": {},
            "error": None,
            "execution_time": 0.0,
            "agent_id": None,
            "findings": [],
            "credentials": [],
            "services": [],
            "completed_at": dt,
        }
        result = TaskResult.from_dict(data)
        assert result.completed_at == dt

    def test_roundtrip_serialization(self, sample_task_result_full):
        """Test to_dict/from_dict roundtrip."""
        data = sample_task_result_full.to_dict()
        restored = TaskResult.from_dict(data)
        assert restored.task_id == sample_task_result_full.task_id
        assert restored.success == sample_task_result_full.success
        assert restored.execution_time == sample_task_result_full.execution_time


# =============================================================================
# Task Dataclass Tests
# =============================================================================

class TestTask:
    """Tests for Task dataclass initialization and defaults."""

    def test_init_defaults(self):
        """Test Task with default values."""
        task = Task()
        assert len(task.id) == 12  # Truncated UUID
        assert task.name == ""
        assert task.task_type == "module"
        assert task.module is None
        assert task.priority == TaskPriority.NORMAL
        assert task.status == TaskStatus.PENDING
        assert task.timeout == 3600
        assert task.retry_count == 0
        assert task.max_retries == 3

    def test_init_generates_unique_id(self):
        """Test each Task gets unique ID."""
        task1 = Task()
        task2 = Task()
        assert task1.id != task2.id

    def test_init_with_all_fields(self):
        """Test Task with all fields specified."""
        task = Task(
            id="custom-id",
            name="my-task",
            task_type="script",
            module="nmap",
            operation="scan",
            options={"ports": "1-1000"},
            target="192.168.1.1",
            targets=["192.168.1.1", "192.168.1.2"],
            priority=TaskPriority.HIGH,
            timeout=7200,
            tags=["recon", "scanning"],
        )
        assert task.id == "custom-id"
        assert task.name == "my-task"
        assert task.task_type == "script"
        assert task.priority == TaskPriority.HIGH

    def test_post_init_name_from_module(self):
        """Test name auto-generated from module."""
        task = Task(module="nmap")
        assert task.name == "nmap"

    def test_post_init_name_from_module_and_operation(self):
        """Test name auto-generated from module:operation."""
        task = Task(module="nmap", operation="service_scan")
        assert task.name == "nmap:service_scan"

    def test_post_init_preserves_explicit_name(self):
        """Test explicit name is not overwritten."""
        task = Task(name="custom-name", module="nmap", operation="scan")
        assert task.name == "custom-name"

    def test_created_at_default_is_datetime(self):
        """Test created_at default is a datetime."""
        task = Task()
        assert isinstance(task.created_at, datetime)


class TestTaskProperties:
    """Tests for Task property methods."""

    def test_is_pending_with_pending_status(self):
        """Test is_pending True when status is PENDING."""
        task = Task(status=TaskStatus.PENDING)
        assert task.is_pending is True

    def test_is_pending_with_queued_status(self):
        """Test is_pending True when status is QUEUED."""
        task = Task(status=TaskStatus.QUEUED)
        assert task.is_pending is True

    def test_is_pending_false_for_running(self):
        """Test is_pending False for RUNNING status."""
        task = Task(status=TaskStatus.RUNNING)
        assert task.is_pending is False

    def test_is_pending_false_for_completed(self):
        """Test is_pending False for completed statuses."""
        for status in [TaskStatus.COMPLETED, TaskStatus.FAILED, TaskStatus.CANCELLED]:
            task = Task(status=status)
            assert task.is_pending is False

    def test_is_running_with_assigned_status(self):
        """Test is_running True when ASSIGNED."""
        task = Task(status=TaskStatus.ASSIGNED)
        assert task.is_running is True

    def test_is_running_with_running_status(self):
        """Test is_running True when RUNNING."""
        task = Task(status=TaskStatus.RUNNING)
        assert task.is_running is True

    def test_is_running_false_for_completed(self):
        """Test is_running False for completed statuses."""
        task = Task(status=TaskStatus.COMPLETED)
        assert task.is_running is False

    def test_is_complete_with_completed_status(self):
        """Test is_complete True when COMPLETED."""
        task = Task(status=TaskStatus.COMPLETED)
        assert task.is_complete is True

    def test_is_complete_with_failed_status(self):
        """Test is_complete True when FAILED."""
        task = Task(status=TaskStatus.FAILED)
        assert task.is_complete is True

    def test_is_complete_with_cancelled_status(self):
        """Test is_complete True when CANCELLED."""
        task = Task(status=TaskStatus.CANCELLED)
        assert task.is_complete is True

    def test_is_complete_false_for_pending(self):
        """Test is_complete False for PENDING status."""
        task = Task(status=TaskStatus.PENDING)
        assert task.is_complete is False

    def test_can_retry_when_failed_under_max(self):
        """Test can_retry True when failed with retries available."""
        task = Task(status=TaskStatus.FAILED, retry_count=1, max_retries=3)
        assert task.can_retry is True

    def test_can_retry_false_when_at_max_retries(self):
        """Test can_retry False when retry_count >= max_retries."""
        task = Task(status=TaskStatus.FAILED, retry_count=3, max_retries=3)
        assert task.can_retry is False

    def test_can_retry_false_when_not_failed(self):
        """Test can_retry False when status is not FAILED."""
        task = Task(status=TaskStatus.COMPLETED, retry_count=0, max_retries=3)
        assert task.can_retry is False


class TestTaskStateMethods:
    """Tests for Task state transition methods."""

    def test_assign_sets_agent_and_status(self, basic_task):
        """Test assign() sets agent and status."""
        basic_task.assign("agent-001")
        assert basic_task.assigned_agent == "agent-001"
        assert basic_task.status == TaskStatus.ASSIGNED

    def test_start_sets_status_and_timestamp(self, basic_task):
        """Test start() sets status and started_at."""
        basic_task.start()
        assert basic_task.status == TaskStatus.RUNNING
        assert isinstance(basic_task.started_at, datetime)

    def test_complete_with_success_result(self, basic_task, sample_task_result):
        """Test complete() with successful result."""
        basic_task.complete(sample_task_result)
        assert basic_task.status == TaskStatus.COMPLETED
        assert basic_task.result == sample_task_result
        assert isinstance(basic_task.completed_at, datetime)

    def test_complete_with_failed_result(self, basic_task, sample_task_result_failed):
        """Test complete() with failed result sets FAILED status."""
        basic_task.complete(sample_task_result_failed)
        assert basic_task.status == TaskStatus.FAILED
        assert basic_task.result == sample_task_result_failed

    def test_fail_sets_status_and_result(self, basic_task):
        """Test fail() sets status and creates error result."""
        basic_task.fail("Connection timeout")
        assert basic_task.status == TaskStatus.FAILED
        assert basic_task.result is not None
        assert basic_task.result.success is False
        assert basic_task.result.error == "Connection timeout"

    def test_cancel_sets_status_and_timestamp(self, basic_task):
        """Test cancel() sets status and completed_at."""
        basic_task.cancel()
        assert basic_task.status == TaskStatus.CANCELLED
        assert isinstance(basic_task.completed_at, datetime)

    def test_retry_success_increments_count(self, basic_task):
        """Test retry() increments retry_count."""
        basic_task.status = TaskStatus.FAILED
        basic_task.retry_count = 0
        result = basic_task.retry()
        assert result is True
        assert basic_task.retry_count == 1

    def test_retry_success_resets_status(self, basic_task):
        """Test retry() resets status to PENDING."""
        basic_task.status = TaskStatus.FAILED
        basic_task.retry()
        assert basic_task.status == TaskStatus.PENDING

    def test_retry_success_clears_assigned_agent(self, basic_task):
        """Test retry() clears assigned_agent."""
        basic_task.status = TaskStatus.FAILED
        basic_task.assigned_agent = "agent-001"
        basic_task.retry()
        assert basic_task.assigned_agent is None

    def test_retry_fails_when_cannot_retry(self, basic_task):
        """Test retry() returns False when can_retry is False."""
        basic_task.status = TaskStatus.FAILED
        basic_task.retry_count = 3
        basic_task.max_retries = 3
        result = basic_task.retry()
        assert result is False

    def test_retry_fails_when_not_failed(self, basic_task):
        """Test retry() returns False when not in FAILED status."""
        basic_task.status = TaskStatus.COMPLETED
        result = basic_task.retry()
        assert result is False


class TestTaskSerialization:
    """Tests for Task serialization methods."""

    def test_to_dict_all_fields(self, basic_task):
        """Test to_dict includes all fields."""
        data = basic_task.to_dict()
        expected_keys = [
            "id", "name", "task_type", "module", "operation", "options",
            "target", "targets", "priority", "status", "timeout",
            "retry_count", "max_retries", "assigned_agent", "created_at",
            "started_at", "completed_at", "result", "tags", "dependencies",
            "metadata"
        ]
        for key in expected_keys:
            assert key in data

    def test_to_dict_priority_is_int(self, basic_task):
        """Test priority is serialized as int."""
        data = basic_task.to_dict()
        assert data["priority"] == TaskPriority.NORMAL.value
        assert isinstance(data["priority"], int)

    def test_to_dict_status_is_string(self, basic_task):
        """Test status is serialized as string."""
        data = basic_task.to_dict()
        assert data["status"] == "pending"
        assert isinstance(data["status"], str)

    def test_to_dict_with_result(self, basic_task, sample_task_result):
        """Test to_dict with result present."""
        basic_task.result = sample_task_result
        data = basic_task.to_dict()
        assert data["result"] is not None
        assert isinstance(data["result"], dict)

    def test_from_dict_basic(self):
        """Test from_dict creates Task correctly."""
        data = {
            "id": "test-id",
            "name": "test-task",
            "task_type": "module",
            "module": "nmap",
            "operation": "scan",
            "options": {},
            "target": None,
            "targets": [],
            "priority": 2,
            "status": "pending",
            "timeout": 3600,
            "retry_count": 0,
            "max_retries": 3,
            "assigned_agent": None,
            "created_at": "2024-01-15T12:00:00",
            "started_at": None,
            "completed_at": None,
            "result": None,
            "tags": [],
            "dependencies": [],
            "metadata": {},
        }
        task = Task.from_dict(data)
        assert task.id == "test-id"
        assert task.name == "test-task"

    def test_from_dict_converts_enums(self):
        """Test from_dict converts priority/status to enums."""
        data = {
            "id": "test",
            "name": "test",
            "task_type": "module",
            "module": None,
            "operation": None,
            "options": {},
            "target": None,
            "targets": [],
            "priority": 3,
            "status": "running",
            "timeout": 3600,
            "retry_count": 0,
            "max_retries": 3,
            "assigned_agent": None,
            "created_at": "2024-01-15T12:00:00",
            "started_at": None,
            "completed_at": None,
            "result": None,
            "tags": [],
            "dependencies": [],
            "metadata": {},
        }
        task = Task.from_dict(data)
        assert task.priority == TaskPriority.HIGH
        assert task.status == TaskStatus.RUNNING

    def test_from_dict_converts_datetimes(self):
        """Test from_dict converts datetime strings."""
        data = {
            "id": "test",
            "name": "test",
            "task_type": "module",
            "module": None,
            "operation": None,
            "options": {},
            "target": None,
            "targets": [],
            "priority": 2,
            "status": "pending",
            "timeout": 3600,
            "retry_count": 0,
            "max_retries": 3,
            "assigned_agent": None,
            "created_at": "2024-01-15T10:00:00",
            "started_at": "2024-01-15T10:05:00",
            "completed_at": None,
            "result": None,
            "tags": [],
            "dependencies": [],
            "metadata": {},
        }
        task = Task.from_dict(data)
        assert isinstance(task.created_at, datetime)
        assert isinstance(task.started_at, datetime)
        assert task.created_at.hour == 10

    def test_from_dict_converts_nested_result(self):
        """Test from_dict converts nested result dict."""
        data = {
            "id": "test",
            "name": "test",
            "task_type": "module",
            "module": None,
            "operation": None,
            "options": {},
            "target": None,
            "targets": [],
            "priority": 2,
            "status": "completed",
            "timeout": 3600,
            "retry_count": 0,
            "max_retries": 3,
            "assigned_agent": None,
            "created_at": "2024-01-15T12:00:00",
            "started_at": None,
            "completed_at": None,
            "result": {
                "task_id": "test",
                "success": True,
                "data": {},
                "error": None,
                "execution_time": 1.0,
                "agent_id": None,
                "findings": [],
                "credentials": [],
                "services": [],
                "completed_at": "2024-01-15T12:00:00",
            },
            "tags": [],
            "dependencies": [],
            "metadata": {},
        }
        task = Task.from_dict(data)
        assert isinstance(task.result, TaskResult)
        assert task.result.success is True

    def test_to_json_from_json_roundtrip(self, basic_task):
        """Test to_json/from_json roundtrip."""
        json_str = basic_task.to_json()
        assert isinstance(json_str, str)
        # Should be valid JSON
        json.loads(json_str)

        restored = Task.from_json(json_str)
        assert restored.id == basic_task.id
        assert restored.name == basic_task.name
        assert restored.module == basic_task.module


# =============================================================================
# TaskQueue Tests
# =============================================================================

class TestTaskQueue:
    """Tests for TaskQueue class."""

    def test_init_empty(self, task_queue):
        """Test TaskQueue initializes empty."""
        assert task_queue._tasks == {}
        assert task_queue._queue == []

    def test_add_task(self, task_queue, basic_task):
        """Test adding a task to queue."""
        task_queue.add(basic_task)
        assert basic_task.id in task_queue._tasks
        assert basic_task.id in task_queue._queue

    def test_add_sets_queued_status(self, task_queue, basic_task):
        """Test add() sets task status to QUEUED."""
        task_queue.add(basic_task)
        assert basic_task.status == TaskStatus.QUEUED

    def test_remove_existing_task(self, task_queue, basic_task):
        """Test removing an existing task."""
        task_queue.add(basic_task)
        removed = task_queue.remove(basic_task.id)
        assert removed == basic_task
        assert basic_task.id not in task_queue._tasks
        assert basic_task.id not in task_queue._queue

    def test_remove_nonexistent_returns_none(self, task_queue):
        """Test removing non-existent task returns None."""
        removed = task_queue.remove("nonexistent-id")
        assert removed is None

    def test_get_existing_task(self, task_queue, basic_task):
        """Test getting an existing task."""
        task_queue.add(basic_task)
        retrieved = task_queue.get(basic_task.id)
        assert retrieved == basic_task

    def test_get_nonexistent_returns_none(self, task_queue):
        """Test getting non-existent task returns None."""
        retrieved = task_queue.get("nonexistent-id")
        assert retrieved is None

    def test_get_all_empty_queue(self, task_queue):
        """Test get_all on empty queue."""
        tasks = task_queue.get_all()
        assert tasks == []


class TestTaskQueuePriority:
    """Tests for TaskQueue priority ordering."""

    def test_add_respects_priority_order(self, task_queue):
        """Test tasks are ordered by priority."""
        low = Task(id="low", priority=TaskPriority.LOW)
        high = Task(id="high", priority=TaskPriority.HIGH)
        task_queue.add(low)
        task_queue.add(high)
        # High priority should be first
        assert task_queue._queue[0] == "high"
        assert task_queue._queue[1] == "low"

    def test_critical_inserted_before_low(self, task_queue):
        """Test CRITICAL priority is inserted before LOW."""
        low = Task(id="low", priority=TaskPriority.LOW)
        critical = Task(id="critical", priority=TaskPriority.CRITICAL)
        task_queue.add(low)
        task_queue.add(critical)
        assert task_queue._queue.index("critical") < task_queue._queue.index("low")

    def test_same_priority_fifo_order(self, task_queue):
        """Test same priority maintains FIFO order."""
        task1 = Task(id="first", priority=TaskPriority.NORMAL)
        task2 = Task(id="second", priority=TaskPriority.NORMAL)
        task_queue.add(task1)
        task_queue.add(task2)
        # First added should still be first (at same priority)
        assert task_queue._queue.index("first") < task_queue._queue.index("second")

    def test_get_next_returns_highest_priority(self, populated_task_queue):
        """Test get_next returns highest priority task."""
        task = populated_task_queue.get_next()
        assert task.id == "critical-1"

    def test_get_next_empty_queue_returns_none(self, task_queue):
        """Test get_next on empty queue returns None."""
        task = task_queue.get_next()
        assert task is None

    def test_multiple_priorities_correct_order(self, populated_task_queue):
        """Test queue maintains correct priority order."""
        # Get all tasks in order
        queue = populated_task_queue._queue
        tasks = [populated_task_queue.get(task_id) for task_id in queue]
        priorities = [t.priority.value for t in tasks if t]
        # Should be in descending order
        assert priorities == sorted(priorities, reverse=True)


class TestTaskQueueCapabilities:
    """Tests for TaskQueue capabilities filtering."""

    def test_get_next_no_capabilities_returns_any(self, populated_task_queue):
        """Test get_next without capabilities returns highest priority."""
        task = populated_task_queue.get_next(agent_capabilities=None)
        assert task is not None

    def test_get_next_with_matching_capability(self, task_queue):
        """Test get_next with matching capability."""
        task = Task(id="test", module="nmap", priority=TaskPriority.NORMAL)
        task_queue.add(task)
        result = task_queue.get_next(agent_capabilities=["nmap", "nikto"])
        assert result == task

    def test_get_next_skips_non_matching_capability(self, task_queue):
        """Test get_next skips tasks when capability doesn't match."""
        task = Task(id="test", module="metasploit", priority=TaskPriority.NORMAL)
        task_queue.add(task)
        result = task_queue.get_next(agent_capabilities=["nmap"])
        assert result is None

    def test_get_next_task_without_module_matches_any_capability(self, task_queue):
        """Test task without module matches any capability."""
        task = Task(id="test", module=None, priority=TaskPriority.NORMAL)
        task_queue.add(task)
        result = task_queue.get_next(agent_capabilities=["nmap"])
        assert result == task


class TestTaskQueueDependencies:
    """Tests for TaskQueue dependency handling."""

    def test_get_next_respects_dependencies(self, task_queue):
        """Test get_next respects dependency completion."""
        dep_task = Task(id="dep-1", module="recon")
        dependent = Task(id="main", module="exploit", dependencies=["dep-1"])

        task_queue.add(dep_task)
        task_queue.add(dependent)

        # Mark dependency as completed
        dep_task.status = TaskStatus.COMPLETED

        result = task_queue.get_next()
        # Now dependent task should be available (after dep is complete)
        # Note: get_next checks status == QUEUED, so we need the dep to be complete
        # and the main task to still be QUEUED
        assert result is not None

    def test_get_next_skips_incomplete_dependencies(self, task_queue):
        """Test get_next skips tasks with incomplete dependencies."""
        dep_task = Task(id="dep-1", module="recon")
        dependent = Task(id="main", module="exploit", dependencies=["dep-1"])

        task_queue.add(dep_task)
        task_queue.add(dependent)

        # dep_task is QUEUED (not COMPLETED), so dependent should be skipped
        # First call should return dep_task
        result = task_queue.get_next()
        assert result.id == "dep-1"

    def test_get_next_dependency_failed_blocks_task(self, task_queue):
        """Test failed dependency blocks dependent task."""
        dep_task = Task(id="dep-1", module="recon")
        dependent = Task(id="main", module="exploit", dependencies=["dep-1"])

        task_queue.add(dep_task)
        task_queue.add(dependent)

        dep_task.status = TaskStatus.FAILED

        # Get next should return None since dep-1 is failed and main is blocked
        result = task_queue.get_next()
        # The first task (dep-1) is FAILED not QUEUED, so it's skipped
        # The second task (main) has incomplete dep, so it's skipped
        assert result is None

    def test_get_next_dependency_not_in_queue(self, task_queue):
        """Test task with dependency not in queue is skipped."""
        dependent = Task(id="main", module="exploit", dependencies=["missing-dep"])
        task_queue.add(dependent)

        result = task_queue.get_next()
        assert result is None

    def test_get_next_all_dependencies_complete(self, task_queue):
        """Test task with all dependencies complete is returned."""
        dep1 = Task(id="dep-1", module="recon")
        dep2 = Task(id="dep-2", module="scan")
        dependent = Task(id="main", module="exploit", dependencies=["dep-1", "dep-2"])

        task_queue.add(dep1)
        task_queue.add(dep2)
        task_queue.add(dependent)

        # Complete all dependencies
        dep1.status = TaskStatus.COMPLETED
        dep2.status = TaskStatus.COMPLETED

        result = task_queue.get_next()
        assert result.id == "main"


class TestTaskQueueStatus:
    """Tests for TaskQueue status and count methods."""

    def test_get_all_with_status_filter(self, task_queue):
        """Test get_all with status filter."""
        task1 = Task(id="task1")
        task2 = Task(id="task2")
        task_queue.add(task1)
        task_queue.add(task2)

        # Both should be QUEUED now
        queued = task_queue.get_all(status=TaskStatus.QUEUED)
        assert len(queued) == 2

        # Change one status
        task1.status = TaskStatus.RUNNING

        queued = task_queue.get_all(status=TaskStatus.QUEUED)
        assert len(queued) == 1
        assert queued[0].id == "task2"

    def test_get_pending_count(self, task_queue):
        """Test get_pending_count."""
        task1 = Task(id="task1", status=TaskStatus.PENDING)
        task2 = Task(id="task2", status=TaskStatus.QUEUED)
        task3 = Task(id="task3", status=TaskStatus.RUNNING)

        task_queue._tasks = {
            "task1": task1,
            "task2": task2,
            "task3": task3,
        }

        count = task_queue.get_pending_count()
        # PENDING and QUEUED both count as pending
        assert count == 2

    def test_get_running_count(self, task_queue):
        """Test get_running_count."""
        task1 = Task(id="task1", status=TaskStatus.ASSIGNED)
        task2 = Task(id="task2", status=TaskStatus.RUNNING)
        task3 = Task(id="task3", status=TaskStatus.COMPLETED)

        task_queue._tasks = {
            "task1": task1,
            "task2": task2,
            "task3": task3,
        }

        count = task_queue.get_running_count()
        # ASSIGNED and RUNNING both count as running
        assert count == 2

    def test_clear_completed(self, task_queue):
        """Test clear_completed removes completed tasks."""
        task1 = Task(id="task1", status=TaskStatus.COMPLETED)
        task2 = Task(id="task2", status=TaskStatus.FAILED)
        task3 = Task(id="task3", status=TaskStatus.QUEUED)

        task_queue.add(task1)
        task_queue.add(task2)
        task_queue.add(task3)

        # Override statuses
        task1.status = TaskStatus.COMPLETED
        task2.status = TaskStatus.FAILED
        task3.status = TaskStatus.QUEUED

        cleared = task_queue.clear_completed()
        # COMPLETED and FAILED are both complete
        assert cleared == 2
        assert len(task_queue._tasks) == 1
        assert "task3" in task_queue._tasks


class TestTaskQueueEdgeCases:
    """Edge case tests for TaskQueue."""

    def test_task_with_both_target_and_targets(self):
        """Test task can have both target and targets."""
        task = Task(
            target="192.168.1.1",
            targets=["192.168.1.2", "192.168.1.3"],
        )
        assert task.target == "192.168.1.1"
        assert len(task.targets) == 2

    def test_task_with_empty_dependencies_list(self, task_queue):
        """Test task with empty dependencies list."""
        task = Task(id="test", dependencies=[])
        task_queue.add(task)
        result = task_queue.get_next()
        assert result == task

    def test_queue_task_status_changed_externally(self, task_queue):
        """Test get_next handles externally changed status."""
        task = Task(id="test")
        task_queue.add(task)
        task.status = TaskStatus.RUNNING  # Changed externally

        result = task_queue.get_next()
        assert result is None  # Should skip non-QUEUED tasks

    def test_task_with_max_retries_zero(self):
        """Test task with max_retries=0."""
        task = Task(max_retries=0, status=TaskStatus.FAILED)
        assert task.can_retry is False
        result = task.retry()
        assert result is False

    def test_task_large_options_dict(self):
        """Test task with large options dict."""
        options = {f"key_{i}": f"value_{i}" for i in range(1000)}
        task = Task(options=options)
        assert len(task.options) == 1000

    def test_queue_remove_task_not_in_queue_list(self, task_queue):
        """Test remove handles task in _tasks but not _queue."""
        task = Task(id="orphan")
        task_queue._tasks["orphan"] = task
        # Not in _queue

        removed = task_queue.remove("orphan")
        assert removed == task
        assert "orphan" not in task_queue._tasks

    def test_clear_completed_includes_cancelled(self, task_queue):
        """Test clear_completed removes cancelled tasks."""
        task = Task(id="cancelled", status=TaskStatus.CANCELLED)
        task_queue.add(task)
        task.status = TaskStatus.CANCELLED

        cleared = task_queue.clear_completed()
        assert cleared == 1
