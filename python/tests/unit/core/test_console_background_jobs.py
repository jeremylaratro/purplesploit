"""Hermetic coverage for console-launched background process tracking."""

import json
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from purplesploit.core.execution import (
    ExecutionOutcome,
    ExecutionRequest,
    ExecutionResult,
)
from purplesploit.core.framework import Framework


def bare_framework() -> Framework:
    """Build only the registry seam, without database or plugin initialization."""
    framework = Framework.__new__(Framework)
    framework._background_jobs = {}
    return framework


def background_result(process: subprocess.Popen, request_id: str) -> dict:
    execution = ExecutionResult(
        request_id=request_id,
        outcome=ExecutionOutcome.RUNNING,
        module_path="recon/nmap",
        operation_name="Fast Scan",
        argv_display=["fixture-tool", "[redacted]"],
        pid=process.pid,
        tool="nmap",
        finished_at=None,
    ).to_dict()
    return {
        "success": False,
        "background": True,
        "message": "Command running in background",
        "note": "Import fixture.xml after completion.",
        "execution": execution,
    }


def reap_until_settled(framework: Framework, timeout: float = 3.0) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        entry = framework.reap_background()[0]
        if entry["status"] != "running":
            return entry
        time.sleep(0.01)
    pytest.fail("background fixture did not settle")


def test_register_background_stamps_job_id_and_deduplicates_request():
    framework = bare_framework()
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    results = background_result(process, "request-register")

    returned = framework.register_background(
        SimpleNamespace(background_process=process), results
    )
    job_id = returned["execution"]["job_id"]

    assert job_id.startswith("bg-")
    assert len(job_id) == 11
    assert len(framework._background_jobs) == 1
    assert framework.background_jobs()[0]["id"] == job_id
    assert framework.register_background(
        SimpleNamespace(background_process=process), results
    ) is results
    assert len(framework._background_jobs) == 1
    process.wait(timeout=3)


@pytest.mark.parametrize(
    ("exit_code", "expected_status"),
    [(0, "finished"), (3, "failed")],
)
def test_reap_background_reaps_and_records_exit(exit_code, expected_status):
    framework = bare_framework()
    process = subprocess.Popen(
        [sys.executable, "-c", f"import sys; sys.exit({exit_code})"]
    )
    results = background_result(process, f"request-exit-{exit_code}")
    framework.register_background(SimpleNamespace(background_process=process), results)

    entry = reap_until_settled(framework)

    assert entry["status"] == expected_status
    assert entry["exit_code"] == exit_code
    assert entry["finished_at"] is not None
    assert process.returncode == exit_code
    assert process.poll() == exit_code


def test_background_snapshot_is_json_serializable_and_excludes_handle():
    framework = bare_framework()
    process = subprocess.Popen([sys.executable, "-c", "pass"])
    framework.register_background(
        SimpleNamespace(background_process=process),
        background_result(process, "request-json"),
    )

    snapshot = reap_until_settled(framework)

    assert "_handle" not in snapshot
    assert snapshot["note"] == "Import fixture.xml after completion."
    json.dumps([snapshot])


def test_stop_background_cancels_process_without_resurrection():
    framework = bare_framework()
    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(5)"]
    )
    results = background_result(process, "request-stop")
    framework.register_background(SimpleNamespace(background_process=process), results)
    job_id = results["execution"]["job_id"]

    try:
        stopped = framework.stop_background(job_id)

        assert stopped["status"] == "cancelled"
        assert stopped["finished_at"] is not None
        deadline = time.monotonic() + 3
        while process.returncode is None and time.monotonic() < deadline:
            snapshot = framework.reap_background()[0]
            assert snapshot["status"] == "cancelled"
            time.sleep(0.01)
        assert process.returncode is not None
        assert framework.reap_background()[0]["status"] == "cancelled"
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=3)


def test_non_background_result_is_untouched():
    framework = bare_framework()
    results = {
        "execution": ExecutionResult(
            request_id="request-complete",
            outcome=ExecutionOutcome.SUCCESS,
            job_id="existing-job",
        ).to_dict()
    }

    returned = framework.register_background(SimpleNamespace(), results)

    assert returned is results
    assert results["execution"]["job_id"] == "existing-job"
    assert framework._background_jobs == {}


@pytest.mark.parametrize(
    "module,results",
    [
        (SimpleNamespace(), {}),
        (
            SimpleNamespace(),
            {
                "execution": ExecutionResult(
                    request_id="request-missing-process",
                    outcome=ExecutionOutcome.RUNNING,
                ).to_dict()
            },
        ),
    ],
)
def test_registration_errors_degrade_to_unchanged_result(module, results):
    framework = bare_framework()

    assert framework.register_background(module, results) is results
    assert framework._background_jobs == {}


def test_run_module_and_operation_register_completed_background_results():
    framework = bare_framework()
    framework._begin_module_execution = MagicMock()
    framework._complete_module_results = MagicMock(
        side_effect=lambda _module, results: results
    )
    framework.register_background = MagicMock(
        side_effect=lambda _module, results: results
    )
    framework.log = MagicMock()
    module = MagicMock()
    module.name = "Fixture"
    module.auto_set_from_context.return_value = None
    module.validate_options.return_value = (True, "")
    module.run.return_value = {"execution": {"outcome": "running"}}

    framework.run_module(module)
    framework.register_background.assert_called_once_with(
        module, {"execution": {"outcome": "running"}}
    )

    framework.register_background.reset_mock()
    operation_result = {"execution": {"outcome": "running"}}
    operation = {"handler": MagicMock(return_value=operation_result)}
    framework.run_operation(module, operation)
    framework.register_background.assert_called_once_with(module, operation_result)


def test_execute_request_keeps_background_registry_out_of_services_lane():
    framework = bare_framework()
    module = MagicMock()
    module.options = {}
    framework.instantiate_module = MagicMock(return_value=module)
    result = ExecutionResult(
        request_id="services-request",
        outcome=ExecutionOutcome.SUCCESS,
        success=True,
    ).to_dict()
    framework.run_module = MagicMock(return_value={"execution": result})

    execution = framework.execute_request(ExecutionRequest("fixture/module"))

    assert execution.outcome is ExecutionOutcome.SUCCESS
    framework.run_module.assert_called_once_with(
        module, _register_background=False
    )
    assert framework._background_jobs == {}

