"""The production CLI submits long-running work through shared services."""

from unittest.mock import MagicMock, patch

from purplesploit.ui.commands import CommandHandler


def handler_with_services():
    framework = MagicMock()
    framework.session.targets.get_current.return_value = {"ip": "192.0.2.10"}
    framework.session.credentials.list.return_value = []
    services = MagicMock()
    services.workflows = MagicMock()
    services.run_workflow.return_value = {"id": "workflow-job"}
    services.run_auto_enum.return_value = {"id": "auto-job"}
    services.run_spray.return_value = {"id": "spray-job"}
    services.job_get.return_value = {
        "id": "workflow-job",
        "kind": "workflow",
        "status": "running",
        "outcome": None,
        "progress": {},
    }
    services.job_control.return_value = {
        "id": "workflow-job",
        "status": "pausing",
    }
    with patch("purplesploit.ui.commands.Display"), patch(
        "purplesploit.ui.commands.InteractiveSelector"
    ):
        handler = CommandHandler(framework, services=services)
    handler.display = MagicMock()
    return handler, services


def test_workflow_and_job_controls_use_shared_service():
    handler, services = handler_with_services()

    assert handler.cmd_workflow(
        ["run", "workflow-1", "--target", "192.0.2.10"]
    )
    services.run_workflow.assert_called_once_with(
        "workflow-1", variables={"target": "192.0.2.10"}
    )

    assert handler.cmd_workflow(["pause", "workflow-1"])
    services.job_control.assert_called_with("workflow-job", "pause")
    assert handler.cmd_workflow(["stop", "workflow-1"])
    services.job_control.assert_called_with("workflow-job", "stop")
    assert handler.cmd_jobs(["status", "workflow-job"])
    services.job_get.assert_called_with("workflow-job")


def test_auto_enum_and_spray_submit_nonblocking_jobs():
    handler, services = handler_with_services()

    assert handler.cmd_auto(
        ["192.0.2.10", "--scope", "light", "--parallel"]
    )
    services.run_auto_enum.assert_called_once_with(
        targets=["192.0.2.10"],
        scope="light",
        phases=None,
        parallel=True,
    )

    assert handler.cmd_spray(
        [
            "192.0.2.10",
            "-u",
            "alice",
            "-p",
            "Fixture1!",
            "--protocol",
            "smb",
        ]
    )
    services.run_spray.assert_called_once_with(
        targets=["192.0.2.10"],
        users=["alice"],
        passwords=["Fixture1!"],
        protocol="smb",
        pattern="breadth_first",
        domain=None,
        delay=0.0,
        jitter=0.0,
        stop_on_success=False,
    )
    assert handler.cmd_spray(["stop"])
    services.job_control.assert_called_with("spray-job", "stop")
