"""Console seams for listing, inspecting, stopping, and opportunistic reaping."""

from types import SimpleNamespace
from unittest.mock import MagicMock

from purplesploit.ui.commands import CommandHandler


def handler(framework=None, services=None):
    instance = CommandHandler.__new__(CommandHandler)
    instance.framework = framework or MagicMock()
    instance.services = services
    instance.display = MagicMock()
    return instance


def background_job(status="running"):
    return {
        "id": "bg-12345678",
        "kind": "bg-scan",
        "status": status,
        "pid": 4321,
        "module_path": "recon/nmap",
    }


def test_cmd_run_reaps_on_entry_even_without_a_loaded_module():
    framework = MagicMock()
    framework.session = SimpleNamespace(current_module=None)
    command_handler = handler(framework)

    assert command_handler.cmd_run([])

    framework.reap_background.assert_called_once_with()
    command_handler.display.print_error.assert_called_once()


def test_jobs_list_combines_shared_and_background_jobs():
    framework = MagicMock()
    framework.reap_background.return_value = [background_job()]
    services = MagicMock()
    services.job_list.return_value = [
        {
            "id": "shared-1",
            "kind": "workflow",
            "status": "running",
            "outcome": None,
        }
    ]
    command_handler = handler(framework, services)

    assert command_handler.cmd_jobs(["list"])

    framework.reap_background.assert_called_once_with()
    services.job_list.assert_called_once_with()
    lines = [call.args[0] for call in command_handler.display.console.print.call_args_list]
    assert any("shared-1  workflow  running" in line for line in lines)
    assert any(
        "bg-12345678  bg-scan  running  running  pid=4321  recon/nmap" in line
        for line in lines
    )
    command_handler.display.print_warning.assert_not_called()


def test_jobs_list_without_services_still_shows_background_jobs():
    framework = MagicMock()
    framework.reap_background.return_value = [background_job("finished")]
    command_handler = handler(framework)

    assert command_handler.cmd_jobs([])

    command_handler.display.print_error.assert_not_called()
    command_handler.display.print_warning.assert_not_called()
    line = command_handler.display.console.print.call_args.args[0]
    assert "finished  success" in line


def test_background_status_and_stop_bypass_shared_services():
    framework = MagicMock()
    framework.reap_background.return_value = [background_job()]
    framework.stop_background.return_value = background_job("cancelled")
    services = MagicMock()
    command_handler = handler(framework, services)

    assert command_handler.cmd_jobs(["status", "bg-12345678"])
    command_handler.display.console.print_json.assert_called_with(
        data=background_job()
    )
    services.job_get.assert_not_called()

    assert command_handler.cmd_jobs(["stop", "bg-12345678"])
    framework.stop_background.assert_called_once_with("bg-12345678")
    services.job_control.assert_not_called()


def test_jobs_list_only_reports_empty_when_both_sources_are_empty():
    framework = MagicMock()
    framework.reap_background.return_value = []
    services = MagicMock()
    services.job_list.return_value = []
    command_handler = handler(framework, services)

    assert command_handler.cmd_jobs(["list"])

    command_handler.display.print_warning.assert_called_once_with("No jobs")

