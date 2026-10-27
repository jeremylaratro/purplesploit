"""Golden parser records and real child-process boundaries for web adapters."""

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from purplesploit.core.execution import ExecutionRequest, normalize_observations
from purplesploit.modules.recon.nuclei import NucleiModule
from purplesploit.modules.web.feroxbuster import FeroxbusterModule
from purplesploit.modules.web.forms import HTMLFormsModule
from purplesploit.modules.web.httpx import HTTPxModule
from purplesploit.modules.web.sqlmap import SQLMapModule
from purplesploit.modules.web.wfuzz import WfuzzModule
from purplesploit.modules.web.wpscan import WPScanModule
from purplesploit.web_observations import parse_html_forms


FIXTURES = Path(__file__).parents[2] / "fixtures"
TARGET = "https://app.example:8443"
ADAPTERS = [(HTTPxModule, "TARGET", "run", {"service", "http_endpoint", "technology"}),
            (FeroxbusterModule, "URL", "op_basic_scan", {"path", "http_endpoint"}),
            (NucleiModule, "TARGET", "op_critical_high", {"finding"}),
            (SQLMapModule, "URL", "run", {"parameter", "finding"}),
            (WfuzzModule, "TARGET", "op_dir_fuzz", {"path", "http_endpoint"}),
            (WPScanModule, "URL", "op_full_scan", {"user", "technology", "finding"})]


@pytest.fixture
def process_tools(tmp_path, monkeypatch):
    """Run executable fixture CLIs, keeping the actual adapters and subprocess runner."""
    tool_dir = tmp_path / "bin"
    tool_dir.mkdir()
    script = tool_dir / "recorded-web-cli"
    script.write_text("""#!/usr/bin/env python3
import json, os, pathlib, sys
tool = pathlib.Path(sys.argv[0]).name
output = json.loads(pathlib.Path(os.environ['WEB_GOLDEN']).read_text())[tool]
pathlib.Path(os.environ['WEB_ARGV']).write_text(json.dumps(sys.argv))
if '-o' in sys.argv:
    pathlib.Path(sys.argv[sys.argv.index('-o') + 1]).write_text(output)
sys.stdout.write(output)
sys.stderr.write('recorded fixture diagnostics\\n')
sys.exit(int(os.environ.get('WEB_EXIT', '0')))
""", encoding="utf-8")
    script.chmod(0o755)
    for name in ("httpx", "feroxbuster", "nuclei", "sqlmap", "wfuzz", "wpscan"):
        (tool_dir / name).symlink_to(script.name)
    monkeypatch.setenv("PATH", str(tool_dir) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("WEB_GOLDEN", str(FIXTURES / "web_assessment.json"))
    monkeypatch.setenv("WEB_ARGV", str(tmp_path / "argv.json"))
    monkeypatch.setattr("builtins.input", lambda *args: pytest.fail("unexpected prompt"))
    return tmp_path


def make_module(cls, tmp_path):
    framework = SimpleNamespace(log=lambda *args: None)
    module = cls(framework)
    module.execution_request = ExecutionRequest(module_path=cls.__module__,
        run_dir=str(tmp_path / cls.__name__), timeout_s=10)
    return module


@pytest.mark.parametrize("cls,option,handler,kinds", ADAPTERS)
def test_real_adapter_process_observations_and_raw_streams(process_tools, cls, option, handler, kinds):
    module = make_module(cls, process_tools)
    module.set_option(option, TARGET + ("/item?id=1" if cls is SQLMapModule else ""))
    result = getattr(module, handler)()
    assert result["success"], result
    assert {item["kind"] for item in result["observations"]} >= kinds
    argv = json.loads((process_tools / "argv.json").read_text())
    assert "None" not in argv
    assert Path(result["execution"]["stdout_ref"]).read_text() == result["stdout"]
    assert "recorded fixture diagnostics" in Path(result["execution"]["stderr_ref"]).read_text()
    normalized = normalize_observations(result, module.execution_request)
    assert all(item.source_execution_id == module.execution_request.request_id for item in normalized)
    assert all(not item["interactive"] and item["emits"] for item in module.get_operation_manifest())


def test_httpx_fields_are_not_confused_with_technology(process_tools):
    module = make_module(HTTPxModule, process_tools)
    module.set_option("TARGET", TARGET)
    result = module.run()
    endpoint = next(item for item in result["observations"] if item["kind"] == "http_endpoint")
    assert endpoint["port"] == 8443
    assert endpoint["attributes"]["status"] == 200
    assert endpoint["attributes"]["title"] == "Sign in"
    assert endpoint["attributes"]["webserver"] == "nginx/1.24"
    assert result["parsed"]["technologies"] == ["PHP:8.2", "nginx:1.24"]


def test_target_argv_preserves_apostrophes_and_shell_metacharacters(process_tools):
    target = TARGET + "/item?id=1&name=O'Reilly;$(touch SHOULD_NOT_EXIST)"
    module = make_module(SQLMapModule, process_tools)
    module.set_option("URL", target)
    module.set_option("COOKIE", "sid=O'Reilly; $(touch SHOULD_NOT_EXIST)")
    module.run()
    argv = json.loads((process_tools / "argv.json").read_text())
    assert argv[argv.index("-u") + 1] == target
    assert "--cookie=sid=O'Reilly; $(touch SHOULD_NOT_EXIST)" in argv
    assert not (process_tools / "SQLMapModule" / "SHOULD_NOT_EXIST").exists()


def test_failed_process_keeps_partial_observations_and_diagnostics(process_tools, monkeypatch):
    monkeypatch.setenv("WEB_EXIT", "3")
    module = make_module(NucleiModule, process_tools)
    module.set_option("TARGET", TARGET)
    result = module.run()
    assert not result["success"]
    assert result["execution"]["exit_code"] == 3
    assert result["observations"][0]["attributes"]["template_id"] == "test-panel"
    assert result["parsed"]["finding_records"][0]["module_name"] == "nuclei"


@pytest.mark.parametrize("flag", ["-json", "-jsonl"])
def test_nuclei_legacy_and_current_output_flags(process_tools, flag):
    module = make_module(NucleiModule, process_tools)
    module.set_option("TARGET", TARGET)
    module.set_option("JSON_FLAG", flag)
    result = module.run()
    assert result["summary"]["medium"] == 1
    assert flag in json.loads((process_tools / "argv.json").read_text())


def test_nuclei_json_array_and_malformed_line_diagnostics(tmp_path):
    module = make_module(NucleiModule, tmp_path)
    raw = json.loads((FIXTURES / "web_assessment.json").read_text())["nuclei"]
    assert module.parse_output(json.dumps([json.loads(raw)]))["summary"]["total"] == 1
    parsed = module.parse_output(raw + "not-json\n")
    assert len(parsed["observations"]) == 1
    assert parsed["parse_errors"][0]["line"] == 2


def test_feroxbuster_parsed_alias_and_noninteractive_options(process_tools):
    module = make_module(FeroxbusterModule, process_tools)
    assert module.op_custom_wordlist()["error"] == "WORDLIST required"
    module.set_option("URL", TARGET)
    result = module.run()
    assert result["parsed"] == result["parsed_results"]
    assert result["parsed"]["found_paths"][0]["path"] == "/admin"
    assert not module.op_custom_scan()["success"]


@pytest.mark.parametrize("handler,location", [("op_param_get_fuzz", "query"), ("op_param_post_fuzz", "body")])
def test_wfuzz_parameter_response_observations(process_tools, handler, location):
    module = make_module(WfuzzModule, process_tools)
    module.set_option("TARGET", TARGET)
    result = getattr(module, handler)()
    parameter = next(item for item in result["observations"] if item["kind"] == "parameter")
    assert parameter["attributes"]["name"] == "admin"
    assert parameter["attributes"]["location"] == location
    assert parameter["attributes"]["status"] == "200"


def test_recorded_form_import_emits_action_method_and_named_parameters(tmp_path):
    html = (FIXTURES / "web_forms.html").read_text()
    parsed = parse_html_forms(html, TARGET + "/login")
    assert parsed["forms_found"]
    assert len(parsed["forms"]) == 2
    assert parsed["forms"][0]["action"] == TARGET + "/account/session"
    assert parsed["forms"][0]["method"] == "POST"
    assert {item["name"] for item in parsed["forms"][0]["parameters"]} >= {"username", "password", "csrf", "remember"}
    module = make_module(HTMLFormsModule, tmp_path)
    module.set_option("URL", TARGET + "/login")
    module.set_option("HTML_FILE", str(FIXTURES / "web_forms.html"))
    assert module.run()["observations"] == parsed["observations"]
    assert {item["kind"] for item in parsed["observations"]} == {"form", "parameter"}
