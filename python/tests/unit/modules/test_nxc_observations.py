"""Adapter tests at the subprocess boundary, with synthetic NetExec line fixtures.

The legacy fixtures follow 1.3-era prefix/table/module layouts; modern tables
follow current NetExec source. They are representative samples, not tool-version
certification. No target is contacted and Framework.run_operation is not mocked.
"""

import ast
import inspect
import os
from pathlib import Path
import shutil
import subprocess
import textwrap
from unittest.mock import patch

import pytest

from purplesploit.core.execution import ExecutionRequest, normalize_observations
from purplesploit.modules.network.nxc_common import parse_nxc_output
from purplesploit.modules.network.nxc_ldap import NXCLDAPModule
from purplesploit.modules.network.nxc_mssql import NXCMSSQLModule
from purplesploit.modules.network.nxc_rdp import NXCRDPModule
from purplesploit.modules.network.nxc_smb import NXCSMBModule
from purplesploit.modules.network.nxc_ssh import NXCSSHModule
from purplesploit.modules.network.nxc_winrm import NXCWinRMModule


FIXTURES = Path(__file__).parents[2] / "fixtures" / "nxc"
ADAPTERS = (NXCSMBModule, NXCLDAPModule, NXCMSSQLModule, NXCRDPModule, NXCSSHModule, NXCWinRMModule)


def execute_fixture(adapter, framework, fixture, operation, **options):
    module = adapter(framework)
    for key, value in {"RHOST": "192.0.2.10", "USERNAME": "alice", "PASSWORD": "fixture-only", **options}.items():
        assert module.set_option(key, value)
    output = (FIXTURES / fixture).read_text()
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, output, "fixture stderr")) as process:
        with patch("builtins.input", side_effect=AssertionError("noninteractive operation prompted")):
            result = getattr(module, operation)()
    argv = process.call_args.args[0]
    assert isinstance(argv, list)
    assert process.call_args.kwargs["shell"] is False
    assert result["stdout"] == output
    assert result["stderr"] == "fixture stderr"
    assert result["returncode"] == 0
    assert result["execution"]["exit_code"] == 0
    request = ExecutionRequest(module_path=f"network/{adapter.__name__}", operation_name=operation)
    normalized = normalize_observations(result, request)
    assert len(normalized) == len(result["observations"])
    assert all(item.source_execution_id == request.request_id for item in normalized)
    return result, argv


def records(result, kind):
    return [item["attributes"] for item in result["observations"] if item["kind"] == kind]


@pytest.mark.parametrize("adapter,fixture,operation", [
    (NXCSMBModule, "smb_legacy.txt", "op_test_auth"),
    (NXCLDAPModule, "ldap_modern.txt", "op_enum_users"),
    (NXCMSSQLModule, "mssql.txt", "op_test_auth"),
    (NXCRDPModule, "rdp.txt", "op_test_auth"),
    (NXCSSHModule, "ssh.txt", "op_test_auth"),
    (NXCWinRMModule, "winrm.txt", "op_test_auth"),
])
def test_auth_and_hosts_cross_protocol(adapter, fixture, operation, mock_framework_minimal):
    result, _ = execute_fixture(adapter, mock_framework_minimal, fixture, operation)
    assert records(result, "host")
    assert records(result, "service")
    identity = records(result, "identity")[0]
    assert identity["username"] == "alice"
    assert identity["authenticated"] is (adapter is not NXCMSSQLModule)
    assert "fixture-only" not in repr(result["observations"])
    if adapter is NXCMSSQLModule:
        assert len(records(result, "identity")) == 1  # "Error:" is not a login.
        assert identity["status"] == "STATUS_LOGON_FAILURE"


def test_smb_legacy_full_enumeration(mock_framework_minimal):
    result, argv = execute_fixture(NXCSMBModule, mock_framework_minimal, "smb_legacy.txt", "op_full_enum")
    assert "--users" in argv
    assert {user["name"] for user in records(result, "user")} == {"alice", "svc_backup"}
    assert {group["name"]: group["member_count"] for group in records(result, "group")} == {"Domain Admins": 2}
    shares = {share["name"]: share for share in records(result, "share")}
    assert shares["C$"]["permissions"] == ["READ", "WRITE"]
    assert shares["Public"]["readable"] and not shares["Public"]["writable"]
    assert shares["Restricted"]["permissions"] == []
    assert {session["username"] for session in records(result, "session")} == {"alice", "bob"}
    assert next(session for session in records(result, "session") if session["username"] == "alice")["client"] == "192.0.2.20"
    logged_on = next(session for session in records(result, "session") if session["username"] == "bob")
    assert logged_on["logged_on"] is True
    assert logged_on["logon_server"] == "DC01"
    policy = {item["name"]: item["value"] for item in records(result, "policy")}
    assert policy["minimum_password_length"] == 12
    assert policy["account_lockout_threshold"] == 5
    assert policy["maximum_password_age"] == "42 days"
    assert {identity["authenticated"] for identity in records(result, "identity")} == {True, False}
    assert {item["target"] for item in result["observations"] if item["kind"] == "host"} == {"192.0.2.10", "192.0.2.11"}


def test_ldap_modern_users_and_groups(mock_framework_minimal):
    result, _ = execute_fixture(NXCLDAPModule, mock_framework_minimal, "ldap_modern.txt", "op_enum_users")
    assert {item["name"] for item in records(result, "user")} == {"alice", "krbtgt"}
    groups = {item["name"]: item for item in records(result, "group")}
    assert groups["Domain Admins"]["member_count"] == 2
    assert groups["Domain Users"]["description"] == "All users"
    policy = {item["name"]: item["value"] for item in records(result, "policy")}
    assert policy["signing"] is True
    assert policy["channel_binding"] == "always"


def test_smb_modern_share_permissions(mock_framework_minimal):
    result, _ = execute_fixture(NXCSMBModule, mock_framework_minimal, "smb_modern.txt", "op_list_shares")
    shares = {item["name"]: item for item in records(result, "share")}
    assert shares["Drop"]["permissions"] == ["WRITE (SUBDIR)"]
    assert shares["Drop"]["writable"] and not shares["Drop"]["readable"]
    assert shares["Public"]["permissions"] == ["READ", "WRITE (ACL)"]
    assert shares["Public"]["writable"] and shares["Public"]["readable"]


@pytest.mark.parametrize("fixture,operation,kind,name", [
    ("ldap_computers.txt", "op_enum_computers", "computer", "DC01$"),
    ("ldap_trusts_legacy.txt", "op_enum_trusts", "domain", "partner.test"),
    ("ldap_trusts_query.txt", "op_enum_trusts", "domain", "partner.test"),
    ("ldap_adcs.txt", "op_adcs", "resource", "CORP-CA"),
    ("ldap_signing_legacy.txt", "op_ldap_signing", "policy", "signing"),
])
def test_ldap_objects(fixture, operation, kind, name, mock_framework_minimal):
    result, _ = execute_fixture(NXCLDAPModule, mock_framework_minimal, fixture, operation)
    item = next(item for item in records(result, kind) if item["name"] == name)
    if kind == "policy":
        assert item["value"] is False
    if fixture == "ldap_trusts_legacy.txt":
        assert item["relationship"] == "trust"
        assert item["direction"] == "bidirectional"
    if fixture == "ldap_trusts_query.txt":
        assert item["direction"] == "bidirectional"
        assert item["trust_attributes"] == 32
        legacy = next(item for item in records(result, "domain") if item["name"] == "legacy.test")
        assert legacy["direction"] == "inbound"
    if kind == "resource":
        assert len(records(result, "resource")) == 4


@pytest.mark.parametrize("adapter,fixture,names", [
    (NXCSSHModule, "ssh.txt", {"root", "alice"}),
    (NXCWinRMModule, "winrm.txt", {"Administrator", "alice", "Guest"}),
])
def test_command_user_enumeration(adapter, fixture, names, mock_framework_minimal):
    result, _ = execute_fixture(adapter, mock_framework_minimal, fixture, "op_users")
    assert {user["name"] for user in records(result, "user")} == names


def test_rdp_status_is_unauthenticated_and_parses_nla(mock_framework_minimal):
    result, argv = execute_fixture(NXCRDPModule, mock_framework_minimal, "rdp.txt", "op_nla")
    assert "-u" not in argv and "-p" not in argv and "-H" not in argv
    assert {item["name"]: item["value"] for item in records(result, "policy")}["nla"] is True
    assert any(item["target"] == "2001:db8::10" for item in result["observations"])


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_argv_preserves_credentials_and_domain(adapter, mock_framework_minimal):
    module = adapter(mock_framework_minimal)
    credentials = {"RHOST": "target with spaces", "USERNAME": "u'\";$(id)", "PASSWORD": "p'\";$(touch /tmp/never)\\!"}
    if "DOMAIN" in module.options:
        credentials["DOMAIN"] = "corp's domain"
    for key, value in credentials.items():
        assert module.set_option(key, value)
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as process:
        module.op_test_auth() if hasattr(module, "op_test_auth") else module.op_enum_users()
    argv = process.call_args.args[0]
    for key, flag in (("USERNAME", "-u"), ("PASSWORD", "-p"), ("DOMAIN", "-d")):
        if key in credentials:
            assert argv[argv.index(flag) + 1] == credentials[key]
    assert argv[2] == credentials["RHOST"]


def test_smb_configured_hash_and_spider_no_prompts(mock_framework_minimal):
    module = NXCSMBModule(mock_framework_minimal)
    for key, value in {"RHOST": "192.0.2.10", "USERNAME": "alice", "HASH": "aad3:1234", "PASSWORD": "ignored"}.items():
        assert module.set_option(key, value)
    assert "HASH" in module.parameters
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as process:
        with patch("builtins.input", side_effect=AssertionError("prompt")):
            module.op_pass_the_hash_configured()
            argv = process.call_args.args[0]
            assert argv[argv.index("-H") + 1] == "aad3:1234"
            assert "-p" not in argv
            module.set_option("SPIDER_SHARE", "Bob's Share")
            module.set_option("SPIDER_PATTERN", "*.txt;$(id)")
            module.op_spider_configured()
            argv = process.call_args.args[0]
            assert "DOWNLOAD_FLAG=False" in argv
            assert "SHARE=Bob's Share" in argv
            assert "PATTERN=*.txt;$(id)" in argv


def test_smb_configured_hash_rejects_missing_values(mock_framework_minimal):
    module = NXCSMBModule(mock_framework_minimal)
    with patch("subprocess.run") as process, patch("builtins.input", side_effect=AssertionError("prompt")):
        assert not module.op_pass_the_hash_configured()["success"]
        module.set_option("HASH", "aad3:1234")
        assert not module.op_pass_the_hash_configured()["success"]
    process.assert_not_called()


@pytest.mark.parametrize("adapter", ADAPTERS)
def test_manifests_describe_prompts_and_requirements(adapter, mock_framework_minimal):
    module = adapter(mock_framework_minimal)
    operations = module.get_operations()
    assert len({operation["id"] for operation in operations}) == len(operations)
    for operation in operations:
        assert {"id", "interactive", "background", "requires", "optional", "emits", "tool"} <= operation.keys()
        assert operation["tool"] == "nxc"
        assert operation["background"] is False
        assert "RHOST" in operation["requires"]
        assert not set(operation["requires"]) & set(operation["optional"])
        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(module, operation["handler"]))))
        prompts = any(isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input" for node in ast.walk(tree))
        assert operation["interactive"] is prompts


def test_unknown_failure_and_ansi_are_not_invented_as_objects():
    output = "\x1b[31mLDAP 192.0.2.10 389 DC01 [-] Error: denied\x1b[0m\nnot a record\n"
    result = parse_nxc_output(output, "ldap", ["--users"], username="alice")
    assert result == []  # A prefixed connection error does not prove an open port.
    assert parse_nxc_output("arbitrary unknown output", "smb") == []


@pytest.mark.parametrize("adapter,fixture,operation", [
    (NXCSMBModule, "smb_legacy.txt", "op_full_enum"),
    (NXCLDAPModule, "ldap_trusts_query.txt", "op_enum_trusts"),
    (NXCMSSQLModule, "mssql.txt", "op_test_auth"),
    (NXCRDPModule, "rdp.txt", "op_nla"),
    (NXCSSHModule, "ssh.txt", "op_users"),
    (NXCWinRMModule, "winrm.txt", "op_users"),
])
def test_actual_fixture_process(adapter, fixture, operation, tmp_path, monkeypatch, mock_framework_minimal):
    """Run the real shell-free subprocess path against an inert nxc stand-in."""
    executable = tmp_path / "nxc"
    shutil.copyfile(FIXTURES / "fixture_driver.py", executable)
    executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("NXC_FIXTURE_PATH", str(FIXTURES / fixture))
    module = adapter(mock_framework_minimal)
    module.set_option("RHOST", "192.0.2.10")
    module.set_option("USERNAME", "alice")
    with patch("builtins.input", side_effect=AssertionError("prompt")):
        result = getattr(module, operation)()
    assert result["success"]
    assert result["stdout"] == (FIXTURES / fixture).read_text()
    assert result["stderr"] == "fixture stderr"
    assert records(result, "host") and records(result, "service")
    if adapter is NXCSMBModule:
        assert records(result, "share")
    elif adapter is NXCLDAPModule:
        assert any(item.get("relationship") == "trust" for item in records(result, "domain"))
    elif adapter is NXCRDPModule:
        assert any(item["name"] == "nla" for item in records(result, "policy"))
    elif adapter in (NXCSSHModule, NXCWinRMModule):
        assert records(result, "user")
