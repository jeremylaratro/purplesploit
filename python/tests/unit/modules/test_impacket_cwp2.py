"""CWP2 fixtures at the subprocess boundary; no live authentication."""

import json
import os
from pathlib import Path
import shlex
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from purplesploit.core.execution import ExecutionRequest, normalize_observations
from purplesploit.modules.ad.kerbrute import KerbruteModule
from purplesploit.modules.impacket.asreproast import ImpacketASREPRoastModule
from purplesploit.modules.impacket.kerberoast import ImpacketKerberoastModule
from purplesploit.modules.impacket.psexec import ImpacketPSExecModule
from purplesploit.modules.impacket.secretsdump import ImpacketSecretsDumpModule
from purplesploit.modules.impacket.smbclient import ImpacketSMBClientModule
from purplesploit.modules.impacket.wmiexec import ImpacketWMIExecModule


FIXTURES = json.loads((Path(__file__).parents[2] / "fixtures" / "impacket_cwp2.json").read_text())
ADAPTERS = {
    "asrep": ImpacketASREPRoastModule, "tgs": ImpacketKerberoastModule,
    "secrets": ImpacketSecretsDumpModule, "shares": ImpacketSMBClientModule,
    "psexec": ImpacketPSExecModule, "wmiexec": ImpacketWMIExecModule,
}


def configured(adapter):
    module = adapter(MagicMock())
    for key, value in {"RHOST": "192.0.2.10", "DOMAIN": "CORP.LOCAL", "USERNAME": "alice",
                       "PASSWORD": "Password:with spaces;$(id)"}.items():
        if key in module.options:
            module.set_option(key, value)
    return module


@pytest.mark.parametrize("name", ADAPTERS)
def test_process_fixture_observations_and_argv(name):
    module = configured(ADAPTERS[name])
    fixture = FIXTURES[name]
    module.set_option("COMMAND", "shares" if name == "shares" else "whoami")
    with patch.object(module, "check_tool_installed", return_value=True), patch(
        "subprocess.run", return_value=subprocess.CompletedProcess([], fixture["returncode"], fixture["stdout"], fixture["stderr"])
    ) as process:
        result = module.run()
    argv = process.call_args.args[0]
    assert isinstance(argv, list)
    assert process.call_args.kwargs["shell"] is False
    assert "Password:with spaces;$(id)" in argv[1]
    assert result["stdout"] == fixture["stdout"]
    observations = normalize_observations(result, ExecutionRequest(module_path=module.__class__.__module__))
    assert set(fixture["kinds"]) <= {item.kind for item in observations}
    assert all("Password:" not in item.target for item in observations)
    assert all(item.source_execution_id for item in observations)
    assert module.get_operation_manifest()[0]["emits"]


@pytest.mark.parametrize("adapter", ADAPTERS.values())
def test_legacy_preview_roundtrips_argv(adapter):
    module = configured(adapter)
    assert shlex.split(module.build_command()) == module.build_argv()


@pytest.mark.parametrize("adapter", [ImpacketASREPRoastModule, ImpacketKerberoastModule])
def test_dc_ip_binding(adapter):
    module = configured(adapter)
    module.set_option("DC_IP", "192.0.2.11")
    argv = module.build_argv()
    assert argv[argv.index("-dc-ip") + 1] == "192.0.2.11"


def test_secret_records_preserve_material_in_attributes():
    result = configured(ImpacketSecretsDumpModule).parse_output(FIXTURES["secrets"]["stdout"])
    credentials = result["credentials"]
    assert {record["secret_source"] for record in credentials} == {"sam", "lsa", "ntds"}
    assert credentials[1]["password"] == "Password:with:colons"
    assert credentials[2]["credential_type"] == "kerberos_key"
    assert credentials[-1]["username"] == "alice"
    assert result["total_hashes"] == 2


def test_smbclient_supported_inputfile_and_cleanup():
    module = configured(ImpacketSMBClientModule)
    module.set_option("SHARE", "Public")
    module.set_option("COMMAND", "ls")
    paths = []

    def execute(argv, **kwargs):
        assert "-share" not in argv and "-c" not in argv
        input_path = argv[argv.index("-inputfile") + 1]
        paths.append(input_path)
        assert Path(input_path).read_text() == "use Public\nls\n"
        assert os.stat(input_path).st_mode & 0o777 == 0o600
        return subprocess.CompletedProcess(argv, 0, "", "")

    with patch.object(module, "check_tool_installed", return_value=True), patch("subprocess.run", side_effect=execute):
        module.run()
    assert not Path(paths[0]).exists()


def test_kerberos_single_user_spray_observations_and_cleanup():
    module = configured(KerbruteModule)
    module.set_option("DC", "192.0.2.10")
    module.set_option("DC_IP", "192.0.2.11")
    fixture = FIXTURES["spray"]
    paths = []

    def execute(argv, **kwargs):
        assert argv[argv.index("--dc") + 1] == "192.0.2.11"
        index = argv.index("passwordspray")
        paths.append(argv[index + 1])
        assert Path(paths[-1]).read_text() == "alice\n"
        assert os.stat(paths[-1]).st_mode & 0o777 == 0o600
        assert argv[index + 2] == "Password:with spaces;$(id)"
        assert kwargs["shell"] is False
        return subprocess.CompletedProcess(argv, 0, fixture["stdout"], fixture["stderr"])

    with patch("subprocess.run", side_effect=execute):
        result = module.op_passwordspray()
    assert not Path(paths[0]).exists()
    assert module.get_option("USERLIST") is None
    assert result["authenticated"] is True
    assert result["locked_out"] is True
    assert result["credentials"][0]["password"] == "Password:with spaces;$(id)"
    assert result["parsed"]["locked_out"] == ["bob"]
    assert "Password:" not in result["message"]
    observations = normalize_observations(result, ExecutionRequest(module_path="ad/kerbrute"))
    assert {item.kind for item in observations} == {"credential", "user"}
    locked = [item for item in observations if item.attributes.get("locked_out")]
    assert locked and all(item.attributes.get("username") == "bob" for item in locked)


def test_invalid_spray_context_never_launches_process():
    module = configured(KerbruteModule)
    module.set_option("USERNAME", None)
    with patch("subprocess.run") as process:
        result = module.op_passwordspray()
    assert result["success"] is False
    process.assert_not_called()


def test_roast_hashes_are_offline_artifacts_not_authenticated_credentials():
    module = configured(ImpacketASREPRoastModule)
    parsed = module.parse_output("$krb5asrep$alice@CORP.LOCAL:abcd$012345\n")
    assert parsed["vulnerable_accounts"] == ["alice"]
    assert parsed["credentials"][0]["credential_type"] == "offline_hash"
    assert parsed["credentials"][0]["authenticated"] is False


def test_named_lsa_secrets_are_not_account_passwords():
    module = configured(ImpacketSecretsDumpModule)
    parsed = module.parse_output("[*] Dumping LSA Secrets\ndpapi_machinekey:0x123456\n")
    assert parsed["credentials"][0]["credential_type"] == "lsa_secret"
    assert "password" not in parsed["credentials"][0]


def test_kerbrute_does_not_treat_log_markers_as_authentication():
    module = configured(KerbruteModule)
    parsed = module._parse_spray("[+] VALID USERNAME: alice@CORP.LOCAL\n[+] Done!\n")
    assert parsed["credentials"] == []
    assert parsed["observations"] == []


def test_kerbrute_password_colons_and_trailing_spaces():
    module = configured(KerbruteModule)
    parsed = module._parse_spray("[+] VALID LOGIN: o'brien@CORP.LOCAL:p:a ss  \n")
    assert parsed["credentials"][0]["username"] == "o'brien"
    assert parsed["credentials"][0]["password"] == "p:a ss  "


def test_kerbrute_list_spray_does_not_rewrite_users(tmp_path):
    module = configured(KerbruteModule)
    userlist = tmp_path / "users with spaces.txt"
    userlist.write_text("alice\nbob\n")
    module.set_option("USERLIST", str(userlist))
    with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 0, "", "")) as process:
        module.op_passwordspray()
    assert str(userlist) in process.call_args.args[0]
    assert userlist.read_text() == "alice\nbob\n"


def test_kerbrute_combination_file_matches_installed_cli(tmp_path):
    module = configured(KerbruteModule)
    userlist, passlist = tmp_path / "users", tmp_path / "passwords"
    userlist.write_text("alice\nbob\n")
    passlist.write_text("one\ntwo:2\n")
    module.set_option("USERLIST", str(userlist))
    module.set_option("PASSLIST", str(passlist))
    paths = []

    def execute(argv, **kwargs):
        paths.append(argv[argv.index("bruteforce") + 1])
        assert argv[-1] == paths[-1]
        assert Path(paths[-1]).read_text() == "alice:one\nalice:two:2\nbob:one\nbob:two:2\n"
        return subprocess.CompletedProcess(argv, 0, "", "")

    with patch("subprocess.run", side_effect=execute):
        module.op_bruteforce()
    assert not Path(paths[0]).exists()


@pytest.mark.parametrize("adapter", [ImpacketPSExecModule, ImpacketWMIExecModule])
def test_failed_execution_does_not_emit_session(adapter):
    module = configured(adapter)
    module.set_option("COMMAND", "whoami")
    with patch.object(module, "check_tool_installed", return_value=True), patch(
        "subprocess.run", return_value=subprocess.CompletedProcess([], 1, "partial output", "connection lost")
    ):
        result = module.run()
    assert result["success"] is False
    assert result["observations"] == []
