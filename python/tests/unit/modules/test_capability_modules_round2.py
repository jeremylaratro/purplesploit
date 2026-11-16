"""
Round-2 capability-module tests (OCD AD mind-map gap/stub closures).

Covers the four modules added to back the OCD `delegation`, `persistence` and
`crack_hash` categories:
  - impacket/finddelegation  (delegation enumeration)
  - impacket/getst           (S4U delegation abuse)
  - impacket/ticketer        (golden/silver ticket — persistence)
  - crack/hashcat            (offline hash cracking)

These assert argv shape (offline — no tool required) and output parsing.
"""

import pytest


# --------------------------------------------------------------------------- #
# impacket/finddelegation
# --------------------------------------------------------------------------- #
class TestFindDelegation:
    @pytest.fixture
    def mod(self, mock_framework_minimal):
        from purplesploit.modules.impacket.finddelegation import ImpacketFindDelegationModule
        return ImpacketFindDelegationModule(mock_framework_minimal)

    def test_identity(self, mod):
        assert mod.category == "impacket"
        assert mod.tool_name == "impacket-findDelegation"
        assert "delegation" in mod.description.lower()

    def test_required_options(self, mod):
        for opt in ("RHOST", "USERNAME", "DOMAIN"):
            assert mod.options[opt]["required"] is True

    def test_build_argv_password(self, mod):
        mod.set_option("RHOST", "10.0.0.1")
        mod.set_option("USERNAME", "svc")
        mod.set_option("PASSWORD", "P@ss")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        cmd = mod.build_command()
        # Realm target (no @host) plus -dc-ip — the form real findDelegation accepts.
        assert "CORP.LOCAL/svc:P@ss" in cmd
        assert "@10.0.0.1" not in cmd
        assert "-dc-ip 10.0.0.1" in cmd

    def test_build_argv_pth(self, mod):
        mod.set_option("RHOST", "10.0.0.1")
        mod.set_option("USERNAME", "svc")
        mod.set_option("HASH", "aad3b:deadbeef")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        argv = mod.build_argv()
        assert "-hashes" in argv and "aad3b:deadbeef" in argv

    def test_parse_delegation_table(self, mod):
        mod.set_option("DOMAIN", "CORP.LOCAL")
        out = (
            "AccountName  AccountType  DelegationType  DelegationRightsTo\n"
            "-----------  -----------  --------------  ------------------\n"
            "websvc$      Computer     Constrained     cifs/dc.corp.local\n"
        )
        res = mod.parse_output(out)
        assert res["success"] is True
        assert res["delegations"][0]["account"] == "websvc$"
        assert res["delegations"][0]["delegation_type"] == "Constrained"
        assert any(o["kind"] == "user" for o in res["observations"])

    def test_parse_ignores_banner(self, mod):
        res = mod.parse_output("Impacket v0.11 - Copyright\n[*] something\n")
        assert res["success"] is False
        assert res["delegations"] == []

    def test_parse_multiword_type_and_fifth_column(self, mod):
        # Fixed-width parse must preserve a multi-word DelegationType and tolerate
        # the newer "SPN Exists" column without shifting fields.
        mod.set_option("DOMAIN", "CORP.LOCAL")
        out = (
            "AccountName  AccountType  DelegationType                      DelegationRightsTo  SPN Exists\n"
            "-----------  -----------  ----------------------------------  ------------------  ----------\n"
            "websvc$      Computer     Constrained w/ Protocol Transition  cifs/dc.corp.local  Yes\n"
        )
        res = mod.parse_output(out)
        assert res["success"] is True
        assert res["delegations"][0]["delegation_type"] == "Constrained w/ Protocol Transition"
        assert res["delegations"][0]["delegation_to"] == "cifs/dc.corp.local"

    def test_parse_no_entries_found(self, mod):
        # "No entries found!" must never be fabricated into a user/target row.
        res = mod.parse_output(
            "AccountName  AccountType  DelegationType  DelegationRightsTo\n"
            "-----------  -----------  --------------  ------------------\n"
            "No entries found!\n"
        )
        assert res["success"] is False
        assert res["delegations"] == []


# --------------------------------------------------------------------------- #
# impacket/getst
# --------------------------------------------------------------------------- #
class TestGetST:
    @pytest.fixture
    def mod(self, mock_framework_minimal):
        from purplesploit.modules.impacket.getst import ImpacketGetSTModule
        return ImpacketGetSTModule(mock_framework_minimal)

    def test_identity(self, mod):
        assert mod.tool_name == "impacket-getST"
        # IMPERSONATE is required (this wrapper is scoped to S4U); SPN is optional
        # so an S4U2self-only ticket (no SPN) is a valid invocation.
        assert mod.options["IMPERSONATE"]["required"] is True
        assert mod.options["SPN"]["required"] is False

    def test_build_argv_s4u2self_no_spn(self, mod):
        mod.set_option("RHOST", "10.0.0.1")
        mod.set_option("USERNAME", "websvc")
        mod.set_option("PASSWORD", "pw")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("IMPERSONATE", "Administrator")
        argv = mod.build_argv()
        assert "-impersonate" in argv and "-spn" not in argv

    def test_build_argv_s4u(self, mod):
        mod.set_option("RHOST", "10.0.0.1")
        mod.set_option("USERNAME", "websvc")
        mod.set_option("HASH", "aad3b:deadbeef")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("SPN", "cifs/dc.corp.local")
        mod.set_option("IMPERSONATE", "Administrator")
        argv = mod.build_argv()
        assert "-spn" in argv and "cifs/dc.corp.local" in argv
        assert "-impersonate" in argv and "Administrator" in argv
        assert "-dc-ip" in argv

    def test_build_argv_aeskey(self, mod):
        mod.set_option("USERNAME", "websvc")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("AESKEY", "ffff")
        mod.set_option("SPN", "cifs/dc")
        mod.set_option("IMPERSONATE", "Administrator")
        argv = mod.build_argv()
        assert "-aesKey" in argv and "ffff" in argv

    def test_parse_saved_ticket(self, mod):
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("IMPERSONATE", "Administrator")
        mod.set_option("SPN", "cifs/dc.corp.local")
        res = mod.parse_output("[*] Saving ticket in Administrator.ccache\n")
        assert res["success"] is True
        assert res["ticket_file"] == "Administrator.ccache"
        assert any(o["kind"] == "credential" for o in res["observations"])

    def test_parse_saving_updating_variant(self, mod):
        # Current upstream prints "Saving/Updating ticket in ..."; must still parse.
        res = mod.parse_output("[*] Saving/Updating ticket in Administrator.ccache\n")
        assert res["success"] is True
        assert res["ticket_file"] == "Administrator.ccache"

    def test_parse_no_ticket(self, mod):
        res = mod.parse_output("[-] Kerberos SessionError: KDC_ERR_BADOPTION\n")
        assert res["success"] is False
        assert res["ticket_file"] is None

    def test_run_gates_success_on_ticket(self, mod, monkeypatch):
        # getST can exit 0 while the KDC rejected the request; success must follow
        # the parsed ticket, not the exit code.
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("IMPERSONATE", "Administrator")
        monkeypatch.setattr(mod, "check_tool_installed", lambda: True)
        monkeypatch.setattr(mod, "execute_command",
                            lambda *a, **k: {"success": True, "returncode": 0,
                                             "stdout": "[-] Kerberos SessionError: KDC_ERR_BADOPTION\n"})
        result = mod.run()
        assert result["success"] is False


# --------------------------------------------------------------------------- #
# impacket/ticketer
# --------------------------------------------------------------------------- #
class TestTicketer:
    @pytest.fixture
    def mod(self, mock_framework_minimal):
        from purplesploit.modules.impacket.ticketer import ImpacketTicketerModule
        return ImpacketTicketerModule(mock_framework_minimal)

    def test_identity(self, mod):
        assert mod.tool_name == "impacket-ticketer"
        for opt in ("USERNAME", "DOMAIN", "DOMAIN_SID"):
            assert mod.options[opt]["required"] is True

    def test_build_argv_golden(self, mod):
        mod.set_option("USERNAME", "Administrator")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("DOMAIN_SID", "S-1-5-21-1-2-3")
        mod.set_option("NTHASH", "deadbeef")
        argv = mod.build_argv()
        assert argv[-1] == "Administrator"
        assert "-nthash" in argv and "deadbeef" in argv
        assert "-domain-sid" in argv and "S-1-5-21-1-2-3" in argv
        assert "-spn" not in argv  # golden

    def test_build_argv_silver(self, mod):
        mod.set_option("USERNAME", "Administrator")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("DOMAIN_SID", "S-1-5-21-1-2-3")
        mod.set_option("AESKEY", "ffff")
        mod.set_option("SPN", "cifs/host.corp.local")
        argv = mod.build_argv()
        assert "-aesKey" in argv and "ffff" in argv
        assert "-spn" in argv and "cifs/host.corp.local" in argv

    def test_offline_no_auth_target(self, mod):
        # ticketer forges offline — the argv must not carry a realm/user@host target.
        mod.set_option("USERNAME", "Administrator")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        mod.set_option("DOMAIN_SID", "S-1-5-21-1-2-3")
        mod.set_option("NTHASH", "deadbeef")
        argv = mod.build_argv()
        assert all("@" not in tok for tok in argv)
        assert all("/" not in tok for tok in argv if tok != "CORP.LOCAL")

    def test_parse_kind(self, mod):
        mod.set_option("USERNAME", "Administrator")
        mod.set_option("DOMAIN", "CORP.LOCAL")
        res = mod.parse_output("[*] Saving ticket in Administrator.ccache\n")
        assert res["success"] is True
        assert res["ticket_kind"] == "golden"
        mod.set_option("SPN", "cifs/host")
        res2 = mod.parse_output("[*] Saving ticket in Administrator.ccache\n")
        assert res2["ticket_kind"] == "silver"


# --------------------------------------------------------------------------- #
# crack/hashcat
# --------------------------------------------------------------------------- #
class TestHashcat:
    @pytest.fixture
    def mod(self, mock_framework_minimal):
        from purplesploit.modules.crack.hashcat import HashcatModule
        return HashcatModule(mock_framework_minimal)

    def test_identity(self, mod):
        assert mod.category == "crack"
        assert mod.tool_name == "hashcat"
        for opt in ("HASH_FILE", "HASH_MODE"):
            assert mod.options[opt]["required"] is True

    def test_build_argv_dict(self, mod):
        mod.set_option("HASH_FILE", "/tmp/h.txt")
        mod.set_option("HASH_MODE", "13100")
        mod.set_option("WORDLIST", "/usr/share/wordlists/rockyou.txt")
        mod.set_option("RULES", "best64.rule")
        argv = mod.build_argv()
        assert argv[:3] == ["hashcat", "-m", "13100"]
        assert "-a" in argv and "/tmp/h.txt" in argv
        assert "/usr/share/wordlists/rockyou.txt" in argv
        assert "-r" in argv and "best64.rule" in argv
        assert "--show" not in argv

    def test_build_argv_show(self, mod):
        mod.set_option("HASH_FILE", "/tmp/h.txt")
        mod.set_option("HASH_MODE", "1000")
        mod.set_option("SHOW", "true")
        argv = mod.build_argv()
        assert "--show" in argv
        assert "-a" not in argv  # show mode runs no attack

    def test_parse_ntlm_pair(self, mod):
        mod.set_option("HASH_MODE", "1000")
        res = mod.parse_output("5f4dcc3b5aa765d61d8327deb882cf99:password123\n")
        assert res["success"] is True
        assert res["cracked"][0]["plaintext"] == "password123"
        assert res["credentials"][0]["hash_type"] == "NTLM"

    def test_parse_hash_with_colons(self, mod):
        # NetNTLMv2 hashes contain many colons; the boundary is the LAST colon,
        # so the full hash is preserved and the plaintext is the final field.
        mod.set_option("HASH_MODE", "5600")
        nv2 = "admin::CORP:1122334455667788:1a2b3c:0101:Summer2026!"
        res = mod.parse_output(nv2 + "\n")
        assert res["cracked"][0]["plaintext"] == "Summer2026!"
        assert res["cracked"][0]["hash"] == "admin::CORP:1122334455667788:1a2b3c:0101"

    def test_parse_hex_plaintext(self, mod):
        # hashcat $HEX[..]-encodes plaintexts containing the separator/whitespace.
        mod.set_option("HASH_MODE", "1000")
        res = mod.parse_output("5f4dcc3b5aa765d61d8327deb882cf99:$HEX[703a61]\n")
        assert res["cracked"][0]["plaintext"] == "p:a"

    def test_parse_rejects_status_text(self, mod):
        mod.set_option("HASH_MODE", "1000")
        out = ("Status...........: Running\n"
               "Progress.........: 1024/1024\n"
               "5f4dcc3b5aa765d61d8327deb882cf99:cracked\n")
        res = mod.parse_output(out)
        # Only the genuine cracked line survives; dotted status labels are rejected.
        assert len(res["cracked"]) == 1
        assert res["cracked"][0]["plaintext"] == "cracked"

    def test_parse_empty(self, mod):
        res = mod.parse_output("[s]tatus [p]ause\n\n")
        assert res["success"] is False
        assert res["cracked"] == []

    def test_run_requires_wordlist_for_dict_attack(self, mod, monkeypatch):
        # A dictionary attack with no wordlist would make hashcat hang on stdin.
        mod.set_option("HASH_FILE", "/tmp/h.txt")
        mod.set_option("HASH_MODE", "1000")  # ATTACK_MODE defaults to "0"
        monkeypatch.setattr(mod, "check_tool_installed", lambda: True)
        result = mod.run()
        assert result["success"] is False
        assert "WORDLIST" in result["error"]

    def test_run_gates_success_on_crack(self, mod, monkeypatch):
        mod.set_option("HASH_FILE", "/tmp/h.txt")
        mod.set_option("HASH_MODE", "1000")
        mod.set_option("SHOW", "true")
        monkeypatch.setattr(mod, "check_tool_installed", lambda: True)
        # --show exits 0 but found nothing -> not a success.
        monkeypatch.setattr(mod, "execute_command",
                            lambda *a, **k: {"success": True, "returncode": 0, "stdout": ""})
        assert mod.run()["success"] is False
