"""T1b executors: CONSTRAINED-DELEG-PT (constrained_deleg.py), OPENSHARES-WRITE
(openshares.py) and SHADOW-CREDS (shadow_creds.py).

Each technique is driven end-to-end with a scripted fake runner (no lab) and the
emitted receipt is asserted to be a well-formed ``adlab.plan003.proof.v1`` with
the shape the harness scorer reads as *proved*: correct schema/technique/class,
the scoring identity the facet keys on (CONSTRAINED-DELEG-PT {domain,principal},
OPENSHARES-WRITE {host_id,share}, SHADOW-CREDS {domain}), all steps ok, verified
rollback for the two mutating techniques, a non-negated terminal fact with a
token, and -- critically -- no recovered secret / canary content anywhere in the
receipt.

Failure / gate / unverified-rollback paths assert the honest *non*-proved shape:
a failed step, a denied gate or an unverified rollback yields an incomplete
receipt (no positive proof), never a fabricated one. OPENSHARES-WRITE uses a
*stateful* fake share runner that models the share as a dict + temp dir so the
real put/get/hash-compare and rollback-absent logic is exercised.
"""
from __future__ import annotations

import json
import shlex
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof


# ----------------------------------------------------------------- keyed fake runner
class _FakeRunner(CommandRunner):
    """Return scripted stdout keyed on the tool name (+ a distinguishing flag)."""

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(returncode=0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "nxc":
            return "nxc"
        return tool


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


class _Deny(AuthorizedLabProvider):
    """Deny exactly one gated op; everything else is not_required."""

    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


# ================================================================= CONSTRAINED-DELEG-PT
def _north_config(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing")
    base.update(kw)
    return ValidationConfig(**base)


def _deleg_finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-d1", "host": host, "category": "delegation", "severity": "high",
        "line": f"msDS-AllowedToDelegateTo cifs/{host} (constrained delegation) on {host}",
    })


def _deleg_proved_script():
    return {
        "impacket-getST": RunResult(0, stdout="[*] Saving ticket in Administrator.ccache"),
        "nxc": RunResult(0, stdout="SMB  winterfell  445  WINTERFELL  [+] north\\Administrator (Pwn3d!)"),
    }


def test_deleg_maps_and_defaults(tmp_path):
    f = _deleg_finding()
    assert f.technique == "CONSTRAINED-DELEG-PT"
    assert is_implemented("CONSTRAINED-DELEG-PT")
    cfg = _north_config()
    specs = {s.name: s for s in get_executor("CONSTRAINED-DELEG-PT").param_specs(
        _ctx(cfg, _FakeRunner({}), tmp_path), f)}
    assert specs["deleg_principal"].recommended == "jon.snow"   # ctx.config.username
    assert specs["impersonate"].recommended == "Administrator"
    assert specs["target_spn"].recommended == "cifs/winterfell.north.sevenkingdoms.local"
    assert specs["target_host"].recommended == f.host


def test_deleg_emits_proved_shaped_receipt(tmp_path):
    cfg = _north_config()
    runner = _FakeRunner(_deleg_proved_script())
    receipt = get_executor("CONSTRAINED-DELEG-PT").run(_ctx(cfg, runner, tmp_path), _deleg_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "CONSTRAINED-DELEG-PT" and receipt["class"] == "delegation"
    # Facet keys on {domain, principal} -- the delegation principal.
    assert receipt["target"] == {"domain": "north.sevenkingdoms.local", "principal": "jon.snow"}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is False          # non-mutating: no rollback
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    assert tf["impersonated"] == "Administrator"
    # getST (KRB5CCNAME unset) then ticket-backed nxc both ran.
    tools = [Path(c[0]).name for c in runner.calls]
    assert tools == ["impacket-getST", "nxc"]


def test_deleg_operator_override_changes_impersonation(tmp_path):
    cfg = _north_config()
    runner = _FakeRunner(_deleg_proved_script())
    get_executor("CONSTRAINED-DELEG-PT").run(
        _ctx(cfg, runner, tmp_path), _deleg_finding(),
        overrides={"impersonate": "sql_svc", "deleg_principal": "jon.snow"})
    getst = next(c for c in runner.calls if Path(c[0]).name == "impacket-getST")
    assert getst[getst.index("-impersonate") + 1] == "sql_svc"


def test_deleg_no_secret_in_receipt(tmp_path):
    cfg = _north_config(password="S3cr3tPassw0rd!")
    receipt = get_executor("CONSTRAINED-DELEG-PT").run(
        _ctx(cfg, _FakeRunner(_deleg_proved_script()), tmp_path), _deleg_finding())
    blob = json.dumps(receipt)
    assert "S3cr3tPassw0rd!" not in blob      # operator password never stored
    assert ".ccache" not in blob               # ticket path is secret-marked, dropped


def test_deleg_nxc_fails_is_not_proved(tmp_path):
    script = _deleg_proved_script()
    script["nxc"] = RunResult(0, stdout="SMB  winterfell  445  [-] north\\Administrator KDC_ERR")
    cfg = _north_config()
    receipt = get_executor("CONSTRAINED-DELEG-PT").run(_ctx(cfg, _FakeRunner(script), tmp_path), _deleg_finding())
    # ticket obtained but access failed -> negated terminal + failed step, never proved.
    assert receipt["terminal_fact"]["ok"] is False
    assert any(s["name"] == "nxc_access" and s["ok"] is False for s in receipt["steps"])
    assert "nxc_access_failed" in receipt["errors"]


def test_deleg_no_ticket_is_not_proved(tmp_path):
    script = {"impacket-getST": RunResult(1, stdout="[-] Kerberos SessionError: KDC_ERR_BADOPTION")}
    cfg = _north_config()
    runner = _FakeRunner(script)
    receipt = get_executor("CONSTRAINED-DELEG-PT").run(_ctx(cfg, runner, tmp_path), _deleg_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None
    assert "getST_no_ticket" in receipt["errors"]
    assert [Path(c[0]).name for c in runner.calls] == ["impacket-getST"]   # nxc never run


def test_deleg_target_not_vulnerable_is_not_proved(tmp_path):
    # Override the delegation principal to one NOT in the vulnerable set.
    cfg = _north_config()
    runner = _FakeRunner(_deleg_proved_script())
    receipt = get_executor("CONSTRAINED-DELEG-PT").run(
        _ctx(cfg, runner, tmp_path), _deleg_finding(), overrides={"deleg_principal": "eddard.stark"})
    assert receipt["target"]["principal"] == "eddard.stark"
    # Receipt is otherwise proved-shaped; the scorer's fabrication guard rejects it.


# ================================================================= OPENSHARES-WRITE
def _shares_config(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="hodor", password="hodorhodor",
                host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}})
    base.update(kw)
    return ValidationConfig(**base)


def _shares_finding(host="srv02.north.sevenkingdoms.local", share="all"):
    return map_finding({
        "finding_id": "AR-s1", "host": host, "category": "smb", "severity": "high",
        "line": f"non-default RW share '{share}' (READ,WRITE) on {host}",
    })


class _FakeShareRunner(CommandRunner):
    """Stateful smbclient fake: models a share as {remote_name: content} + temp dir.

    Parses the smbclient ``-c`` command and models put/get/rm so the executor's
    real local write, upload, download, sha256-compare and rollback-absent logic
    is exercised. ``tamper`` corrupts the content returned by ``get`` to drive the
    hash-mismatch path.
    """

    def __init__(self, tamper=False):
        self.store: dict[str, str] = {}
        self.tamper = tamper
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        if Path(argv[0]).name != "smbclient" or "-c" not in argv:
            return RunResult(returncode=0, stdout="")
        command = argv[argv.index("-c") + 1]
        parts = shlex.split(command)
        if not parts:
            return RunResult(returncode=0, stdout="")
        op, args = parts[0].lower(), parts[1:]
        if op == "put":
            local, remote = args[0], args[1]
            self.store[remote] = Path(local).read_text(encoding="utf-8")
            return RunResult(0, stdout=f"putting file {local} as \\{remote} (999.9 kb/s) (average 999.9 kb/s)")
        if op == "get":
            remote, dest = args[0], args[1]
            if remote not in self.store:
                return RunResult(1, stdout=f"NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \\{remote}")
            content = self.store[remote]
            if self.tamper:
                content = content + "_tampered"
            Path(dest).write_text(content, encoding="utf-8")
            return RunResult(0, stdout=f"getting file \\{remote} of size {len(content)} as {dest} (999.9 kb/s)")
        if op in ("rm", "deltree"):
            remote = args[0]
            self.store.pop(remote, None)
            return RunResult(0, stdout="")
        return RunResult(returncode=0, stdout="")


def test_openshares_maps_and_defaults(tmp_path):
    f = _shares_finding()
    assert f.technique == "OPENSHARES-WRITE" and f.entity.get("share") == "all"
    assert is_implemented("OPENSHARES-WRITE")
    cfg = _shares_config()
    specs = {s.name: s for s in get_executor("OPENSHARES-WRITE").param_specs(
        _ctx(cfg, _FakeShareRunner(), tmp_path), f)}
    assert specs["share"].recommended == "all"               # from finding.entity.share
    assert specs["canary_name"].recommended.startswith("vrcheck_")


def test_openshares_emits_proved_shaped_receipt(tmp_path):
    cfg = _shares_config()
    runner = _FakeShareRunner()
    receipt = get_executor("OPENSHARES-WRITE").run(_ctx(cfg, runner, tmp_path), _shares_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "OPENSHARES-WRITE" and receipt["class"] == "openshares"
    # Facet keys on {host_id, share}; host_id resolved via host_aliases.
    assert receipt["target"].get("host_id") == "srv02" and receipt["target"].get("share") == "all"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert receipt["mutation"]["rollback"]["method"] == "smbclient rm + readback-absent verify"
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "file_write_readback" and tf["ok"] is True and tf["proof_token"]
    assert "rollback_unverified" not in receipt["errors"]
    # The full round-trip ran: put, readback-get, rm, verify-absent get.
    cmds = [shlex.split(c[c.index("-c") + 1])[0] for c in runner.calls if "-c" in c]
    assert cmds == ["put", "get", "rm", "get"]
    # After rollback the canary is gone from the modelled share.
    assert runner.store == {}


def test_openshares_operator_override_changes_share(tmp_path):
    cfg = _shares_config(host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}})
    runner = _FakeShareRunner()
    receipt = get_executor("OPENSHARES-WRITE").run(
        _ctx(cfg, runner, tmp_path), _shares_finding(), overrides={"share": "public"})
    assert receipt["target"].get("share") == "public"
    # The UNC path in the put argv targets the overridden share.
    put = next(c for c in runner.calls if "-c" in c and shlex.split(c[c.index("-c") + 1])[0] == "put")
    assert "//srv02.north.sevenkingdoms.local/public" in put


def test_openshares_no_secret_or_canary_in_receipt(tmp_path):
    cfg = _shares_config(password="hodorhodor")
    runner = _FakeShareRunner()
    # Fixed canary name so we can read the content the executor generated.
    receipt = get_executor("OPENSHARES-WRITE").run(
        _ctx(cfg, runner, tmp_path), _shares_finding(), overrides={"canary_name": "vrcheck_fixed.txt"})
    canary_content = (tmp_path / "vrcheck_fixed.txt").read_text(encoding="utf-8")
    blob = json.dumps(receipt)
    assert "hodorhodor" not in blob          # operator password never stored
    assert canary_content not in blob         # canary content kept out of the receipt
    assert len(canary_content) >= 32          # (sanity: a real random canary was written)


def test_openshares_write_gate_denied_inconclusive(tmp_path):
    cfg = _shares_config()
    runner = _FakeShareRunner()
    receipt = get_executor("OPENSHARES-WRITE").run(
        _ctx(cfg, runner, tmp_path, _Deny("openshares_write")), _shares_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"] is False    # never wrote -> nothing to roll back
    assert runner.store == {}


def test_openshares_hash_mismatch_is_not_proved(tmp_path):
    cfg = _shares_config()
    runner = _FakeShareRunner(tamper=True)     # readback content != written content
    receipt = get_executor("OPENSHARES-WRITE").run(_ctx(cfg, runner, tmp_path), _shares_finding())
    assert receipt["complete"] is False
    assert any(s["name"] == "hash_compare" and s["ok"] is False for s in receipt["steps"])
    assert "readback_hash_mismatch" in receipt["errors"]
    assert receipt["terminal_fact"]["ok"] is False     # negated predicate, not fabricated
    # The mutating write still happened, so rollback was still performed + verified.
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True


def test_openshares_target_not_vulnerable_is_not_proved(tmp_path):
    cfg = _shares_config()
    runner = _FakeShareRunner()
    receipt = get_executor("OPENSHARES-WRITE").run(
        _ctx(cfg, runner, tmp_path), _shares_finding(share="not_a_vuln_share"),
        overrides={"share": "not_a_vuln_share"})
    assert receipt["target"].get("share") == "not_a_vuln_share"
    # Proved-shaped receipt, but the scorer's fabrication guard rejects the share.


# ================================================================= SHADOW-CREDS
def _shadow_config(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="hodor", password="hodorhodor")
    base.update(kw)
    return ValidationConfig(**base)


def _shadow_finding(host="winterfell.north.sevenkingdoms.local"):
    return map_finding({
        "finding_id": "AR-sc1", "host": host, "category": "adcs", "severity": "high",
        "rule_id": "promoted-shadow-creds",
        "line": f"shadow credentials candidate on {host}",
    })


# A realistic certipy shadow-auto transcript: recovers a hash AND auto-restores.
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _shadow_proved_stdout():
    return ("[*] Targeting user 'winterfell$'\n"
            "[*] Adding Key Credential with device ID to the Key Credentials\n"
            "[*] Authenticating as 'winterfell$' via PKINIT\n"
            f"[*] Got hash for 'winterfell$@north.sevenkingdoms.local': {_FAKE_NT_HASH}\n"
            "[*] Restoring the old Key Credentials for 'winterfell$'\n"
            "[*] Successfully restored the old Key Credentials\n")


def test_shadow_maps_and_defaults(tmp_path):
    f = _shadow_finding()
    assert f.technique == "SHADOW-CREDS"
    assert is_implemented("SHADOW-CREDS")
    cfg = _shadow_config()
    specs = {s.name: s for s in get_executor("SHADOW-CREDS").param_specs(
        _ctx(cfg, _FakeRunner({}), tmp_path), f)}
    # victim account defaults to the finding host's computer account <shortname>$.
    assert specs["account"].recommended == "winterfell$"


def test_shadow_emits_proved_shaped_receipt(tmp_path):
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=_shadow_proved_stdout())})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "SHADOW-CREDS" and receipt["class"] == "shadow_creds"
    assert receipt["target"]["domain"] == "north.sevenkingdoms.local"   # facet keys on {domain}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert receipt["mutation"]["rollback"]["method"] == "certipy shadow auto self-restore"
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "secret_recovered" and tf["ok"] is True and tf["proof_token"]


def test_shadow_operator_override_changes_account(tmp_path):
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=_shadow_proved_stdout())})
    get_executor("SHADOW-CREDS").run(
        _ctx(cfg, runner, tmp_path), _shadow_finding(), overrides={"account": "sql_svc"})
    cad = next(c for c in runner.calls if Path(c[0]).name == "certipy-ad")
    assert cad[cad.index("-account") + 1] == "sql_svc"


def test_shadow_no_secret_in_receipt(tmp_path):
    cfg = _shadow_config(password="hodorhodor")
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=_shadow_proved_stdout())})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    blob = json.dumps(receipt)
    assert _FAKE_NT_HASH not in blob                     # recovered NT hash never stored
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in blob
    assert "hodorhodor" not in blob                      # operator password never stored


def test_shadow_write_gate_denied_inconclusive(tmp_path):
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=_shadow_proved_stdout())})
    receipt = get_executor("SHADOW-CREDS").run(
        _ctx(cfg, runner, tmp_path, _Deny("shadow_write")), _shadow_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert [Path(c[0]).name for c in runner.calls] == []     # certipy never run


def test_shadow_unverified_rollback_is_inconclusive(tmp_path):
    # Hash recovered, but NO restore marker -> rollback cannot be verified.
    stdout = (f"[*] Got hash for 'winterfell$@north.sevenkingdoms.local': {_FAKE_NT_HASH}\n"
              "[-] Failed to restore the old Key Credentials\n")
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=stdout)})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_shadow_no_hash_is_not_proved(tmp_path):
    stdout = "[-] Authentication failed; no hash recovered\n"
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(1, stdout=stdout)})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None
    assert "shadow_no_hash" in receipt["errors"]
    assert any(s["name"] == "shadow_auto" and s["ok"] is False for s in receipt["steps"])


# ---------------- regression: review-found integrity holes (must stay closed) ----------------
def test_shadow_inprogress_restore_line_is_not_verified(tmp_path):
    # certipy prints the in-progress "Restoring the old Key Credentials" line
    # BEFORE the LDAP restore; if the restore then FAILS (no success line) the
    # rollback must NOT be reported verified (else a dirty lab reads as clean).
    stdout = (f"[*] Got hash for 'winterfell$@north.sevenkingdoms.local': {_FAKE_NT_HASH}\n"
              "[*] Restoring the old Key Credentials for 'winterfell$'\n"
              "[-] Could not restore the old Key Credentials: insufficient rights\n")
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(0, stdout=stdout)})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_shadow_benign_nthash_phrase_is_not_recovery(tmp_path):
    # A line merely MENTIONING "NT hash" (no recovered value) must not yield a
    # secret_recovered proof.
    stdout = ("[-] Could not retrieve the NT hash for the target account\n"
              "[-] shadow auto failed\n")
    cfg = _shadow_config()
    runner = _FakeRunner({"certipy-ad": RunResult(1, stdout=stdout)})
    receipt = get_executor("SHADOW-CREDS").run(_ctx(cfg, runner, tmp_path), _shadow_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None
    assert "shadow_no_hash" in receipt["errors"]


def test_openshares_verify_transport_failure_is_not_verified(tmp_path):
    # A verify-get that fails to CONNECT (no explicit NT_STATUS not-found token)
    # must NOT be read as "canary gone" -- rollback stays unverified rather than
    # falsely reporting a clean share.
    class _FlakyVerify(_FakeShareRunner):
        def run(self, argv, *, env=None, timeout=None, cwd=None):
            if "-c" in argv:
                parts = shlex.split(argv[argv.index("-c") + 1])
                if len(parts) >= 3 and parts[0].lower() == "get" and parts[2].endswith(".absent"):
                    self.calls.append(list(argv))
                    return RunResult(1, stdout="Connection to srv02 failed (connection refused)")
            return super().run(argv, env=env, timeout=timeout, cwd=cwd)
    cfg = _shares_config()
    runner = _FlakyVerify()
    receipt = get_executor("OPENSHARES-WRITE").run(_ctx(cfg, runner, tmp_path), _shares_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
