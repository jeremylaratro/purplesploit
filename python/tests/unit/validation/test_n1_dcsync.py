"""N1 DCSync terminal module (dcsync.py) -- the reusable, non-mutating DA proof.

Driven end-to-end with a scripted fake runner (no lab). Asserts the proved shape
the scorer reads as *proved*: schema/technique/class, the ``{host_id}`` scoring
identity, the ``dcsync`` step ok, a non-negated ``replication_dump`` terminal
with a token, ``mutation.applied=False`` (a read -> no rollback), and -- the
secret rule -- no krbtgt hash / operator password anywhere. The honest shapes
(no replication -> not-proved; denied gate) and the credential-mode wiring (-k /
-hashes / password target) are asserted too.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof


class _KeyRunner(CommandRunner):
    def __init__(self, script=None):
        self.script = script or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(Path(argv[0]).name, RunResult(returncode=0, stdout=""))


class _Deny(AuthorizedLabProvider):
    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _cfg(host_aliases=None, **kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing", host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


_DC = "dc01.north.sevenkingdoms.local"
_ALIAS = {_DC: {"host_id": "dc01"}}
# The krbtgt hash in the dump is a SECRET -- it must NEVER reach the receipt.
_DCSYNC_OK = ("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
              "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef:::\n")


def _dcsync_finding(host=_DC):
    # No aranum signal maps to DCSYNC (chaining edge); the C engine supplies the
    # DC host. A neutral line maps to no technique but carries finding.host.
    return map_finding({"finding_id": "AR-ds", "host": host, "category": "delegation",
                        "severity": "high", "line": f"domain controller {host}"})


# ================================================================= defaults
def test_dcsync_maps_and_defaults(tmp_path):
    f = _dcsync_finding()
    assert is_implemented("DCSYNC")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("DCSYNC").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path), f)}
    assert specs["dc_host"].recommended == f.host


# ================================================================= proved-shaped receipt
def test_dcsync_proved_shaped_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "DCSYNC" and receipt["class"] == "dcsync"
    assert receipt["target"].get("host_id") == "dc01"        # facet keys on {host_id}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    # DCSync now resolves the real NetBIOS name first (rpcclient/lookupsid; falls
    # to the heuristic here since the fake runner returns nothing), then DCSyncs.
    assert [s["name"] for s in receipt["steps"]] == ["resolve_netbios", "dcsync"]
    assert receipt["mutation"]["applied"] is False           # read-only: no rollback
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "replication_dump" and tf["ok"] is True and tf["proof_token"]
    # secretsdump requested just the krbtgt replication object.
    sd = next(c for c in runner.calls if Path(c[0]).name == "impacket-secretsdump")
    # krbtgt is NetBIOS-domain-qualified (NORTH/krbtgt) so name translation is
    # unambiguous in a multi-domain forest; never the bare "krbtgt".
    assert "-just-dc-user" in sd and "NORTH/krbtgt" in sd and "krbtgt" not in sd


def test_dcsync_no_replication_is_not_proved(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    runner = _KeyRunner({"impacket-secretsdump": RunResult(1, stdout="[-] DCSync failed: access denied")})
    receipt = get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "dcsync_failed" in receipt["errors"]
    assert any(s["name"] == "dcsync" and s["ok"] is False for s in receipt["steps"])


def test_dcsync_banner_without_krbtgt_line_is_not_proved(tmp_path):
    # BLOCKER-4 falsifier: a run that exits 0 and prints the dump BANNER (and even
    # a "Kerberos keys grabbed" summary) but NO complete krbtgt:<rid>:<lm>:<nt>:::
    # replication line must be not-proved. The old marker accepted the banner
    # alone -> a false Domain Admin. Only real replication evidence counts now.
    cfg = _cfg(host_aliases=_ALIAS)
    banner = ("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
              "[*] Using the DRSUAPI method to get NTDS.DIT secrets\n"
              "[*] Kerberos keys grabbed\n"
              "[-] DRSGetNCChanges failed: access denied\n")
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=banner)})
    receipt = get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "dcsync_failed" in receipt["errors"]


def test_dcsync_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("DCSYNC").run(
        _ctx(cfg, runner, tmp_path, _Deny("dcsync")), _dcsync_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert runner.calls == []                                 # secretsdump never run


def test_dcsync_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, password="DCSyncP@ss!")
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    blob = json.dumps(receipt)
    assert "DCSyncP@ss!" not in blob                          # operator password never stored
    assert "0123456789abcdef0123456789abcdef" not in blob      # krbtgt hash never read in


def test_dcsync_hash_auth_wiring(tmp_path):
    op_hash = "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
    cfg = _cfg(host_aliases=_ALIAS, password=None, nt_hash=op_hash)
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    sd = next(c for c in runner.calls if Path(c[0]).name == "impacket-secretsdump")
    assert "-hashes" in sd                                    # hash auth wired
    assert op_hash not in json.dumps(receipt)                 # ... but never stored
    assert receipt["complete"] is True and receipt["terminal_fact"]["ok"] is True


def test_dcsync_ticket_auth_wiring_when_no_creds(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, password=None)            # ticket-backed context (a front's TGT)
    runner = _KeyRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dcsync_finding())
    sd = next(c for c in runner.calls if Path(c[0]).name == "impacket-secretsdump")
    assert "-k" in sd and "-no-pass" in sd                    # -k -no-pass (captured ticket)
