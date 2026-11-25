"""N1 ESC11 executor (esc11.py) -- the RPC/ICPR ADCS relay front.

ESC11 shares ESC8's listener chassis (same fake ProcessManager + runner harness)
and differs only in the relay TRANSPORT (rpc:// + -rpc-mode ICPR -icpr-ca-name)
and the added ``ca`` param. Asserts the proved shape, the RPC listener argv, the
ca param wiring, and the honest non-proved shapes.
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
from purplesploit.validation.executors.process_manager import ProcessManager, ProcHandle
from purplesploit.validation import proof


class _FakePM(ProcessManager):
    def __init__(self, reads=None, poll_codes=None):
        self.reads = list(reads) if reads is not None else [""]
        self.poll_codes = list(poll_codes) if poll_codes is not None else [None]
        self.started: list[list[str]] = []
        self.stopped: list[str] = []
        self._ri = 0
        self._pi = 0

    def start(self, argv, *, env=None, cwd=None) -> ProcHandle:
        self.started.append(list(argv))
        return ProcHandle(id=f"h{len(self.started)}")

    def read(self, handle) -> str:
        val = self.reads[min(self._ri, len(self.reads) - 1)]
        self._ri += 1
        return val

    def poll(self, handle):
        val = self.poll_codes[min(self._pi, len(self.poll_codes) - 1)]
        self._pi += 1
        return val

    def stop(self, handle) -> str:
        self.stopped.append(handle.id)
        return self.reads[min(self._ri, len(self.reads) - 1)]


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


def _ctx(cfg, runner, tmp_path, pm, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path, proc_manager=pm)


def _cfg(host_aliases=None, **kw) -> ValidationConfig:
    base = dict(domain="essos.local", dc_ip="10.0.1.10",
                username="khal.drogo", password="h0rsel0rd",
                poll_interval_s=0, tool_timeout_s=5, host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


_CA_HOST = "braavos.essos.local"
_ALIAS = {_CA_HOST: {"host_id": "srv03"}}
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _esc11_finding(host=_CA_HOST):
    return map_finding({"finding_id": "AR-e11", "host": host, "category": "adcs",
                        "severity": "critical", "rule_id": "promoted-adcs-ca",
                        "line": f"AD CS CA ESSOS-CA on {host}"})


def _auth_stdout():
    return ("[*] Got TGT\n[*] Saved credential cache to 'srv03.ccache'\n"
            f"[*] Got hash for 'braavos$': {_FAKE_NT_HASH}\n")


def _issued(tmp_path):
    (tmp_path / "braavos.pfx").write_bytes(b"PFX")
    (tmp_path / "srv03.ccache").write_bytes(b"CC")


# ================================================================= defaults + ca param
def test_esc11_maps_and_defaults(tmp_path):
    f = _esc11_finding()
    assert is_implemented("ESC11")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("ESC11").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path, _FakePM()), f)}
    assert specs["ca_host"].recommended == f.host
    assert specs["ca"].recommended == "ESSOS-CA"            # from finding.entity.ca (ESC11-only param)
    assert specs["template"].recommended == "DomainController"


def test_esc11_proved_shaped_receipt_uses_rpc_transport(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    pm = _FakePM(reads=["[*] GOT certificate via ICPR (Base64 certificate: ...)"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC11").run(_ctx(cfg, runner, tmp_path, pm), _esc11_finding())
    assert receipt["technique"] == "ESC11" and receipt["class"] == "adcs"
    assert receipt["target"].get("host_id") == "srv03"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "cert_issued_and_used" and tf["ok"] is True and tf["proof_token"]
    # the listener used the RPC/ICPR relay transport (not HTTP), with the CA name.
    started = " ".join(pm.started[0])
    assert "rpc://braavos.essos.local" in started
    assert "-rpc-mode" in started and "ICPR" in started
    assert "-icpr-ca-name" in started and "ESSOS-CA" in started
    assert "certsrv/certfnsh.asp" not in started


def test_esc11_no_cert_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, tool_timeout_s=0)
    pm = _FakePM(reads=[""], poll_codes=[None])
    receipt = get_executor("ESC11").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _esc11_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "esc11_no_cert" in receipt["errors"]
    assert receipt["mutation"]["applied"] is False


def test_esc11_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    pm = _FakePM(reads=["GOT certificate"])
    receipt = get_executor("ESC11").run(
        _ctx(cfg, _KeyRunner(), tmp_path, pm, _Deny("adcs_relay")), _esc11_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and pm.started == []


def test_esc11_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, password="Dr0g0R1des!")
    _issued(tmp_path)
    pm = _FakePM(reads=["GOT certificate"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC11").run(_ctx(cfg, runner, tmp_path, pm), _esc11_finding())
    blob = json.dumps(receipt)
    assert "Dr0g0R1des!" not in blob
    assert _FAKE_NT_HASH not in blob
    assert "braavos.pfx" not in blob and "srv03.ccache" not in blob   # key-material paths never stored
