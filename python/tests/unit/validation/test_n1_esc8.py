"""N1 ESC8 executor (esc8.py) -- the coerce->relay->CA keystone, listener-based.

Driven end-to-end with a scripted fake ProcessManager (the ntlmrelayx --adcs
listener) + a fake CommandRunner (the coercion trigger + certipy auth), with
``poll_interval_s=0`` so the bounded poll never sleeps. Asserts the proved shape
the harness scorer reads as *proved*: schema/technique/class, the ``{host_id}``
scoring identity, all steps ok, mutation + VERIFIED key-material rollback, a
non-negated ``cert_issued_and_used`` terminal with a token, and no issued
pfx/ccache/recovered-hash/operator-password anywhere. The honest non-proved
shapes (no cert issued -> inconclusive; denied gate; unverified/vacuous rollback)
are asserted too.
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


# ============================================================ fakes / helpers
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
    """Scripted synchronous runner keyed on tool basename (certipy-ad = the auth)."""

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
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing",
                poll_interval_s=0, tool_timeout_s=5, host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


_CA_HOST = "dc01.north.sevenkingdoms.local"
_ALIAS = {_CA_HOST: {"host_id": "dc01"}}
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _esc8_finding(host=_CA_HOST):
    return map_finding({"finding_id": "AR-e8", "host": host, "category": "adcs",
                        "severity": "critical", "rule_id": "promoted-adcs-ca",
                        "line": f"AD CS CA NORTH-CA Web Enrollment on {host}"})


def _auth_stdout():
    return ("[*] Using principal: dc01$@north.sevenkingdoms.local\n"
            "[*] Got TGT\n"
            "[*] Saved credential cache to 'dc01.ccache'\n"
            f"[*] Got hash for 'dc01$': {_FAKE_NT_HASH}\n")


def _issued(tmp_path):
    (tmp_path / "dc01.pfx").write_bytes(b"PFX")        # the relay saved the issued cert
    (tmp_path / "dc01.ccache").write_bytes(b"CC")


# ================================================================= mapping + defaults
def test_esc8_maps_and_defaults(tmp_path):
    f = _esc8_finding()
    assert is_implemented("ESC8")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("ESC8").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path, _FakePM()), f)}
    assert specs["ca_host"].recommended == f.host
    assert specs["victim_dc"].recommended == f.host
    assert specs["template"].recommended == "DomainController"
    assert specs["listener_host"].recommended == ""
    assert specs["method"].recommended == "auto"


# ================================================================= proved-shaped receipt
def test_esc8_proved_shaped_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$' (Base64 certificate: ...)"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "ESC8" and receipt["class"] == "adcs"
    assert receipt["target"].get("host_id") == "dc01"      # facet keys on {host_id}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert [s["name"] for s in receipt["steps"]] == [
        "start_listener", "coerce_trigger", "cert_issued", "cert_auth", "destroy_key_material"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "rollback_unverified" not in receipt["errors"]
    assert not (tmp_path / "dc01.pfx").exists()            # issued key material destroyed
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "cert_issued_and_used" and tf["ok"] is True and tf["proof_token"]
    assert pm.started and pm.stopped
    # the listener relayed to the HTTP Web-Enrollment endpoint.
    assert any("certsrv/certfnsh.asp" in " ".join(a) for a in pm.started)


def test_esc8_no_cert_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, tool_timeout_s=0)      # bounded poll elapses at once
    pm = _FakePM(reads=[""], poll_codes=[None])            # no pfx, no marker
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "esc8_no_cert" in receipt["errors"]
    assert receipt["mutation"]["applied"] is False          # nothing issued -> no rollback
    assert pm.stopped
    assert not any(Path(c[0]).name == "certipy-ad" for c in runner.calls)   # auth never ran


def test_esc8_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    pm = _FakePM(reads=["GOT certificate"])
    receipt = get_executor("ESC8").run(
        _ctx(cfg, _KeyRunner(), tmp_path, pm, _Deny("adcs_relay")), _esc8_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert pm.started == []                                 # listener never started on denial


def test_esc8_unverified_rollback_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    (tmp_path / "dc01.pfx").mkdir()                         # destruction fails (a dir)
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$'"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
    assert any(s["name"] == "destroy_key_material" and s["ok"] is False
               for s in receipt["steps"])
    assert receipt["terminal_fact"]["ok"] is True           # scorer's guard -> inconclusive


def test_esc8_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS, password="R3layKeyst0ne!")
    _issued(tmp_path)
    pm = _FakePM(reads=["GOT certificate"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding())
    blob = json.dumps(receipt)
    assert "R3layKeyst0ne!" not in blob                     # operator password never stored
    assert _FAKE_NT_HASH not in blob                        # recovered NT hash never stored
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in blob
    assert "dc01.pfx" not in blob and "dc01.ccache" not in blob   # key-material paths never stored


def test_esc8_operator_override_method_and_listener(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issued(tmp_path)
    pm = _FakePM(reads=["GOT certificate"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding(),
                             overrides={"method": "petitpotam", "listener_host": "10.0.0.250"})
    trig = next(c for c in runner.calls if Path(c[0]).name == "coercer")
    assert trig[trig.index("--filter-method-name") + 1] == "EfsRpcOpenFileRaw"
    assert "10.0.0.250" in trig                             # coercion points at the operator listener


def test_esc8_target_not_vulnerable_shape(tmp_path):
    # A CA host whose host_id is outside the ESC8 vulnerable set -> proved-shaped
    # locally; the scorer's fabrication guard is what rejects it (see cross-check).
    cfg = _cfg(host_aliases={_CA_HOST: {"host_id": "srv02"}})
    _issued(tmp_path)
    pm = _FakePM(reads=["GOT certificate"])
    runner = _KeyRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    receipt = get_executor("ESC8").run(_ctx(cfg, runner, tmp_path, pm), _esc8_finding())
    assert receipt["target"].get("host_id") == "srv02"
    assert receipt["complete"] is True and receipt["terminal_fact"]["ok"] is True
