"""C.0 composition-enabling refactor (review B1/B2/B3/H5a/H6) -- the hooks the
chaining engine (C) needs, proven REAL before the engine exists.

These tests pin that ``a1+b1`` is not scripted:
* **B1 (threading is real):** a DCSync given a THREADED ccache+principal
  authenticates AS the front's principal (e.g. ``dc01$``) with ``KRB5CCNAME``
  forwarded to the runner -- NOT as the operator user. Without this the captured
  TGT would be silently ignored.
* **B2 (typed products):** a mutating front exposes its ccache as a typed
  ``Capability(DC_TGT, ccache, principal)`` the engine can route.
* **B3 (deferred rollback):** a COMPOSED mutating front does NOT destroy its key
  material inline (so a downstream terminal can use it); a public ``teardown``
  destroys + VERIFIES it later.
* **H5a (no false DA):** ``local_admin_for`` is a real state that never equals or
  feeds ``S_DA``.
* **H6 (no leak):** the composable receipt carries no ccache path / secret.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation import states
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
    Capability, CAP_CCACHE, CAP_NT_HASH, CAP_PRINCIPAL, ComposableResult,
)
from purplesploit.validation.executors.process_manager import ProcessManager, ProcHandle


# ============================================================ fakes / helpers
class _EnvRunner(CommandRunner):
    """Scripted runner that records each call's argv AND env (for threading proof)."""

    def __init__(self, script=None):
        self.script = script or {}
        self.calls: list[tuple[list[str], dict]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append((list(argv), dict(env or {})))
        return self.script.get(Path(argv[0]).name, RunResult(returncode=0, stdout=""))

    def argv_of(self, tool):
        return next(a for a, _ in self.calls if Path(a[0]).name == tool)

    def env_of(self, tool):
        return next(e for a, e in self.calls if Path(a[0]).name == tool)


class _FakePM(ProcessManager):
    def __init__(self, reads=None):
        self.reads = list(reads) if reads is not None else [""]
        self.started: list[list[str]] = []
        self.stopped: list[str] = []
        self._ri = 0

    def start(self, argv, *, env=None, cwd=None) -> ProcHandle:
        self.started.append(list(argv))
        return ProcHandle(id=f"h{len(self.started)}")

    def read(self, handle) -> str:
        val = self.reads[min(self._ri, len(self.reads) - 1)]
        self._ri += 1
        return val

    def poll(self, handle):
        return None

    def stop(self, handle) -> str:
        self.stopped.append(handle.id)
        return self.reads[min(self._ri, len(self.reads) - 1)]


def _cfg(host_aliases=None, **kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing",
                poll_interval_s=0, tool_timeout_s=5, host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


_DC = "dc01.north.sevenkingdoms.local"
_ALIAS = {_DC: {"host_id": "dc01"}}
_DCSYNC_OK = ("[*] Dumping Domain Credentials\n"
              "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KRBTGThash0000000000000000000000:::\n")
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def _ctx(cfg, runner, tmp_path, *, pm=None, input_caps=None, env=None, composed=False):
    return ExecutorContext(
        cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
        output_dir=tmp_path, proc_manager=pm or _FakePM(),
        input_caps=input_caps or {}, env=env or {}, composed=composed)


def _dc_finding(host=_DC):
    return map_finding({"finding_id": "AR-ds", "host": host, "category": "delegation",
                        "severity": "high", "line": f"domain controller {host}"})


def _esc8_finding(host=_DC):
    return map_finding({"finding_id": "AR-e8", "host": host, "category": "adcs",
                        "severity": "critical", "line": f"AD CS CA Web Enrollment on {host}"})


def _auth_stdout():
    return ("[*] Using principal: dc01$@north.sevenkingdoms.local\n"
            "[*] Got TGT\n[*] Saved credential cache to 'dc01.ccache'\n"
            f"[*] Got hash for 'dc01$': {_FAKE_NT_HASH}\n")


def _issue(tmp_path):
    (tmp_path / "dc01.pfx").write_bytes(b"PFX")
    (tmp_path / "dc01.ccache").write_bytes(b"CC")


# ================================================================= states (H5a)
def test_new_states_are_known_and_distinct():
    for s in (states.S_COERCED_AUTH, states.S_COMPUTER_CONTROL,
              states.S_RBCD_WRITE, states.S_IMPERSONATION_TGT):
        assert states.is_state(s) and s in states.BASE_STATES


def test_local_admin_is_a_state_but_never_domain_admin():
    la = states.local_admin_for("srv02.north.sevenkingdoms.local")
    assert la.startswith("local_admin:") and states.is_state(la)
    assert la != states.S_DA and la != states.DA_CREDS and la != states.DC_TGT
    assert la not in states.BASE_STATES                 # per-host, not a base DA state
    assert not states.is_state("local_admin:")          # empty host -> not a state


def test_cred_for_is_principal_typed():
    c = states.cred_for("administrator")
    assert c == "cred:administrator" and states.is_state(c)
    assert states.cred_principal(c) == "administrator"
    assert states.cred_principal(states.DC_TGT) == ""   # not a cred token
    assert not states.is_state("cred:")                 # empty principal -> not a state


# ================================================================= Capability (B2)
def test_capability_typing_and_secret_flag():
    cc = Capability(state=states.DC_TGT, channel=CAP_CCACHE, value="/run/x.ccache",
                    principal="dc01$")
    assert cc.secret is True and cc.principal == "dc01$"      # ccache PATH is secret-marked (H6)
    assert Capability(state=states.DA_CREDS, channel=CAP_NT_HASH, value="h").secret is True
    assert Capability(state=states.DC_TGT, channel=CAP_PRINCIPAL, value="dc01$").secret is False
    try:
        Capability(state=states.DC_TGT, channel="bogus")
        assert False, "unknown channel must raise"
    except ValueError:
        pass


def test_executor_context_composition_slots_default_empty():
    ctx = ExecutorContext(_cfg(), runner=_EnvRunner(),
                          authorizer=AuthorizedLabProvider(True), output_dir=Path("/tmp"))
    assert ctx.input_caps == {} and ctx.env == {} and ctx.composed is False


def test_executor_default_hooks_are_safe_noops():
    dc = get_executor("DCSYNC")
    assert dc.produced(None, None, {}, {}) == []             # non-front: no products
    td = dc.teardown(_ctx(_cfg(), _EnvRunner(), Path("/tmp")), None)
    assert td["performed"] is False and td["verified"] is True   # nothing to undo == clean


# ================================================================= B1: threading is REAL
def test_dcsync_threads_ccache_and_authenticates_as_front_principal(tmp_path):
    """The crux: a threaded ccache makes DCSync auth AS dc01$ with KRB5CCNAME set,
    NOT as the operator jon.snow. This is a1.eff literally feeding b1.pre."""
    cfg = _cfg(host_aliases=_ALIAS)
    runner = _EnvRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    ctx = _ctx(cfg, runner, tmp_path,
               input_caps={"ccache": "/run/dc01.ccache", "principal": "dc01$"},
               env={"KRB5CCNAME": "/run/dc01.ccache"})
    receipt = get_executor("DCSYNC").run(ctx, _dc_finding())
    sd = runner.argv_of("impacket-secretsdump")
    assert "-k" in sd and "-no-pass" in sd
    target = sd[-1]
    assert "dc01$" in target and "jon.snow" not in target    # auth'd as the FRONT's principal
    assert runner.env_of("impacket-secretsdump").get("KRB5CCNAME") == "/run/dc01.ccache"
    assert receipt["complete"] is True                       # and it still proves DA


def test_dcsync_threads_nt_hash_for_a_principal(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    threaded = "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
    runner = _EnvRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    ctx = _ctx(cfg, runner, tmp_path,
               input_caps={"nt_hash": threaded, "principal": "administrator"})
    receipt = get_executor("DCSYNC").run(ctx, _dc_finding())
    sd = runner.argv_of("impacket-secretsdump")
    assert "-hashes" in sd and "administrator" in sd[-1]
    assert threaded not in json.dumps(receipt)               # threaded hash never stored (H6)


def test_dcsync_standalone_unchanged_when_no_threaded_caps(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)                           # operator password, no input_caps
    runner = _EnvRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    get_executor("DCSYNC").run(_ctx(cfg, runner, tmp_path), _dc_finding())
    sd = runner.argv_of("impacket-secretsdump")
    assert sd[-1] == "north.sevenkingdoms.local/jon.snow:iknownothing@" + _DC  # operator creds
    assert runner.env_of("impacket-secretsdump").get("KRB5CCNAME") is None


# ================================================================= B3: deferred rollback
def test_esc8_composed_defers_rollback_and_produces_dc_tgt(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issue(tmp_path)
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$' (Base64 certificate: ...)"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    ctx = _ctx(cfg, runner, tmp_path, pm=pm, composed=True)
    res = get_executor("ESC8").run_composable(ctx, _esc8_finding())
    assert isinstance(res, ComposableResult) and res.complete is True
    # key material SURVIVES (not destroyed inline) so DCSync can consume it.
    assert (tmp_path / "dc01.pfx").exists() and (tmp_path / "dc01.ccache").exists()
    names = [s["name"] for s in res.receipt["steps"]]
    assert "rollback_deferred" in names and "destroy_key_material" not in names
    # produced a typed DC_TGT capability the engine can thread.
    caps = res.capabilities
    assert len(caps) == 1 and caps[0].state == states.DC_TGT
    assert caps[0].channel == CAP_CCACHE and caps[0].value and caps[0].principal == "dc01$"
    # the teardown obligation carries the secret paths (engine-only).
    assert res.teardown_obligation and (tmp_path / "dc01.pfx").name in \
        " ".join(res.teardown_obligation["paths"])
    # H6: no secret path leaks into the serializable receipt.
    assert "dc01.pfx" not in json.dumps(res.receipt)


def test_esc8_deferred_teardown_destroys_and_verifies(tmp_path):
    cfg = _cfg(host_aliases=_ALIAS)
    _issue(tmp_path)
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$'"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    ctx = _ctx(cfg, runner, tmp_path, pm=pm, composed=True)
    res = get_executor("ESC8").run_composable(ctx, _esc8_finding())
    td = res.executor.teardown(ctx, res.teardown_obligation)
    assert td["performed"] is True and td["verified"] is True
    assert not (tmp_path / "dc01.pfx").exists()               # destroyed at teardown
    assert not (tmp_path / "dc01.ccache").exists()


def test_esc8_standalone_still_destroys_inline(tmp_path):
    """Guard: the composed branch must not change standalone behaviour."""
    cfg = _cfg(host_aliases=_ALIAS)
    _issue(tmp_path)
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$'"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout())})
    res = get_executor("ESC8").run_composable(_ctx(cfg, runner, tmp_path, pm=pm), _esc8_finding())
    names = [s["name"] for s in res.receipt["steps"]]
    assert "destroy_key_material" in names and "rollback_deferred" not in names
    assert not (tmp_path / "dc01.pfx").exists()               # destroyed inline (composed=False)
    assert res.capabilities == []                             # standalone exposes no product


def test_certifried_composed_defers_and_teardown_deletes_computer(tmp_path):
    cfg = _cfg(host_aliases={_DC: {"host_id": "srv03"}})
    (tmp_path / "x.pfx").write_bytes(b"PFX")
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=(
        "[*] Successfully created account\n"
        "[*] Saved certificate and private key to 'x.pfx'\n" + _auth_stdout()))})
    ctx = _ctx(cfg, runner, tmp_path, composed=True)
    res = get_executor("CERTIFRIED").run_composable(
        ctx, _esc8_finding(),
        overrides={"ca": "ESSOS-CA", "dc_fqdn": _DC, "new_computer": "cmp_cf"})
    assert res.complete is True
    names = [s["name"] for s in res.receipt["steps"]]
    assert "rollback_deferred" in names and "rollback_delete_computer" not in names
    assert res.capabilities and res.capabilities[0].state == states.DC_TGT
    assert res.teardown_obligation["computer"]                # the created computer to delete
    # teardown deletes the computer (certipy account delete runs) + verifies.
    td_runner = _EnvRunner({"certipy-ad": RunResult(0, stdout="[*] Successfully deleted account"),
                            "nxc": RunResult(0, stdout="LDAP 10.0.0.11 [+] bind ok (no match)")})
    td_ctx = _ctx(cfg, td_runner, tmp_path, composed=True)
    td = res.executor.teardown(td_ctx, res.teardown_obligation)
    assert any(Path(a[0]).name == "certipy-ad" and "delete" in a for a, _ in td_runner.calls)
    assert td["performed"] is True
