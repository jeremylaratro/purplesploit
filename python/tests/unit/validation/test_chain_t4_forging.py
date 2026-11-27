"""T4b composition: the DCSync -> GOLDEN forging chain.

The engine recovers the krbtgt signing key via DCSync and THREADS it in-memory
into a downstream GOLDEN edge, which forges a TGT with it and proves through the
forged ccache -> S_persistence. Driven with a scripted fake runner (no lab).

Asserts the chain is REAL and NON-VACUOUS:
  * reached S_persistence only through FRONT -> DCSYNC -> GOLDEN-TICKET;
  * GOLDEN actually forged with the DCSync-recovered krbtgt key (it appears in the
    live ticketer argv, i.e. it was threaded, not invented);
  * the forged ccache was the reauth credential (KRB5CCNAME named it);
  * the SECRET RULE holds across composition: the krbtgt AES key, the krbtgt NT
    hash, and the operator password never appear anywhere in the ChainReport;
  * fail-closed: with no front to produce the krbtgt key, GOLDEN is NOT reachable
    (it never forges on operator creds), and a failed forge does not reach the goal.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
    ValidationExecutor, ComposableResult, Capability, CAP_CCACHE,
)
from purplesploit.validation.engine import ChainEngine
from purplesploit.validation import states


_DC = "dc01.north.sevenkingdoms.local"
# Distinctive secrets that must NEVER reach the ChainReport.
KRBTGT_AES = "abad1dea" * 8                       # 64 hex = a krbtgt AES256 key
KRBTGT_NT = "0123456789abcdef0123456789abcdef"    # the krbtgt NT hash
OP_PW = "0per4t0r-Secret!"

# A DCSync dump that carries the krbtgt replication line AND the AES256 key line.
_DCSYNC_WITH_KEYS = (
    "[*] Dumping Domain Credentials\n"
    f"krbtgt:502:aad3b435b51404eeaad3b435b51404ee:{KRBTGT_NT}:::\n"
    "[*] Kerberos keys grabbed\n"
    f"north.sevenkingdoms.local\\krbtgt:aes256-cts-hmac-sha1-96:{KRBTGT_AES}\n"
    "krbtgt:aes128-cts-hmac-sha1-96:deadbeefdeadbeefdeadbeefdeadbeef\n")
# A dump that fails the krbtgt replication predicate (no complete record).
_DCSYNC_EMPTY = "[*] Dumping Domain Credentials\n[-] no data\n"


class _KrbFront(ValidationExecutor):
    """Minimal front that produces a DC_TGT ccache capability (what a real ADCS /
    shadow-creds front yields), so DCSync's precondition is met without modelling
    the front's own tooling."""
    technique = "KRB-FRONT"
    pre = frozenset({states.S0_USER_CREDS})
    eff = frozenset({states.DC_TGT})
    mutating = False

    def param_specs(self, ctx, finding):
        return []

    def execute(self, ctx, finding, params):
        return {}

    def run_composable(self, ctx, finding, overrides=None):
        receipt = {"technique": self.technique, "class": "fake", "complete": True,
                   "mutation": {"applied": False, "rollback": {"performed": False,
                                "verified": True, "method": None}},
                   "terminal_fact": None, "steps": [], "errors": []}
        cap = Capability(state=states.DC_TGT, channel=CAP_CCACHE,
                         value="/run/front/dc01.ccache", principal="dc01$")
        return ComposableResult(receipt=receipt, complete=True, capabilities=[cap],
                                teardown_obligation=None, executor=self)


class _ChainForgeRunner(CommandRunner):
    def __init__(self, dcsync_out=_DCSYNC_WITH_KEYS, make_ccache=True):
        self.dcsync_out = dcsync_out
        self.make_ccache = make_ccache
        self.calls: list[tuple[list[str], dict]] = []
        self.reauth_env: dict = {}

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append((list(argv), dict(env or {})))
        name = Path(argv[0]).name
        if name == "impacket-secretsdump":
            return RunResult(0, stdout=self.dcsync_out)
        if name == "impacket-lookupsid":
            return RunResult(0, stdout="[*] Domain SID is: S-1-5-21-111-222-333\n")
        if name == "impacket-ticketer":
            if self.make_ccache and cwd:
                p = Path(cwd) / f"{argv[-1]}.ccache"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"FORGED")
                return RunResult(0, stdout=f"[*] Saving ticket in {argv[-1]}.ccache\n")
            return RunResult(0, stdout="[*] skeleton ticket\n")
        if name == "nxc":
            self.reauth_env = dict(env or {})
            cc = (env or {}).get("KRB5CCNAME")
            if cc and Path(cc).exists():
                return RunResult(0, stdout="SMB  dc01  445  WS  "
                                 "[+] NORTH\\Administrator from ccache (Pwn3d!)\n")
            return RunResult(0, stdout="SMB  dc01  445  WS  [-] auth failed\n")
        return RunResult(0, stdout="")

    def ticketer_argv(self):
        return next((a for a, _ in self.calls if Path(a[0]).name == "impacket-ticketer"), None)

    def ran(self, tool):
        return any(Path(a[0]).name == tool for a, _ in self.calls)


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password=OP_PW, tool_timeout_s=5,
                host_aliases={_DC: {"host_id": "dc01"}})
    base.update(kw)
    return ValidationConfig(**base)


def _finding_for(edge):
    # Every real edge (DCSYNC reauth host; GOLDEN reauth_target) keys on the DC host.
    return map_finding({"finding_id": "KB-c", "host": _DC, "category": "kerberos",
                        "severity": "high", "line": f"krbtgt on {_DC}"})


def _ctx(cfg, runner, tmp_path):
    return ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _engine(runner, **kw):
    edges = [_KrbFront(), get_executor("DCSYNC"), get_executor("GOLDEN-TICKET")]
    return ChainEngine(edges, goal=states.S_PERSISTENCE, **kw)


# ============================================================ the positive chain

def test_dcsync_to_golden_chain_reaches_persistence(tmp_path):
    runner = _ChainForgeRunner()
    report = _engine(runner).run(_ctx(_cfg(), runner, tmp_path), _finding_for)
    assert report.reached is True
    d = report.to_dict()
    techs = [r.get("technique") for r in d.get("receipts", [])]
    assert techs == ["KRB-FRONT", "DCSYNC", "GOLDEN-TICKET"]
    # GOLDEN forged with the krbtgt key DCSync recovered (threaded, not invented)
    targv = runner.ticketer_argv()
    assert targv is not None and "-aesKey" in targv and KRBTGT_AES in targv
    # and authenticated THROUGH the forged ccache
    assert runner.reauth_env.get("KRB5CCNAME", "").endswith("Administrator.ccache")


def test_chain_report_carries_no_krbtgt_secret(tmp_path):
    # The secret rule must survive composition: nothing secret in the ChainReport.
    runner = _ChainForgeRunner()
    report = _engine(runner).run(_ctx(_cfg(), runner, tmp_path), _finding_for)
    assert report.reached is True
    blob = json.dumps(report.to_dict())
    assert KRBTGT_AES not in blob       # the threaded krbtgt AES key, never serialized
    assert KRBTGT_NT not in blob        # the krbtgt NT hash, never read into the report
    assert OP_PW not in blob            # the operator password, never stored


def test_dcsync_standalone_never_captures_the_key(tmp_path):
    # Non-composed DCSync stays presence-only: no key captured, no capability.
    runner = _ChainForgeRunner()
    res = get_executor("DCSYNC").run_composable(
        ExecutorContext(_cfg(), runner=runner, authorizer=AuthorizedLabProvider(True),
                        output_dir=tmp_path, composed=False),
        _finding_for(get_executor("DCSYNC")))
    assert res.complete is True
    assert res.capabilities == []       # no KRBTGT key threaded when not composing
    # and the receipt never carried the secret
    assert KRBTGT_AES not in json.dumps(res.receipt)


# ================================================================ fail-closed controls

def test_no_front_means_golden_is_unreachable(tmp_path):
    # Without a front to produce the krbtgt key, there is NO path to S_persistence:
    # GOLDEN never forges on operator creds (chain_pre={KRBTGT} is seed-unsatisfiable).
    runner = _ChainForgeRunner()
    edges = [get_executor("DCSYNC"), get_executor("GOLDEN-TICKET")]  # no front
    report = ChainEngine(edges, goal=states.S_PERSISTENCE).run(
        _ctx(_cfg(), runner, tmp_path), _finding_for)
    assert report.reached is False
    assert not runner.ran("impacket-ticketer")       # GOLDEN never forged


def test_failed_forge_does_not_reach_persistence(tmp_path):
    # DCSync recovers the key, but the forge produces no ccache -> GOLDEN does not
    # complete -> no S_persistence capability -> goal not reached.
    runner = _ChainForgeRunner(make_ccache=False)
    report = _engine(runner).run(_ctx(_cfg(), runner, tmp_path), _finding_for)
    assert report.reached is False


def test_failed_dcsync_means_no_key_and_no_reach(tmp_path):
    # DCSync fails its krbtgt predicate -> no KRBTGT produced -> GOLDEN unreachable.
    runner = _ChainForgeRunner(dcsync_out=_DCSYNC_EMPTY)
    report = _engine(runner).run(_ctx(_cfg(), runner, tmp_path), _finding_for)
    assert report.reached is False
    assert not runner.ran("impacket-ticketer")
