"""PLAN-C modular chaining engine (engine/chain_engine.py) -- driven with the REAL
N1 executors over scripted fakes (no lab), so the composition is proven real.

Pins the acceptance criteria:
* **Modularity** -- the search finds ESC8->DCSync, ESC11->DCSync AND
  Certifried->DCSync through the SAME reusable DCSync terminal, no hardcoded chain.
* **Threading (B1)** -- an executed ESC8->DCSync chain THREADS ESC8's issued
  ccache into DCSync (``KRB5CCNAME`` + the dc01$ principal), not the operator.
* **Deferred verified teardown (H4)** -- ESC8's mutation is rolled back + VERIFIED
  at chain teardown; an unverified teardown -> "DA proved but NOT clean".
* **Escalation vs given (H5)** -- a front->DCSync chain is an ESCALATION; the
  engine REFUSES a DA-granting seed (H5b).
* **No leak (H6)** -- the ChainReport carries no ccache path / secret.
* **Honest failure** -- an incomplete front yields no DA, no false proof.
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
    ValidationExecutor, ComposableResult,
)
from purplesploit.validation.executors.process_manager import ProcessManager, ProcHandle
from purplesploit.validation.engine import ChainEngine, ChainReport, default_edges, da_in_minutes
from purplesploit.validation.engine.chain_engine import OPERATOR_SEED, _StateEntry


# ============================================================ fakes / helpers
class _EnvRunner(CommandRunner):
    def __init__(self, script=None, save_ccache=True):
        self.script = script or {}
        self.calls: list[tuple[list[str], dict]] = []
        self.save_ccache = save_ccache

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append((list(argv), dict(env or {})))
        name = Path(argv[0]).name
        # Simulate certipy 'auth' saving the issued cert's key material in the run
        # dir, so it lands in whatever ISOLATED output dir the engine gave this
        # edge (no hard-coded path in the test). Guarded so a pre-seeded path
        # (e.g. a dir, to force a teardown failure) is left intact.
        if self.save_ccache and name == "certipy-ad" and "auth" in argv and cwd:
            d = Path(cwd); d.mkdir(parents=True, exist_ok=True)
            for fn in ("dc01.pfx", "dc01.ccache"):
                p = d / fn
                if not p.exists():
                    p.write_bytes(b"X")
        return self.script.get(name, RunResult(returncode=0, stdout=""))

    def call_for(self, tool):
        return next((a, e) for a, e in self.calls if Path(a[0]).name == tool)


class _FakePM(ProcessManager):
    def __init__(self, reads=None):
        self.reads = list(reads) if reads is not None else [""]
        self.started, self.stopped, self._ri = [], [], 0

    def start(self, argv, *, env=None, cwd=None) -> ProcHandle:
        self.started.append(list(argv))
        return ProcHandle(id=f"h{len(self.started)}")

    def read(self, handle) -> str:
        v = self.reads[min(self._ri, len(self.reads) - 1)]; self._ri += 1; return v

    def poll(self, handle):
        return None

    def stop(self, handle) -> str:
        self.stopped.append(handle.id)
        return self.reads[min(self._ri, len(self.reads) - 1)]


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip="10.0.0.11",
                username="jon.snow", password="iknownothing",
                poll_interval_s=0, tool_timeout_s=5,
                host_aliases={_DC: {"host_id": "dc01"}})
    base.update(kw)
    return ValidationConfig(**base)


_DC = "dc01.north.sevenkingdoms.local"
_DCSYNC_OK = ("[*] Dumping Domain Credentials\n"
              "krbtgt:502:aad3b435b51404eeaad3b435b51404ee:KRBTGThash00000000000000000000:::\n")


def _auth_stdout():
    return ("[*] Using principal: dc01$@north.sevenkingdoms.local\n[*] Got TGT\n"
            "[*] Saved credential cache to 'dc01.ccache'\n"
            "[*] Got hash for 'dc01$': aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\n")


def _adcs_finding():
    return map_finding({"finding_id": "AR-e8", "host": _DC, "category": "adcs",
                        "severity": "critical", "line": f"AD CS CA Web Enrollment on {_DC}"})


def _dc_finding():
    return map_finding({"finding_id": "AR-ds", "host": _DC, "category": "delegation",
                        "severity": "high", "line": f"domain controller {_DC}"})


def _finding_for(edge):
    return _dc_finding() if edge.technique == "DCSYNC" else _adcs_finding()


def _base_ctx(cfg, runner, tmp_path, pm):
    return ExecutorContext(cfg, runner=runner, authorizer=AuthorizedLabProvider(True),
                           output_dir=tmp_path, proc_manager=pm)


# ================================================================= modularity (search)
def test_search_finds_every_front_to_the_same_dcsync():
    engine = ChainEngine(default_edges())
    paths = [[e.technique for e in p] for p in engine.search()]
    assert ["ESC8", "DCSYNC"] in paths
    assert ["ESC11", "DCSYNC"] in paths
    assert ["CERTIFRIED", "DCSYNC"] in paths
    # every DA path terminates in the SAME reusable terminal b1.
    assert paths and all(p[-1] == "DCSYNC" for p in paths)


def test_search_shares_one_dcsync_edge_object():
    engine = ChainEngine(default_edges())
    terminals = {p[-1].technique for p in engine.search()}
    assert terminals == {"DCSYNC"}                         # one reusable terminal for all paths


def test_adding_no_goal_edge_gives_no_path():
    # Only fronts, no DCSync terminal -> S_DA unreachable -> empty search.
    fronts = [get_executor(t) for t in ("ESC8", "ESC11", "CERTIFRIED")]
    assert ChainEngine(fronts).search() == []


# ================================================================= B1 threading end-to-end
def test_da_chain_threads_front_ccache_into_dcsync(tmp_path):
    """The crux: the engine runs ESC8 then DCSync, and DCSync authenticates with
    ESC8's issued ccache (KRB5CCNAME + dc01$), NOT the operator. a1+b1 is REAL."""
    cfg = _cfg()
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$' (Base64 certificate: ...)"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout()),
                         "impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    # CERTIFRIED/ESC11 require a 'ca' the finding doesn't carry, so sequential
    # fallback skips them (each torn down if it mutated) and lands on ESC8 -- the
    # front needing no extra param -- then DCSync. Deterministic, not incidental.
    report = da_in_minutes(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    assert isinstance(report, ChainReport)
    assert report.reached is True and report.escalation is True
    assert report.path == ["ESC8", "DCSYNC"]
    # DCSync consumed the THREADED ccache (from ESC8's ISOLATED output dir):
    # KRB5CCNAME set + dc01$ principal, NOT the operator user.
    sd_argv, sd_env = runner.call_for("impacket-secretsdump")
    assert sd_env.get("KRB5CCNAME") == str(tmp_path / "ESC8" / "dc01.ccache")
    assert "-k" in sd_argv and "-no-pass" in sd_argv
    assert "dc01$" in sd_argv[-1].lower() and "jon.snow" not in sd_argv[-1]
    # two receipts carried for the scorer: the ESC8 front + the DCSYNC terminal.
    assert [r["technique"] for r in report.receipts] == ["ESC8", "DCSYNC"]


# ================================================================= H4 deferred verified teardown
def test_chain_teardown_is_deferred_and_verified(tmp_path):
    cfg = _cfg()
    pm = _FakePM(reads=["GOT certificate"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout()),
                         "impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    report = da_in_minutes(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    assert report.reached and report.clean is True
    assert "proved" in report.label.lower() and "clean" in report.label.lower()
    # ESC8's key material was destroyed at CHAIN teardown (not per-edge).
    td = {t["edge"]: t for t in report.teardown}
    assert "ESC8" in td and td["ESC8"]["performed"] and td["ESC8"]["verified"]
    assert not (tmp_path / "ESC8" / "dc01.pfx").exists()
    assert not (tmp_path / "ESC8" / "dc01.ccache").exists()
    # the ESC8 front receipt is reconciled with the chain teardown, so it scores
    # proved+clean standalone (not a dangling "rollback_unverified").
    esc8_rcpt = next(r for r in report.receipts if r["technique"] == "ESC8")
    assert esc8_rcpt["mutation"]["rollback"]["performed"] is True
    assert esc8_rcpt["mutation"]["rollback"]["verified"] is True


def test_chain_reports_not_clean_on_unverified_teardown(tmp_path):
    cfg = _cfg()
    # Pre-seed ESC8's isolated output dir with dc01.pfx as a DIR so its teardown
    # unlink fails -> rollback cannot verify. The runner leaves an existing path be.
    (tmp_path / "ESC8" / "dc01.pfx").mkdir(parents=True)
    pm = _FakePM(reads=["GOT certificate"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout()),
                         "impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    report = da_in_minutes(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    assert report.reached is True                          # DA still proved
    assert report.clean is False                           # ... but NOT clean (loud)
    assert "not clean" in report.label.lower()
    assert any(t["edge"] == "ESC8" and not t["verified"] for t in report.teardown)
    # the failed teardown is reflected in the receipt (never a false "clean").
    esc8_rcpt = next(r for r in report.receipts if r["technique"] == "ESC8")
    assert esc8_rcpt["mutation"]["rollback"]["verified"] is False


# ================================================================= H5 escalation vs given
def test_seed_refuses_da_granting_states():
    for bad in (states.DA_CREDS, states.DC_TGT, states.KRBTGT, states.S_DA):
        try:
            ChainEngine(default_edges(), seed=frozenset({states.S0_USER_CREDS, bad}))
            assert False, f"seed with {bad} must be refused (H5b)"
        except ValueError:
            pass


def test_escalation_detection_distinguishes_produced_from_seed():
    engine = ChainEngine(default_edges())
    dcsync = next(e for e in default_edges() if e.technique == "DCSYNC")
    # DC_TGT produced by a front -> escalation.
    produced = {states.DC_TGT: _StateEntry(capability=None, provenance="ESC8")}
    assert engine._satisfied_by_escalation(dcsync, produced) is True
    # the same state as an operator seed -> NOT an escalation (given creds).
    seeded = {states.DC_TGT: _StateEntry(capability=None, provenance=OPERATOR_SEED)}
    assert engine._satisfied_by_escalation(dcsync, seeded) is False


def test_given_creds_label_is_not_an_escalation_claim():
    engine = ChainEngine(default_edges())
    label = engine._label(reached=True, escalation=False, clean=True).lower()
    assert "given creds" in label and "no escalation" in label
    assert "escalation from operator creds" not in label     # not claimed an escalation


# ================================================================= honest failure + H6
def test_incomplete_front_yields_no_da(tmp_path):
    cfg = _cfg(tool_timeout_s=0)                           # bounded poll elapses at once
    pm = _FakePM(reads=[""])                               # no cert issued
    runner = _EnvRunner({"impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    report = da_in_minutes(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    assert report.reached is False and report.escalation is False
    assert "not reached" in report.label.lower()
    # the terminal DCSync never ran (the front did not produce DC_TGT).
    assert not any(Path(a[0]).name == "impacket-secretsdump" for a, _ in runner.calls)


def test_no_viable_path_is_honest():
    # An engine with no annotated edges at all -> no path, no false DA.
    report = ChainEngine([]).run(
        ExecutorContext(_cfg(), runner=_EnvRunner(), authorizer=AuthorizedLabProvider(True),
                        output_dir=Path("/tmp")), _finding_for)
    assert report.reached is False and report.clean is True
    assert report.label == "no viable path"


def test_chain_report_has_no_secret_payload(tmp_path):
    cfg = _cfg(password="Ch4inSecret!")
    pm = _FakePM(reads=["GOT certificate"])
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout=_auth_stdout()),
                         "impacket-secretsdump": RunResult(0, stdout=_DCSYNC_OK)})
    report = da_in_minutes(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    blob = json.dumps(report.to_dict())
    assert "Ch4inSecret!" not in blob                      # operator password never stored
    assert "dc01.ccache" not in blob and "dc01.pfx" not in blob   # ccache/pfx PATHS never in report
    assert "KRBTGThash00000000000000000000" not in blob   # krbtgt hash never read in
    assert report.to_dict()["schema"] == "adlab.plan003.chain.v1"


# ===================================================== review fixes (HIGH-1/2, MEDIUM-1)
def test_front_issuing_cert_without_ccache_gives_no_false_da(tmp_path):
    """HIGH-1: ESC8 issues a cert but PKINIT yields no usable ccache -> it produces
    no DC_TGT, so DCSync's precondition is NOT established, the path ends, and the
    terminal NEVER silently runs on operator creds. No false 'escalation'."""
    cfg = _cfg()
    pm = _FakePM(reads=["[*] GOT certificate for 'DC01$'"])          # cert IS issued
    runner = _EnvRunner({"certipy-ad": RunResult(0, stdout="[-] PKINIT failed: KDC_ERR")},
                        save_ccache=True)                            # ... but auth has no TGT/ccache marker
    engine = ChainEngine([get_executor("ESC8"), get_executor("DCSYNC")])
    report = engine.run(_base_ctx(cfg, runner, tmp_path, pm), _finding_for)
    assert report.reached is False and report.escalation is False    # NO false DA
    assert "not reached" in report.label.lower()
    # the terminal DCSync never ran -> no operator-cred fallback masquerading as escalation.
    assert not any(Path(a[0]).name == "impacket-secretsdump" for a, _ in runner.calls)
    # the issued cert was still torn down (honest cleanup even on a failed chain).
    assert report.clean is True


class _FakeEdge(ValidationExecutor):
    """Minimal controllable edge for the engine's clean/escalation accounting."""
    def __init__(self, technique, pre, eff, *, complete=True, produce=None,
                 mutated=False, defer_verified=True, inline_verified=None):
        self.technique = technique
        self.pre = frozenset(pre)
        self.eff = frozenset(eff)
        self.mutating = mutated
        self._complete, self._produce, self._mutated = complete, produce, mutated
        self._defer_verified, self._inline_verified = defer_verified, inline_verified

    def param_specs(self, ctx, finding):
        return []

    def execute(self, ctx, finding, params):
        return {}

    def run_composable(self, ctx, finding, overrides=None):
        rollback = {"performed": False, "verified": False, "method": None}
        obligation = None
        if self._mutated and self._inline_verified is not None:
            rollback = {"performed": True, "verified": self._inline_verified, "method": "inline"}
        elif self._mutated:
            obligation = {"paths": ["x"]}                            # deferred -> engine calls teardown()
        receipt = {"technique": self.technique, "class": "fake", "complete": self._complete,
                   "mutation": {"applied": self._mutated, "rollback": rollback},
                   "terminal_fact": None, "steps": [], "errors": []}
        caps = [self._produce] if (self._produce and self._complete) else []
        return ComposableResult(receipt=receipt, complete=self._complete,
                                capabilities=caps, teardown_obligation=obligation, executor=self)

    def teardown(self, ctx, obligation):
        return {"performed": True, "verified": self._defer_verified,
                "method": "fake-teardown", "note": ""}


def _fake_ctx():
    return ExecutorContext(_cfg(), runner=_EnvRunner(), authorizer=AuthorizedLabProvider(True),
                           output_dir=Path("/tmp"))


def test_inline_rollback_unverified_counts_against_clean():
    """MEDIUM-1: an edge that rolls back INLINE (no deferred obligation) with an
    UNVERIFIED result must still make the chain NOT clean -- the engine reads every
    receipt's mutation.rollback, not only the deferred teardown stack."""
    edge = _FakeEdge("INLINE_MUT", {states.S0_USER_CREDS}, {states.S_DA},
                     complete=True, mutated=True, inline_verified=False)
    report = ChainEngine([edge]).run(_fake_ctx(), lambda e: object())
    assert report.reached is True and report.clean is False
    assert report.teardown == []                             # no deferred obligation was registered
    assert "not clean" in report.label.lower()


def test_cross_path_leftover_mutation_is_not_hidden_by_later_clean_path():
    """HIGH-2: an earlier fallback path that leaves an UNVERIFIED mutation must not
    be hidden by a later clean path that reaches -- cleanliness is aggregated."""
    # both mutating so costs tie -> name order (AAA < ZZZ) runs the dirty path first.
    dirty = _FakeEdge("AAA_DIRTY", {states.S0_USER_CREDS}, {states.S_DA},
                      complete=False, mutated=True, defer_verified=False)   # mutates, fails, teardown unverified
    clean = _FakeEdge("ZZZ_CLEAN", {states.S0_USER_CREDS}, {states.S_DA},
                      complete=True, mutated=True, defer_verified=True)      # reaches, clean teardown
    report = ChainEngine([dirty, clean]).run(_fake_ctx(), lambda e: object())
    assert report.reached is True                            # the clean path reached DA
    assert report.clean is False                             # ... but the earlier leftover makes it NOT clean
    assert "not clean" in report.label.lower()
    assert any(t["edge"] == "AAA_DIRTY" and not t["verified"] for t in report.teardown)
