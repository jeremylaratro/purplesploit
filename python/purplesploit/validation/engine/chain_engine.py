"""The modular chaining engine (PLAN-C) -- reaches Domain Admin by SEARCH, not a
script. Composes the validated techniques (edges) over a capability-state graph:
an edge's ``eff`` (what it establishes) satisfies another edge's ``pre`` (what it
needs), so ``a1+b1`` and ``a2+b1`` both reach DA through the SAME reusable
terminal ``b1`` (DCSync) with no hardcoded chain.

Design (review-corrected, 25NOV2026):

* **Seed-restriction + provenance (H5b).** The seed state set is
  ``{S0_USER_CREDS}`` ONLY; the engine REFUSES ``DA_CREDS``/``DC_TGT`` as a seed.
  Every state in the store is tagged with provenance (the producing edge, or
  ``operator-seed``). A terminal whose ``pre`` is met only by an operator-seed
  credential is "DA given creds", NOT an escalation.
* **Typed-capability threading (B1/B2).** Each edge runs via
  :meth:`ValidationExecutor.run_composable`; its produced :class:`Capability`
  objects are routed BY CHANNEL into a FRESH per-edge context (ccache ->
  ``KRB5CCNAME`` + principal; nt_hash/aes_key -> the matching auth; principal ->
  target). A fresh context per edge (never a shared mutated one) keeps candidates
  independent.
* **Deferred, verified teardown (H3/H4).** A mutating edge DEFERS its rollback
  (``ctx.composed``); the engine registers the teardown obligation the instant
  the edge reports ``mutation.applied`` and, at chain end, drains EVERY obligation
  in reverse, requiring each rollback VERIFIED before it calls the chain "clean".
  An unverified teardown -> "DA proved but NOT clean" (loud), never silently clean.
* **No payload leak (H6).** :class:`ChainReport` serializes edge NAMES, the public
  per-edge ``proof.v1`` receipts, and teardown status ONLY. Capability payloads
  (ccache paths, hashes) live in the in-memory store and never reach the report.
* **Single best path for the first C (H4).** The engine executes ONE ranked path,
  not a top-k race (racing multiplies in-flight mutations + the cancelled-sibling
  teardown window); racing is a later addition once cancelled-sibling verified
  teardown is proven.

The engine does NOT grade proof -- the ad-lab-harness scorer is the independent
judge. The engine reports which path it took and carries the receipts; the scorer
reads them as proved/not-proved/inconclusive.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Any, Callable, Optional

from .. import states
from ..executors.base import (
    ValidationExecutor, ExecutorContext, Capability,
    CAP_CCACHE, CAP_NT_HASH, CAP_AES_KEY, CAP_PRINCIPAL, CAP_NONE,
)

OPERATOR_SEED = "operator-seed"


# ---------------------------------------------------------------- state store
@dataclass
class _StateEntry:
    """A capability-state the chain has established, with its provenance (H5b)."""
    capability: Optional[Capability]     # machine-consumable artifact (in-memory only)
    provenance: str                      # producing edge-id, or OPERATOR_SEED


# ---------------------------------------------------------------- report
@dataclass
class ChainReport:
    """The PUBLIC outcome of a chain run (H6: names + receipts + teardown only).

    Carries NO capability payloads (ccache paths, hashes) -- those stayed in the
    engine's in-memory store. ``receipts`` are the ordered per-edge ``proof.v1``
    receipts the harness scorer independently grades.
    """
    goal: str
    reached: bool                        # did the chain complete to the goal state?
    escalation: bool                     # True = privilege was ESCALATED (not operator-given DA)
    clean: bool                          # True = every mutation rolled back AND verified
    path: list[str] = field(default_factory=list)          # edge NAMES in order
    receipts: list[dict] = field(default_factory=list)     # public per-edge receipts
    teardown: list[dict] = field(default_factory=list)     # per-edge {edge, performed, verified, note}
    label: str = ""
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "adlab.plan003.chain.v1",
            "goal": self.goal, "reached": self.reached, "escalation": self.escalation,
            "clean": self.clean, "label": self.label, "note": self.note,
            "path": list(self.path),
            "teardown": list(self.teardown),
            "receipts": list(self.receipts),   # already-scrubbed public receipts
        }


# ---------------------------------------------------------------- engine
FindingFor = Callable[[ValidationExecutor], Any]   # edge -> a finding (or None if none)


class ChainEngine:
    """Search the capability-state graph for a path to ``goal`` and execute it.

    ``edges`` are the executors that may participate -- only those with a non-empty
    ``pre`` AND ``eff`` (annotated for C) and that pass the crack/destructive HARD
    FILTERS (Q4). ``seed`` is the starting state set (defaults to the single
    ``S0_USER_CREDS``; a ``DA_CREDS``/``DC_TGT`` seed is refused, H5b).
    """

    def __init__(self, edges: list[ValidationExecutor], *,
                 goal: str = states.S_DA,
                 seed: frozenset = frozenset({states.S0_USER_CREDS}),
                 allow_crack: bool = False, allow_destructive: bool = False):
        forbidden = seed & {states.DA_CREDS, states.DC_TGT, states.KRBTGT, states.S_DA}
        if forbidden:
            raise ValueError(
                f"seed may not grant escalation states {sorted(forbidden)} (H5b: "
                "the engine proves escalation from operator creds, never seeds DA)")
        self.goal = goal
        self.seed = frozenset(seed)
        self.edges = [e for e in edges if self._edge_allowed(e, allow_crack, allow_destructive)]

    @staticmethod
    def _edge_allowed(e: ValidationExecutor, allow_crack: bool, allow_destructive: bool) -> bool:
        if not (e.pre and e.eff):
            return False                                     # un-annotated -> never participates
        if getattr(e, "crack_dependent", False) and not allow_crack:
            return False                                     # HARD FILTER (Q4), not a multiplier
        if getattr(e, "destructive", False) and not allow_destructive:
            return False                                     # HARD FILTER (Q4)
        return True

    # ------------------------------------------------------------ cost / search
    @staticmethod
    def _edge_cost(e: ValidationExecutor) -> float:
        # Prefer proven recipes and non-mutating edges; shorter paths win on sum.
        return 1.0 + (0.0 if e.verified_recipe else 0.5) + (0.3 if e.mutating else 0.0)

    @staticmethod
    def _applicable(e: ValidationExecutor, have: frozenset) -> bool:
        # OR-precondition semantics: an edge fires when ANY of its pre-states is
        # held (DCSync.pre={DC_TGT, DA_CREDS} means "either satisfies"). This
        # matches the N1 edge model (test_front_eff_satisfies_dcsync_pre).
        return bool(e.pre & have)

    def search(self) -> list[list[ValidationExecutor]]:
        """All simple edge paths ``seed -> ... -> goal``, ranked cheapest-first.
        No path is baked in: adding an annotated edge makes it participate
        automatically."""
        results: list[tuple[float, int, list[ValidationExecutor]]] = []

        def dfs(have: frozenset, path: list[ValidationExecutor], cost: float):
            if self.goal in have:
                results.append((cost, len(path), list(path)))
                return
            if len(path) >= len(self.edges):                 # no simple path longer than |edges|
                return
            for e in self.edges:
                if e in path or not self._applicable(e, have):
                    continue
                new_have = have | e.eff
                if new_have == have:                         # edge added nothing -> prune
                    continue
                dfs(new_have, path + [e], cost + self._edge_cost(e))

        dfs(self.seed, [], 0.0)
        results.sort(key=lambda r: (r[0], r[1], [x.technique for x in r[2]]))
        return [p for _, _, p in results]

    # ------------------------------------------------------------ threading
    @staticmethod
    def _thread_caps(edge: ValidationExecutor, store: dict[str, _StateEntry]
                     ) -> tuple[dict[str, Any], dict[str, str]]:
        """Build the edge's ``input_caps`` + ``env`` by routing the stored
        capabilities for the pre-states this edge consumes (B2 per-channel)."""
        input_caps: dict[str, Any] = {}
        env: dict[str, str] = {}
        for st in edge.pre:
            entry = store.get(st)
            cap = entry.capability if entry else None
            if cap is None:
                continue
            if cap.channel == CAP_CCACHE and cap.value:
                input_caps["ccache"] = cap.value
                env["KRB5CCNAME"] = cap.value
            elif cap.channel == CAP_NT_HASH and cap.value:
                input_caps["nt_hash"] = cap.value
            elif cap.channel == CAP_AES_KEY and cap.value:
                input_caps["aes_key"] = cap.value
            elif cap.channel == CAP_PRINCIPAL and cap.value:
                input_caps["principal"] = cap.value
            if cap.principal and "principal" not in input_caps:
                input_caps["principal"] = cap.principal
        return input_caps, env

    def _satisfied_by_escalation(self, edge: ValidationExecutor,
                                 store: dict[str, _StateEntry]) -> bool:
        """H5: True iff ANY pre-state satisfying this edge was PRODUCED by a prior
        edge (a real escalation) rather than only an operator-seed credential."""
        for st in (edge.pre & frozenset(store)):
            if store[st].provenance != OPERATOR_SEED:
                return True
        return False

    # ------------------------------------------------------------ run
    def run(self, base_ctx: ExecutorContext, finding_for: FindingFor) -> ChainReport:
        """Execute candidate paths cheapest-first until one reaches the goal.

        This is SEQUENTIAL fallback, NOT a race (H4): one path runs at a time and
        every mutation it made is torn down + verified BEFORE the next path is
        attempted, so live mutations are never multiplied and there is no
        cancelled-sibling teardown window. The first path that reaches the goal is
        returned; otherwise the last (honest failure)."""
        paths = self.search()
        if not paths:
            return ChainReport(goal=self.goal, reached=False, escalation=False, clean=True,
                               label="no viable path",
                               note="no annotated edge path from the seed reaches the goal")
        last: Optional[ChainReport] = None
        for path in paths:
            report = self._run_one(base_ctx, finding_for, path)
            if report.reached:
                return report
            last = report
        return last if last is not None else ChainReport(
            goal=self.goal, reached=False, escalation=False, clean=True, label="no viable path")

    def _run_one(self, base_ctx: ExecutorContext, finding_for: FindingFor,
                 path: list[ValidationExecutor]) -> ChainReport:
        """Execute ONE path: thread capabilities edge->edge, then tear down every
        mutation (verified). An edge that cannot be parameterized or does not
        complete ends the path; its mutations are still torn down."""
        store: dict[str, _StateEntry] = {
            s: _StateEntry(capability=None, provenance=OPERATOR_SEED) for s in self.seed}
        receipts: list[dict] = []
        teardown_stack: list[tuple[ValidationExecutor, dict, ExecutorContext]] = []
        reached = False
        escalation = False
        fail_note = ""

        for edge in path:
            finding = finding_for(edge)
            if finding is None:
                fail_note = f"no finding available for edge {edge.technique}"
                break
            input_caps, env = self._thread_caps(edge, store)
            # FRESH per-edge context (never a shared mutated one), composed=True so
            # mutating fronts DEFER rollback to our teardown.
            ctx = replace(base_ctx, input_caps=input_caps, env=env, composed=True)

            # Record whether THIS edge's completion is a real escalation (its pre
            # was met by a produced state) before we add its own effects.
            edge_escalation = self._satisfied_by_escalation(edge, store)

            try:
                result = edge.run_composable(ctx, finding)
            except Exception as exc:                         # e.g. required param absent
                fail_note = f"edge {edge.technique} could not run: {type(exc).__name__}: {exc}"
                break
            receipts.append(result.receipt)

            # H4: register the teardown obligation the instant a mutation applied
            # (mutation.applied is in the just-built receipt), BEFORE anything else.
            # Carry the receipt so teardown can reconcile its rollback status.
            if result.teardown_obligation:
                teardown_stack.append((edge, result.teardown_obligation, ctx, result.receipt))

            if not result.complete:
                fail_note = f"edge {edge.technique} did not complete"
                break

            # Route produced capabilities into the store (provenance = this edge).
            for cap in result.capabilities:
                store[cap.state] = _StateEntry(capability=cap, provenance=edge.technique)
            # A non-producing edge that still established effects (e.g. the DCSync
            # terminal) marks its eff states as reached-by-this-edge.
            for st in edge.eff:
                store.setdefault(st, _StateEntry(capability=None, provenance=edge.technique))

            if self.goal in edge.eff:
                reached = True
                escalation = edge_escalation
                break                                        # early-exit at first goal (H4)

        # ---- teardown: drain EVERY obligation in reverse, VERIFY each (H4) ----
        teardown_log: list[dict] = []
        clean = True
        for edge, obligation, ctx, receipt in reversed(teardown_stack):
            td = edge.teardown(ctx, obligation)
            performed, verified = bool(td.get("performed")), bool(td.get("verified"))
            teardown_log.append({"edge": edge.technique, "performed": performed,
                                 "verified": verified, "method": td.get("method"),
                                 "note": td.get("note", "")})
            # Reconcile the front receipt's rollback with the ACTUAL chain-teardown
            # result, so a composed front receipt is self-consistent and the harness
            # scorer grades it the same standalone as the chain reports it. This
            # records a true event (the chain really did tear this mutation down);
            # a FAILED teardown leaves verified=False -> the scorer keeps it
            # inconclusive, never a false "clean".
            mut = receipt.get("mutation") if isinstance(receipt, dict) else None
            if isinstance(mut, dict):
                rb = mut.setdefault("rollback", {})
                rb["performed"] = performed
                rb["verified"] = verified
                if td.get("method"):
                    rb["method"] = td["method"]
            if not verified:
                clean = False

        return self._report(reached, escalation, clean, path, receipts,
                            teardown_log, fail_note)

    def _report(self, reached, escalation, clean, path, receipts, teardown_log,
                fail_note) -> ChainReport:
        if reached and escalation and clean:
            label = "DA proved (escalation from operator creds) and clean"
        elif reached and escalation and not clean:
            label = "DA proved (escalation) but NOT clean -- mutation left behind"
        elif reached and not escalation:
            label = "DA given creds (no escalation) -- terminal met by operator-seed cred"
        else:
            label = "DA not reached"
        return ChainReport(
            goal=self.goal, reached=reached, escalation=escalation, clean=clean,
            path=[e.technique for e in path], receipts=receipts, teardown=teardown_log,
            label=label, note=fail_note)
