"""The ValidationExecutor interface, command runner, and authorization gate.

Each executor encodes one PROVEN per-technique recipe (claude-mem #66146) as a
*parameterized* chain of steps, captures a non-secret terminal predicate, runs a
*verified rollback* if it mutated AD, and returns a loose artifact that
:mod:`purplesploit.validation.proof` turns into a ``proof.v1`` receipt.

Design points:

* **Command execution is injected** (:class:`CommandRunner`) so an executor is
  unit-testable with a scripted fake and never has to touch a live lab.
  ``SubprocessRunner`` is the real adapter; secrets are kept out of the stored
  ``argv_display`` via :func:`redact_argv`.
* **exit 0 is never proof.** An executor decides each step's ``ok`` from a
  predicate over the tool's output, not from its return code.
* **Mutating ops are gated** (:class:`AuthorizationProvider`, per #66119/#66120):
  on a ``denied`` verdict the executor stops and emits an incomplete receipt
  (the scorer reads that as ``inconclusive``/``gate_denied``) -- it never works
  around a denial.
"""
from __future__ import annotations

import subprocess
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ..config import ValidationConfig
from ..recommend import ParamSpec, ParamValue, resolve_params, params_preview
from ..predicates import strip_ansi
from .. import proof
from .process_manager import (ProcessManager, SubprocessProcessManager, ProcHandle,
                              poll_for_capture)


# ------------------------------------------------------------------ command runner
@dataclass
class RunResult:
    """What a single tool invocation returned (runtime only -- not serialized)."""
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None


# ------------------------------------------------------------------ capability output
# Channels the chaining engine (C) knows how to route into a downstream edge.
CAP_CCACHE = "ccache"       # a Kerberos credential-cache PATH -> KRB5CCNAME + ccache param
CAP_NT_HASH = "nt_hash"     # an NT hash (SECRET) -> -hashes, in-memory only
CAP_AES_KEY = "aes_key"     # an AES key (SECRET) -> -aesKey -k, in-memory only
CAP_PRINCIPAL = "principal" # the principal a cred acts as (e.g. "dc01$") -> target principal
CAP_CONTROL = "control"   # a typed, object/right-bound grant, never an auth credential
CAP_NONE = "none"           # a state established with no machine-consumable artifact
CAP_CHANNELS = frozenset({CAP_CCACHE, CAP_NT_HASH, CAP_AES_KEY, CAP_PRINCIPAL, CAP_CONTROL, CAP_NONE})

# Channels whose VALUE is a secret and must never be serialized into a receipt /
# ChainReport. A ccache PATH is project-marked secret too (it names bearer key
# material on disk), so the engine keeps it in-memory and out of any report (H6).
_SECRET_CHANNELS = frozenset({CAP_NT_HASH, CAP_AES_KEY, CAP_CCACHE})


@dataclass(frozen=True)
class ControlGrant:
    actor: str
    object: str
    right: str
    lifetime: str = "until teardown"


@dataclass(frozen=True)
class Capability:
    """A typed, machine-consumable artifact a front produced for a state it
    established, so the engine can THREAD it into a downstream edge by channel
    (review B2). Runtime only -- NEVER serialized; the engine routes it in-memory
    and the proof receipt carries only public identifiers.

    ``state``      -- the capability-state (``states.*``) this satisfies.
    ``channel``    -- how the engine feeds it downstream (one of ``CAP_*``).
    ``value``      -- the concrete artifact (a ccache PATH, an NT hash, ...). May
                      be a SECRET (see :data:`_SECRET_CHANNELS`).
    ``principal``  -- the principal this credential acts as (e.g. ``dc01$``), so a
                      downstream DCSync authenticates as the right identity (B1).
    """
    state: str
    channel: str = CAP_NONE
    value: Any = None
    principal: Optional[str] = None
    provenance: tuple[str, ...] = ()  # assigned once by the engine; aliases retain it

    @property
    def secret(self) -> bool:
        return self.channel in _SECRET_CHANNELS

    def __post_init__(self):
        if self.channel not in CAP_CHANNELS:
            raise ValueError(f"unknown capability channel: {self.channel!r}")


# Flags whose following token is a secret and must be masked in any stored argv.
# ``-H`` (NetExec/bloodyAD hash) and ``--aesKey`` (NetExec AES key, double-dash
# camelCase form) are included for the D2 nxc/bloodyAD fallbacks below.
_SECRET_FLAGS = frozenset({
    "-p", "--password", "-hashes", "-H", "--hash", "-aesKey", "--aesKey",
    "--aes-key", "-computer-pass", "-pfx", "-password", "-pass",
})


def redact_argv(argv: list[str]) -> list[str]:
    """Mask secret-bearing tokens so an argv can be shown/stored safely.

    Masks the token after a known secret flag, and any ``domain/user:password``
    authentication target (the ``:password`` part only).
    """
    out: list[str] = []
    mask_next = False
    for token in argv:
        if mask_next:
            out.append("***")
            mask_next = False
            continue
        if token in _SECRET_FLAGS:
            out.append(token)
            mask_next = True
            continue
        # impacket auth target: domain/user:password[@host]
        if "/" in token and ":" in token.split("/", 1)[1]:
            head, tail = token.split("/", 1)
            user, _, rest = tail.partition(":")
            host = ""
            if "@" in rest:
                _, host = rest.split("@", 1)
                host = "@" + host
            out.append(f"{head}/{user}:***{host}")
            continue
        # smbclient/winexe auth value: [DOMAIN\]user%password -> mask the
        # password after '%'. Excludes flags and anything with a '/' (UNC paths
        # like //host/share and impacket targets are handled above / left alone).
        if "%" in token and "/" not in token and not token.startswith("-"):
            user_part, _, password = token.partition("%")
            if user_part and password:
                out.append(f"{user_part}%***")
                continue
        out.append(token)
    return out


class CommandRunner(ABC):
    """Runs a tool argv and returns a :class:`RunResult`. Injected for testing."""

    @abstractmethod
    def run(self, argv: list[str], *, env: Optional[dict[str, str]] = None,
            timeout: Optional[int] = None, cwd: Optional[str] = None) -> RunResult:
        ...


class SubprocessRunner(CommandRunner):
    """Real adapter: runs the Kali tooling on PATH via ``subprocess``.

    Assumes it runs where impacket-*, certipy-ad, bloodyad, nxc, hashcat are on
    PATH (e.g. the Kali container -- claude-mem #66146). Captures stdout/stderr;
    a timeout or OSError becomes a non-crashing :class:`RunResult`.
    """

    def __init__(self, default_timeout: int = 300, base_env: Optional[dict] = None):
        self.default_timeout = default_timeout
        self.base_env = base_env

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        import os
        merged = dict(os.environ if self.base_env is None else self.base_env)
        if env:
            merged.update({k: v for k, v in env.items() if v is not None})
            for k, v in env.items():
                if v is None:
                    merged.pop(k, None)  # honor explicit unset (e.g. KRB5CCNAME)
        try:
            proc = subprocess.run(
                list(argv), capture_output=True, text=True, cwd=cwd, env=merged,
                timeout=timeout or self.default_timeout, check=False,
            )
            # Strip ANSI at the boundary so every executor's predicate matches
            # clean output regardless of the tool's colour/terminal formatting.
            return RunResult(returncode=proc.returncode,
                             stdout=strip_ansi(proc.stdout), stderr=strip_ansi(proc.stderr))
        except subprocess.TimeoutExpired as exc:
            return RunResult(returncode=None, stdout=strip_ansi(exc.stdout),
                             stderr=strip_ansi(exc.stderr), timed_out=True,
                             error="timeout")
        except OSError as exc:
            return RunResult(returncode=None, error=f"{type(exc).__name__}: {exc}")


# ------------------------------------------------------------------ D2 tool fallback
@dataclass
class ToolAttempt:
    """One tool candidate in an ordered D2 fallback chain (ADR-002 D2, light).

    ``success`` is a POSITIVE predicate over the :class:`RunResult` -- did this
    tool actually achieve the step? It is the real success marker (e.g. a hash
    blob or a write-confirmation), never a bare exit code, so a fallback can
    never mask a confident negative as success.
    """
    tool: str                                       # short label for the step note
    argv: list[str]
    success: Callable[[RunResult], bool]            # positive "did it work?" predicate
    env: Optional[dict] = None
    cwd: Optional[str] = None


# Substrings in ``RunResult.error`` that mean the tool binary was not found.
_ABSENT_MARKERS = ("filenotfounderror", "no such file", "not found")


def _tool_absent(res: RunResult) -> bool:
    """True iff ``res`` indicates the tool binary was missing (PATH absence)."""
    err = (res.error or "").lower()
    return any(marker in err for marker in _ABSENT_MARKERS)


def first_successful(runner: CommandRunner, attempts: list[ToolAttempt],
                     timeout: Optional[int] = None) -> tuple[ToolAttempt, RunResult, bool]:
    """Light D2 tool fallback. Try each ToolAttempt in order. An attempt whose tool
    is ABSENT (RunResult.error containing FileNotFoundError / 'No such file' / 'not found')
    or HUNG (res.timed_out) is skipped to the next in the chain. The first attempt whose
    success(res) is True wins -> return (att, res, True). If none succeed, return the FIRST
    attempt that actually RAN (for honest failure reporting) with ok=False; if every tool
    was absent, return (attempts[0], RunResult(returncode=None, error='no fallback tool available'), False).
    A clean primary that simply produced no positive result (ran, success False, not absent)
    is a trusted negative -- but still try the remaining attempts before giving up, since a
    different tool may succeed where the primary's output format/version differed.

    "Actually RAN" means the attempt was not a tool-absence -- a clean negative OR a
    hang both count, so the no-fallback sentinel fires *exactly* when every tool was
    absent (never when a present tool merely hung or returned nothing).
    """
    first_ran: Optional[tuple[ToolAttempt, RunResult]] = None
    for att in attempts:
        res = runner.run(att.argv, env=att.env, timeout=timeout, cwd=att.cwd)
        if _tool_absent(res):
            continue                                 # binary missing -> next in chain
        if first_ran is None:
            first_ran = (att, res)                   # honest-failure candidate (ran or hung)
        if res.timed_out:
            continue                                 # hung -> next in chain, don't test success
        if att.success(res):
            return att, res, True                    # first positive result wins (short-circuit)
    if first_ran is None:                            # every tool was absent
        return (attempts[0],
                RunResult(returncode=None, error="no fallback tool available"), False)
    att, res = first_ran                             # a trusted negative / hang, honestly reported
    return att, res, False


# ------------------------------------------------------------------ authorization gate
class AuthorizationProvider(ABC):
    """Decides whether a gated op may proceed (per the #66119/#66120 protocol)."""

    @abstractmethod
    def authorize(self, op: str, detail: dict[str, Any]) -> str:
        """Return one of ``approved`` / ``denied`` / ``not_required``."""


class AuthorizedLabProvider(AuthorizationProvider):
    """Treats every op as ``not_required`` when the engagement is authorized.

    Default for an authorized lab (``config.authorized``); when not authorized it
    denies, so an executor fails closed rather than acting without authorization.
    """

    def __init__(self, authorized: bool = True):
        self.authorized = authorized

    def authorize(self, op, detail) -> str:
        return "not_required" if self.authorized else "denied"


# ------------------------------------------------------------------ destructive gate
class DestructiveConfirmationProvider(ABC):
    """Decides whether a destructive (irreversible / code-exec) op may proceed.

    A *per-call runtime* gate, layered ON TOP OF the chaining engine's static
    ``destructive``/``crack_dependent`` eligibility filters (``chain_engine.py``'s
    ``_edge_allowed``) -- the two answer different questions and both apply
    (T3 plan §4.3): the static filter decides whether an executor CLASS may even
    be considered by a composed search; this gate decides whether THIS specific,
    already-resolved invocation (e.g. GENERIC-ALL's ``reset_password`` pivot,
    FORCE-CHANGE-PASSWORD, GPO-ABUSE's SYSVOL write) may actually fire.
    """

    @abstractmethod
    def confirm(self, op: str, detail: dict[str, Any]) -> bool: ...


class InteractiveDestructiveConfirmer(DestructiveConfirmationProvider):
    """Prints a loud warning; blocks on an EXACT 'yes' typed by the operator.

    Fail-closed on EOF (no input available) -- never silently proceeds."""

    def __init__(self, prompt_fn: Callable[[str], str] = input,
                 warn_fn: Optional[Callable[[str], None]] = None):
        self.prompt_fn = prompt_fn
        self.warn_fn = warn_fn or (lambda s: print(s, file=sys.stderr))

    def confirm(self, op: str, detail: dict[str, Any]) -> bool:
        self.warn_fn(f"\n*** DESTRUCTIVE OPERATION ***\nop: {op}\ndetail: {detail}\n"
                      "This is IRREVERSIBLE and/or executes code on a live host.\n")
        try:
            answer = self.prompt_fn("Type 'yes' to proceed, anything else to abort: ")
        except EOFError:
            self.warn_fn(f"[DESTRUCTIVE] {op}: no input available (EOF) -- refusing (fail closed)")
            return False
        return answer.strip() == "yes"


class NonInteractiveDestructiveConfirmer(DestructiveConfirmationProvider):
    """For headless/automated runs ONLY. Fail-closed: proceeds iff explicitly
    pre-authorized via ``config.allow_destructive`` -- never prompts, never
    silently defaults to True. Always prints the warning (visible in logs/output
    either way)."""

    def __init__(self, allowed: bool, warn_fn: Optional[Callable[[str], None]] = None):
        self.allowed = allowed
        self.warn_fn = warn_fn or (lambda s: print(s, file=sys.stderr))

    def confirm(self, op: str, detail: dict[str, Any]) -> bool:
        self.warn_fn(
            f"[DESTRUCTIVE] {op}: {detail} -- non-interactive run; "
            + ("allow_destructive is set, proceeding" if self.allowed
               else "allow_destructive NOT set, refusing"))
        return self.allowed is True


# ------------------------------------------------------------------ executor context
@dataclass
class ExecutorContext:
    """Everything an executor needs at run time, assembled by the orchestrator.

    ``proc_manager`` is the ADR-001 chassis extension: an injected background
    :class:`ProcessManager` for listener-based executors (COERCION, NTLM-RELAY,
    UNCONSTRAINED-DELEG). It is additive and optional -- it defaults to a real
    :class:`SubprocessProcessManager`, so the eight synchronous executors and
    every existing call site are untouched; tests inject a scripted fake.

    ``destructive_confirmer`` is the T3 per-call runtime gate (see
    :class:`DestructiveConfirmationProvider`). ``__post_init__`` defaults it,
    fail-closed, to a :class:`NonInteractiveDestructiveConfirmer` keyed on
    ``config.allow_destructive`` -- so a bare ``ExecutorContext`` built with
    nothing injected (e.g. a unit test) NEVER prompts and NEVER silently allows.
    """
    config: ValidationConfig
    runner: CommandRunner
    authorizer: AuthorizationProvider
    output_dir: Any                      # pathlib.Path for this run's receipts/ccache
    proc_manager: ProcessManager = field(default_factory=SubprocessProcessManager)
    destructive_confirmer: Optional["DestructiveConfirmationProvider"] = None
    # -- composition slots (review B1/B3): empty/False for every standalone run,
    #    so the 15 executors and every existing call site are untouched. The
    #    chaining engine (C) populates them per edge when composing a chain.
    input_caps: dict[str, Any] = field(default_factory=dict)  # threaded creds: ccache/nt_hash/aes_key/principal
    env: dict[str, str] = field(default_factory=dict)         # extra env (e.g. KRB5CCNAME=<ccache>) forwarded to runner
    composed: bool = False                                    # True => mutating fronts DEFER rollback to chain teardown

    _private_errors: list[str] = field(default_factory=list, repr=False)
    _pending_teardown: Optional[dict] = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.destructive_confirmer is None:
            self.destructive_confirmer = NonInteractiveDestructiveConfirmer(
                allowed=getattr(self.config, "allow_destructive", False))


# ------------------------------------------------------------------ step / plan records
@dataclass
class StepRecord:
    """One executed (or previewed) chain step."""
    name: str
    ok: bool = False
    argv_display: list[str] = field(default_factory=list)   # redacted, safe to store
    returncode: Optional[int] = None
    note: str = ""

    def as_step(self) -> dict:
        return {"name": self.name, "ok": self.ok}


@dataclass
class ValidationPlan:
    """An operator-facing preview of what an executor would do (no execution)."""
    technique: str
    technique_class: str
    target: dict[str, Any]
    mutating: bool
    terminal_kind: str
    params: dict[str, ParamValue]
    steps_preview: list[str]
    verified_recipe: bool
    recipe_ref: str
    finding_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique": self.technique,
            "class": self.technique_class,
            "target": self.target,
            "mutating": self.mutating,
            "terminal_kind": self.terminal_kind,
            "verified_recipe": self.verified_recipe,
            "recipe_ref": self.recipe_ref,
            "finding": self.finding_summary,
            "params": params_preview(self.params),
            "steps": self.steps_preview,
        }


@dataclass
class ComposableResult:
    """What the chaining engine (C) gets back from one composed edge run.

    Splits the PUBLIC, serializable receipt from the SECRET, engine-only products:
    ``capabilities`` (typed creds threaded downstream in-memory) and
    ``teardown_obligation`` (secret key-material paths for the deferred rollback).
    Neither of the latter two is ever written into a ChainReport (H6)."""
    receipt: dict
    complete: bool
    capabilities: list = field(default_factory=list)   # list[Capability], in-memory only
    teardown_obligation: Optional[dict] = None          # secret paths, engine-only
    executor: Optional["ValidationExecutor"] = None     # for the engine to invoke .teardown()


class StubNotImplemented(NotImplementedError):
    """Raised by a stub executor's ``execute`` -- the recipe is documented, not wired."""


# ------------------------------------------------------------------ executor ABC
class ValidationExecutor(ABC):
    """Base class: parameterize a recipe, execute it, emit a proof.v1 receipt.

    Subclass attributes:
      ``technique`` / ``technique_class`` -- keys into the proof-truth facet.
      ``terminal_kind``   -- one of :data:`proof.TERMINAL_KINDS`.
      ``mutating``        -- True if the chain changes AD (requires rollback).
      ``verified_recipe`` -- True if the recipe was PROVEN end-to-end (#66146).
      ``recipe_ref``      -- the #66146 recipe string this executor encodes.
    """
    technique: str = ""
    technique_class: str = ""
    terminal_kind: str = ""
    mutating: bool = False
    # T3: irreversible / code-exec op -- a STATIC, engine-level eligibility flag
    # (chain_engine.py's _edge_allowed reads this via getattr; declaring it here
    # promotes that defensive read to a real, documented attribute every
    # executor can see and override, same footing as `mutating`). Per-call, the
    # separate RUNTIME gate is ctx.destructive_confirmer (see base.py above).
    destructive: bool = False
    verified_recipe: bool = False
    recipe_ref: str = ""
    # Capability-state metadata for the chaining engine (C). Default empty so an
    # un-annotated executor simply never participates in a composed path; the N1
    # fronts + the C tranche set these over ``states`` constants.
    pre: frozenset = frozenset()
    eff: frozenset = frozenset()

    # -- interface subclasses implement --------------------------------------
    @abstractmethod
    def param_specs(self, ctx: ExecutorContext, finding) -> list[ParamSpec]:
        """Overridable params for this finding, each with a recommended default."""

    @abstractmethod
    def execute(self, ctx: ExecutorContext, finding, params: dict[str, ParamValue]) -> dict:
        """Run the recipe; return a loose artifact
        (``{steps, gate, mutation, terminal_fact, complete, errors}``)."""

    def target_identity(self, ctx: ExecutorContext, finding,
                        params: dict[str, ParamValue]) -> dict[str, Any]:
        """Identity dict for proof-truth matching. Default: the finding host.

        Override where the chain acts on a param-supplied host (e.g. RBCD's
        ``delegate_to``) rather than the finding's own host.
        """
        host = finding.host or ""
        return ctx.config.resolve_target_identity(host) if host else dict(finding.entity)

    def steps_preview(self, ctx: ExecutorContext, finding,
                      params: dict[str, ParamValue]) -> list[str]:
        """Human-readable step preview for the confirmation screen. Optional."""
        return [self.recipe_ref] if self.recipe_ref else []

    # -- composition hooks (review B2/B3) -- default no-ops -------------------
    def produced(self, ctx: ExecutorContext, finding,
                 params: dict[str, ParamValue], artifact: dict) -> list[Capability]:
        """Typed capabilities this edge established, for the engine to THREAD into
        a downstream edge (B2). Default: none -- a non-composable executor. A
        front overrides this to expose its ccache/hash/principal; the engine
        routes each by channel and keeps secret values in-memory only."""
        return []

    def teardown(self, ctx: ExecutorContext, obligation: dict) -> dict:
        """Run the DEFERRED rollback for a composed mutating edge (B3), using the
        (secret) paths the engine captured in ``obligation`` at mutation time.
        Default: nothing to tear down. Returns
        ``{performed, verified, method, note}``; a mutating front overrides it.
        The engine requires ``verified`` before it reports a chain "clean" (H4)."""
        return {"performed": False, "verified": True, "method": None,
                "note": "no teardown obligation (non-mutating edge)"}

    def chain_pre(self, ctx, finding) -> frozenset:
        return self.pre

    def chain_eff(self, ctx, finding) -> frozenset:
        return self.eff

    def _params(self, ctx, finding, overrides=None):
        bound = dict(getattr(finding, "_overrides", {}))
        bound.update(overrides or {})
        return resolve_params(self.param_specs(ctx, finding), bound)

    # -- shared orchestration -------------------------------------------------
    def plan(self, ctx: ExecutorContext, finding,
             overrides: Optional[dict[str, Any]] = None) -> ValidationPlan:
        """Resolve params (with any overrides) and build a non-executing preview."""
        params = self._params(ctx, finding, overrides)
        return ValidationPlan(
            technique=self.technique, technique_class=self.technique_class,
            target=self.target_identity(ctx, finding, params),
            mutating=self.mutating, terminal_kind=self.terminal_kind,
            params=params, steps_preview=self.steps_preview(ctx, finding, params),
            verified_recipe=self.verified_recipe, recipe_ref=self.recipe_ref,
            finding_summary=finding.summary(),
        )

    def _execute_to_artifact(self, ctx: ExecutorContext, finding,
                             params: dict[str, ParamValue]) -> dict:
        """Run ``execute`` fail-closed: any exception becomes an incomplete
        artifact carrying the error (never a fabricated proof)."""
        ctx._pending_teardown = None
        try:
            return self.execute(ctx, finding, params)
        except StubNotImplemented as exc:
            ctx._private_errors.append(str(exc))
            return {"steps": [], "complete": False, "errors": ["stub_not_implemented"]}
        except Exception as exc:  # fail closed -> incomplete receipt, never a proof
            ctx._private_errors.append(str(exc))
            artifact = {"steps": [], "complete": False, "errors": ["executor_exception"]}
            if ctx._pending_teardown:
                artifact["mutation"] = {"applied": True}
                artifact["teardown_obligation"] = ctx._pending_teardown
            return artifact

    def _receipt_from(self, ctx: ExecutorContext, finding,
                      params: dict[str, ParamValue], artifact: dict) -> dict:
        """Build the ``proof.v1`` receipt from a loose artifact. Shared by ``run``
        and ``run_composable`` so the receipt (and its secret-scrubbing) is
        identical on both paths. ``artifact`` keys outside the receipt schema
        (e.g. ``teardown_obligation``) are ignored here, so engine-only secret
        paths never reach the receipt (H6)."""
        executor_meta = {"name": type(self).__name__, "technique": self.technique,
                         "verified_recipe": self.verified_recipe}
        candidate = {"finding_id": finding.finding_id, "logical_id": finding.logical_id,
                     "host": finding.host, **{k: v for k, v in finding.entity.items()
                                              if not isinstance(v, (dict, list))}}
        return proof.build_receipt(
            technique=self.technique, cls=self.technique_class,
            target=self.target_identity(ctx, finding, params),
            steps=artifact.get("steps"), gate=artifact.get("gate"),
            mutation=artifact.get("mutation"), terminal_fact=artifact.get("terminal_fact"),
            complete=artifact.get("complete", False),
            candidate=candidate, executor=executor_meta,
            errors=artifact.get("errors"),
        )

    def run(self, ctx: ExecutorContext, finding,
            overrides: Optional[dict[str, Any]] = None) -> dict:
        """Full path: resolve params, execute, and return a proof.v1 receipt.

        Any exception inside ``execute`` yields an incomplete receipt carrying
        the error (never a fabricated proof).
        """
        params = self._params(ctx, finding, overrides)
        artifact = self._execute_to_artifact(ctx, finding, params)
        return self._receipt_from(ctx, finding, params, artifact)

    def run_composable(self, ctx: ExecutorContext, finding,
                       overrides: Optional[dict[str, Any]] = None) -> "ComposableResult":
        """The engine-facing path (C): execute this edge as part of a chain and
        return the receipt PLUS the machine-consumable products -- the typed
        capabilities to thread downstream, and the deferred-teardown obligation
        (secret paths, engine-only, never in the receipt). ``ctx.composed`` tells
        a mutating front to DEFER its rollback so the key material survives for a
        downstream terminal (B3)."""
        params = self._params(ctx, finding, overrides)
        artifact = self._execute_to_artifact(ctx, finding, params)
        receipt = self._receipt_from(ctx, finding, params, artifact)
        caps = self.produced(ctx, finding, params, artifact) if artifact.get("complete") else []
        return ComposableResult(
            receipt=receipt,
            complete=bool(artifact.get("complete")),
            capabilities=list(caps),
            teardown_obligation=artifact.get("teardown_obligation"),
            executor=self,
        )
