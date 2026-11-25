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
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

from ..config import ValidationConfig
from ..recommend import ParamSpec, ParamValue, resolve_params, params_preview
from ..predicates import strip_ansi
from .. import proof


# ------------------------------------------------------------------ command runner
@dataclass
class RunResult:
    """What a single tool invocation returned (runtime only -- not serialized)."""
    returncode: Optional[int]
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    error: Optional[str] = None


# Flags whose following token is a secret and must be masked in any stored argv.
_SECRET_FLAGS = frozenset({
    "-p", "--password", "-hashes", "-H", "--hash", "-aesKey", "--aes-key",
    "-computer-pass", "-pfx", "-password",
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


# ------------------------------------------------------------------ executor context
@dataclass
class ExecutorContext:
    """Everything an executor needs at run time, assembled by the orchestrator."""
    config: ValidationConfig
    runner: CommandRunner
    authorizer: AuthorizationProvider
    output_dir: Any                      # pathlib.Path for this run's receipts/ccache


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
    verified_recipe: bool = False
    recipe_ref: str = ""

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

    # -- shared orchestration -------------------------------------------------
    def plan(self, ctx: ExecutorContext, finding,
             overrides: Optional[dict[str, Any]] = None) -> ValidationPlan:
        """Resolve params (with any overrides) and build a non-executing preview."""
        params = resolve_params(self.param_specs(ctx, finding), overrides)
        return ValidationPlan(
            technique=self.technique, technique_class=self.technique_class,
            target=self.target_identity(ctx, finding, params),
            mutating=self.mutating, terminal_kind=self.terminal_kind,
            params=params, steps_preview=self.steps_preview(ctx, finding, params),
            verified_recipe=self.verified_recipe, recipe_ref=self.recipe_ref,
            finding_summary=finding.summary(),
        )

    def run(self, ctx: ExecutorContext, finding,
            overrides: Optional[dict[str, Any]] = None) -> dict:
        """Full path: resolve params, execute, and return a proof.v1 receipt.

        Any exception inside ``execute`` yields an incomplete receipt carrying
        the error (never a fabricated proof).
        """
        params = resolve_params(self.param_specs(ctx, finding), overrides)
        executor_meta = {"name": type(self).__name__, "technique": self.technique,
                         "verified_recipe": self.verified_recipe}
        candidate = {"finding_id": finding.finding_id, "logical_id": finding.logical_id,
                     "host": finding.host, **{k: v for k, v in finding.entity.items()
                                              if not isinstance(v, (dict, list))}}
        try:
            artifact = self.execute(ctx, finding, params)
        except StubNotImplemented as exc:
            artifact = {"steps": [], "complete": False,
                        "errors": [f"stub_not_implemented: {exc}"]}
        except Exception as exc:  # fail closed -> incomplete receipt, never a proof
            artifact = {"steps": [], "complete": False,
                        "errors": [f"{type(exc).__name__}: {exc}"]}
        return proof.build_receipt(
            technique=self.technique, cls=self.technique_class,
            target=self.target_identity(ctx, finding, params),
            steps=artifact.get("steps"), gate=artifact.get("gate"),
            mutation=artifact.get("mutation"), terminal_fact=artifact.get("terminal_fact"),
            complete=artifact.get("complete", False),
            candidate=candidate, executor=executor_meta,
            errors=artifact.get("errors"),
        )
