"""Deterministic credential-reuse campaign orchestration.

The campaign selects an explicit credential/host/transport matrix, accounts for
lockout risk, delegates each authorized cell to a mockable Aranum handoff, and
feeds collected authentication outcomes to the interop derivation layer.

NOTE: Wiring credentials into Aranum's credential CLI is an Aranum-side contract;
this module deliberately invents no credential-bearing command-line flags.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from purplesploit.core.credential_spray import LockoutPolicy
from purplesploit.core.execution import AuthContext, AuthScope, Observation, generate_account_ref
from purplesploit.interop.aranum import AranumBundle
from purplesploit.interop.derive import derive_from_bundle

try:
    from purplesploit.modules.recon.aranum import ARANUM_OWNED_BASELINES
except (ImportError, AttributeError):  # Optional adapter during partial installations.
    ARANUM_OWNED_BASELINES = ()


ARANUM_MODULE_PATH = "recon/aranum"
_OUTCOMES = {
    "success", "failure", "lockout", "error", "anonymous", "null-session", "skipped",
}


@dataclass(frozen=True)
class CredentialTest:
    """One explicitly selected credential, host, and transport cell."""

    account_ref: str
    host: str
    transport: str
    scope: AuthScope | None
    domain: str | None
    local_host: str | None
    aranum_owned: bool


@dataclass
class CellExec:
    """Normalized return value for a campaign execution seam."""

    outcome: str
    auth_outcome: dict[str, Any] | None = None
    reason: str = ""


@dataclass
class CellOutcome:
    test: CredentialTest
    outcome: str
    reason: str = ""
    auth_outcome: dict[str, Any] | None = None


@dataclass
class CampaignResult:
    findings: list
    outcomes: list[CellOutcome]
    summary: dict[str, int]
    bundle: AranumBundle


class LockoutAccountant:
    """Deterministic count-based lockout accounting with no wall clock."""

    def __init__(self, policy: LockoutPolicy | None = None):
        self.policy = policy or LockoutPolicy.conservative()
        self.failures: dict[str, int] = {}
        self.locked: set[str] = set()

    def can_test(self, account_ref: str) -> tuple[bool, str]:
        if account_ref in self.locked:
            return False, "locked"
        if self.failures.get(account_ref, 0) >= self.policy.threshold - 1:
            return False, "near-threshold"
        return True, ""

    def record(self, account_ref: str, outcome: str) -> None:
        normalized = str(outcome).strip().lower()
        if normalized == "failure":
            self.failures[account_ref] = self.failures.get(account_ref, 0) + 1
        elif normalized == "lockout":
            self.locked.add(account_ref)


ExecutionSeam = Callable[[CredentialTest], CellExec | Mapping[str, Any] | None]


class _FrameworkAranumHandoff:
    """Resolve P3 and call its credential-test contract when supplied by Aranum."""

    def __init__(self, framework: Any):
        self.framework = framework

    def __call__(self, test: CredentialTest) -> CellExec:
        if self.framework is None:
            return CellExec("error", reason="recon/aranum framework is unavailable")
        try:
            instantiate = getattr(self.framework, "instantiate_module", None)
            if callable(instantiate):
                module = instantiate(ARANUM_MODULE_PATH)
            else:
                getter = getattr(self.framework, "get_module", None)
                metadata = getter(ARANUM_MODULE_PATH) if callable(getter) else None
                module_class = getattr(metadata, "instance", None)
                module = module_class(self.framework) if callable(module_class) else None
            if module is None:
                return CellExec("error", reason="recon/aranum module is unavailable")
            execute = getattr(module, "execute_credential_test", None)
            if not callable(execute):
                return CellExec(
                    "error",
                    reason="recon/aranum credential-test contract is unavailable",
                )
            return _normalize_exec(execute(test))
        except Exception as exc:  # External execution failures are campaign data.
            return CellExec("error", reason=f"{type(exc).__name__}: {exc}")


def _normalize_exec(value: CellExec | Mapping[str, Any] | None) -> CellExec:
    if isinstance(value, CellExec):
        outcome = str(value.outcome).strip().lower()
        return CellExec(
            outcome if outcome in _OUTCOMES else "error",
            value.auth_outcome if isinstance(value.auth_outcome, dict) else None,
            value.reason,
        )
    if isinstance(value, Mapping):
        mapping = dict(value)
        nested = mapping.get("auth_outcome")
        raw = dict(nested) if isinstance(nested, Mapping) else mapping
        outcome = str(mapping.get("outcome", raw.get("outcome", "error"))).strip().lower()
        return CellExec(
            outcome if outcome in _OUTCOMES else "error",
            raw if raw else None,
            str(mapping.get("reason", "")),
        )
    return CellExec("error", reason="execution seam returned no outcome")


class ReuseCampaign:
    """Compose a declared reuse matrix, lockout accounting, P3 handoff, and P4."""

    def __init__(
        self,
        *,
        corpus: Iterable[Mapping[str, Any]],
        hosts: Iterable[str],
        scope: AuthScope | None,
        transports: Iterable[str],
        domain: str | None = None,
        lockout_policy: LockoutPolicy | None = None,
        handoff: ExecutionSeam | None = None,
        framework: Any = None,
    ):
        if scope not in {None, "local", "domain", "machine"}:
            raise ValueError("scope must be 'local', 'domain', 'machine', or None")
        self.corpus = [dict(credential) for credential in corpus]
        self.hosts = [str(host) for host in hosts]
        self.scope = scope
        self.transports = [str(transport) for transport in transports]
        self.domain = domain if scope == "domain" else None
        self.lockout_policy = lockout_policy or LockoutPolicy.conservative()
        self.handoff = handoff if handoff is not None else _FrameworkAranumHandoff(framework)

    @classmethod
    def from_session(cls, session: Any, **kwargs: Any) -> "ReuseCampaign":
        """Build a campaign from a Session's CredentialManager corpus."""
        manager = getattr(session, "credentials", None)
        corpus = getattr(manager, "credentials", manager)
        return cls(corpus=corpus or (), **kwargs)

    @staticmethod
    def _account_ref(credential: Mapping[str, Any]) -> str:
        explicit = credential.get("account_ref")
        if explicit:
            return str(explicit)
        return generate_account_ref(
            str(credential.get("username") or ""),
            credential.get("scope"),
            credential.get("domain"),
            credential.get("local_host"),
        )

    def build_matrix(self) -> list[CredentialTest]:
        """Return the declared Cartesian matrix in stable host/corpus/transport order."""
        matrix = []
        seen: set[CredentialTest] = set()
        for host in sorted(self.hosts):
            for credential in self.corpus:
                account_ref = self._account_ref(credential)
                for transport in self.transports:
                    test = CredentialTest(
                        account_ref=account_ref,
                        host=host,
                        transport=transport,
                        scope=self.scope,
                        domain=self.domain if self.scope == "domain" else None,
                        local_host=host if self.scope == "local" else None,
                        aranum_owned=transport in ARANUM_OWNED_BASELINES,
                    )
                    if test not in seen:
                        seen.add(test)
                        matrix.append(test)
        return matrix

    @staticmethod
    def _observation(cell: CellOutcome) -> Observation | None:
        raw = cell.auth_outcome
        if not isinstance(raw, dict) or not raw:
            return None
        return Observation(
            kind="identity",
            target=cell.test.host,
            attributes={
                "record_type": "auth_outcome",
                "transport": cell.test.transport,
                "outcome": cell.outcome,
            },
            source_tool="aranum",
            source_schema="purplesploit/reuse-campaign-1",
            raw=raw,
            auth_context=AuthContext(
                account_ref=cell.test.account_ref,
                scope=cell.test.scope,
                domain=cell.test.domain,
                local_host=cell.test.local_host,
            ),
            module_path=ARANUM_MODULE_PATH,
            observed_at="1970-01-01T00:00:00+00:00",
        )

    def run(self) -> CampaignResult:
        accountant = LockoutAccountant(self.lockout_policy)
        outcomes: list[CellOutcome] = []
        observations: list[Observation] = []
        summary = {
            "tested": 0,
            "skipped": 0,
            "locked": 0,
            "success": 0,
            "failure": 0,
            "lockout": 0,
            "error": 0,
            "anonymous": 0,
            "null-session": 0,
        }

        for test in self.build_matrix():
            allowed, reason = accountant.can_test(test.account_ref)
            if not allowed:
                cell = CellOutcome(
                    test,
                    "skipped",
                    reason=f"skipped: account {reason}",
                )
                outcomes.append(cell)
                summary["skipped"] += 1
                continue

            try:
                executed = _normalize_exec(self.handoff(test))
            except Exception as exc:  # A seam failure must not discard prior outcomes.
                executed = CellExec("error", reason=f"{type(exc).__name__}: {exc}")
            cell = CellOutcome(test, executed.outcome, executed.reason, executed.auth_outcome)
            outcomes.append(cell)
            summary["tested"] += 1
            summary[executed.outcome] += 1
            accountant.record(test.account_ref, executed.outcome)
            observation = self._observation(cell)
            if observation is not None:
                observations.append(observation)

        summary["locked"] = len(accountant.locked)
        bundle = AranumBundle(
            run_root=Path("."),
            bundle_fingerprint="purplesploit-reuse-campaign-v1",
            run_id="purplesploit-reuse-campaign",
            status="complete",
            extensions={"module_path": ARANUM_MODULE_PATH},
            observations=observations,
        )
        derived = derive_from_bundle(bundle)
        return CampaignResult(derived.findings, outcomes, summary, bundle)


__all__ = [
    "ARANUM_MODULE_PATH",
    "CampaignResult",
    "CellExec",
    "CellOutcome",
    "CredentialTest",
    "ExecutionSeam",
    "LockoutAccountant",
    "ReuseCampaign",
]
