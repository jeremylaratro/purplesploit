"""ValidationExecutor registry: technique -> executor class.

Fully implemented (ALL eleven techniques): RBCD (``rbcd.py``), KERBEROAST + ASREP
(``roast.py``), LAPS (``laps.py``), CONSTRAINED-DELEG-PT (``constrained_deleg.py``),
OPENSHARES-WRITE (``openshares.py``), SHADOW-CREDS (``shadow_creds.py``), ADCS-ESC1
(``adcs_esc1.py``), and the listener trio COERCION (``coercion.py``), NTLM-RELAY
(``ntlm_relay.py``), UNCONSTRAINED-DELEG (``unconstrained_deleg.py``) on the
``ProcessManager`` chassis (``process_manager.py``, ADR-001). No stubs remain
(``stubs.py``'s ``STUB_EXECUTORS`` is empty). The orchestrator looks executors up
here by the technique the finding mapper attached.
"""
from __future__ import annotations

from typing import Optional

from .base import (ValidationExecutor, ExecutorContext, CommandRunner,
                   SubprocessRunner, AuthorizationProvider, AuthorizedLabProvider,
                   ValidationPlan, StepRecord, RunResult, StubNotImplemented,
                   redact_argv, ToolAttempt, first_successful,
                   ProcessManager, SubprocessProcessManager, ProcHandle,
                   poll_for_capture,
                   DestructiveConfirmationProvider, InteractiveDestructiveConfirmer,
                   NonInteractiveDestructiveConfirmer)
from .rbcd import RBCDExecutor
from .roast import KerberoastExecutor, ASREPExecutor
from .laps import LAPSExecutor
from .constrained_deleg import ConstrainedDelegExecutor
from .openshares import OpenSharesExecutor
from .shadow_creds import ShadowCredsExecutor
from .adcs_esc1 import ADCSESC1Executor
from .coercion import CoercionExecutor
from .ntlm_relay import NTLMRelayExecutor
from .unconstrained_deleg import UnconstrainedDelegExecutor
from .esc8 import ESC8Executor
from .esc11 import ESC11Executor
from .certifried import CertifriedExecutor
from .dcsync import DCSyncExecutor
from .write_dacl import WriteDaclExecutor
from .write_owner import WriteOwnerExecutor
from .add_member import AddMemberExecutor
from .targeted_kerberoast import TargetedKerberoastExecutor
from .force_change_password import ForceChangePasswordExecutor
from .generic_all import GenericAllExecutor
from .gpo_abuse import GpoAbuseExecutor
from .stubs import STUB_EXECUTORS

# Full executors win over any stub key of the same technique.
_FULL: tuple[type[ValidationExecutor], ...] = (
    RBCDExecutor, KerberoastExecutor, ASREPExecutor, LAPSExecutor,
    ConstrainedDelegExecutor, OpenSharesExecutor, ShadowCredsExecutor,
    ADCSESC1Executor, CoercionExecutor, NTLMRelayExecutor, UnconstrainedDelegExecutor,
    # N1 -- ADCS relay fronts + the reusable DCSync terminal (b1).
    ESC8Executor, ESC11Executor, CertifriedExecutor, DCSyncExecutor,
    # T3 -- ACL / object-takeover edges. All 7 now real (GPO-ABUSE built last,
    # per the plan's own implementation order -- it was the most UNVERIFIED).
    WriteDaclExecutor, WriteOwnerExecutor, AddMemberExecutor,
    TargetedKerberoastExecutor, ForceChangePasswordExecutor, GenericAllExecutor,
    GpoAbuseExecutor,
)

# Technique -> executor class.
REGISTRY: dict[str, type[ValidationExecutor]] = {
    **STUB_EXECUTORS, **{cls.technique: cls for cls in _FULL},
}

# Techniques whose recipe is fully wired end-to-end (not a stub).
IMPLEMENTED: frozenset[str] = frozenset(cls.technique for cls in _FULL)


def get_executor(technique: Optional[str]) -> Optional[ValidationExecutor]:
    """Instantiate the executor for ``technique``, or ``None`` if unregistered."""
    cls = REGISTRY.get(technique or "")
    return cls() if cls is not None else None


def is_implemented(technique: Optional[str]) -> bool:
    return technique in IMPLEMENTED


__all__ = [
    "ValidationExecutor", "ExecutorContext", "CommandRunner", "SubprocessRunner",
    "AuthorizationProvider", "AuthorizedLabProvider", "ValidationPlan", "StepRecord",
    "RunResult", "StubNotImplemented", "redact_argv", "ToolAttempt", "first_successful",
    "ProcessManager", "SubprocessProcessManager", "ProcHandle", "poll_for_capture",
    "DestructiveConfirmationProvider", "InteractiveDestructiveConfirmer",
    "NonInteractiveDestructiveConfirmer",
    "RBCDExecutor",
    "KerberoastExecutor", "ASREPExecutor", "LAPSExecutor",
    "ConstrainedDelegExecutor", "OpenSharesExecutor", "ShadowCredsExecutor",
    "ADCSESC1Executor", "CoercionExecutor", "NTLMRelayExecutor",
    "UnconstrainedDelegExecutor",
    "ESC8Executor", "ESC11Executor", "CertifriedExecutor", "DCSyncExecutor",
    "GenericAllExecutor", "WriteDaclExecutor", "WriteOwnerExecutor",
    "AddMemberExecutor", "ForceChangePasswordExecutor",
    "TargetedKerberoastExecutor", "GpoAbuseExecutor",
    "REGISTRY", "IMPLEMENTED", "get_executor", "is_implemented",
]
