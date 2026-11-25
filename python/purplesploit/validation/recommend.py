"""Recommended-default + operator-overridable parameter model.

The UX principle (claude-mem #66142): wherever a validation needs an input (a
new principal name, a delegation escalation target, an SPN, a share), the
framework *proposes a concrete recommended default* derived from the operator's
own inputs, and the operator may *override any of it*.

Worked example to implement faithfully (#66142): creds for user ``joe`` + DC IP
+ domain; the framework finds a local privesc and a delegation issue; it offers
to validate the privesc by creating user ``joe_escalation_test`` and to test the
delegation by creating computer ``joe_cmp_delegation`` with ``joe`` as the
escalation target. Every one of those values is a recommended default the
operator can change.

This module holds the generic model (:class:`ParamSpec`, :class:`ParamValue`,
:func:`resolve_params`) and the derivation helpers. Each
``ValidationExecutor.param_specs`` composes these into the technique-specific
parameter set.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Optional


# ------------------------------------------------------------------ helpers
# Derivation of recommended defaults from the operator-supplied principal.
# These encode the owner worked example verbatim.

def escalation_test_user(base: str) -> str:
    """Recommended new user for a privesc validation: ``<user>_escalation_test``."""
    return f"{base}_escalation_test"


def delegation_computer(base: str) -> str:
    """Recommended new computer for a delegation validation: ``<user>_cmp_delegation``."""
    return f"{base}_cmp_delegation"


def recommended_spn(service: str, host: str) -> str:
    """Recommended SPN for an S4U request, e.g. ``cifs/<target-host>``."""
    return f"{service}/{host}"


# ------------------------------------------------------------------ validators
_SAM_INVALID = re.compile(r'[\\/:*?"<>|,+=;\[\]@]')
# AD sAMAccountName hard limit is 20 chars (a computer carries a trailing '$').
_SAM_HARD_MAX = 20
# Legacy pre-Windows-2000 (NetBIOS) convention keeps computer names <= 15.
_SAM_LEGACY_MAX = 15


def validate_sam_name(value: Any) -> Optional[str]:
    """Validate an AD account label. Returns an error string, or ``None`` if ok.

    Hard-fails on illegal characters or > 20 chars (the sAMAccountName limit).
    Does *not* fail a name in (15, 20]: the owner default ``<user>_cmp_delegation``
    can exceed the 15-char legacy convention, which is a warning, not an error.
    """
    if not isinstance(value, str) or not value.strip():
        return "must be a non-empty string"
    if _SAM_INVALID.search(value):
        return "contains characters not allowed in a sAMAccountName"
    if len(value) > _SAM_HARD_MAX:
        return f"exceeds the {_SAM_HARD_MAX}-char sAMAccountName limit ({len(value)} chars)"
    return None


def sam_name_warning(value: Any) -> Optional[str]:
    """A non-fatal advisory for a name over the legacy 15-char convention."""
    if isinstance(value, str) and len(value) > _SAM_LEGACY_MAX:
        return (f"name is {len(value)} chars; over the {_SAM_LEGACY_MAX}-char "
                "pre-Windows-2000 convention (still a valid sAMAccountName)")
    return None


# ------------------------------------------------------------------ model
# Parameter kinds, used by a front-end to render/validate an override sensibly.
PARAM_KINDS = frozenset({
    "principal_name",     # a new user/account to create
    "computer_name",      # a new computer account to create
    "escalation_target",  # the principal to impersonate / escalate to
    "target_host",        # the host/computer a chain acts against
    "spn",                # a service principal name
    "share",              # an SMB share name
    "free",               # anything else
})


@dataclass
class ParamSpec:
    """One overridable parameter with a recommended default.

    ``recommended`` is the already-derived default value (never a callable).
    ``validator`` returns an error string for an invalid value, else ``None``.
    ``advisory`` returns a non-fatal warning string, else ``None``.
    """
    name: str
    kind: str
    description: str
    recommended: Any
    rationale: str
    required: bool = True
    choices: Optional[list[Any]] = None
    validator: Optional[Callable[[Any], Optional[str]]] = None
    advisory: Optional[Callable[[Any], Optional[str]]] = None

    def __post_init__(self) -> None:
        if self.kind not in PARAM_KINDS:
            raise ValueError(f"unknown param kind: {self.kind!r}")

    def validate(self, value: Any) -> Optional[str]:
        if self.required and (value is None or value == ""):
            return "a value is required"
        if self.choices is not None and value not in self.choices:
            return f"must be one of {self.choices!r}"
        if self.validator is not None and value is not None:
            return self.validator(value)
        return None

    def warn(self, value: Any) -> Optional[str]:
        return self.advisory(value) if self.advisory else None


@dataclass
class ParamValue:
    """A resolved parameter: the spec, the chosen value, and where it came from."""
    spec: ParamSpec
    value: Any
    source: str                      # 'recommended' | 'operator-override'
    warning: Optional[str] = None

    @property
    def name(self) -> str:
        return self.spec.name

    @property
    def overridden(self) -> bool:
        return self.source == "operator-override"


class ParamValidationError(ValueError):
    """Raised when an operator override fails its spec's validator."""


def resolve_params(specs: list[ParamSpec],
                   overrides: Optional[dict[str, Any]] = None) -> dict[str, ParamValue]:
    """Resolve each spec to a :class:`ParamValue`, applying operator overrides.

    An override present in ``overrides`` wins over the recommended default and is
    marked ``operator-override``; everything else takes the recommended default
    and is marked ``recommended``. Every resolved value is validated against its
    spec (recommended defaults included), so a bad default surfaces as loudly as
    a bad override. Non-fatal advisories are attached, not raised.
    """
    overrides = overrides or {}
    unknown = set(overrides) - {spec.name for spec in specs}
    if unknown:
        raise ParamValidationError(f"unknown override(s): {sorted(unknown)}")
    resolved: dict[str, ParamValue] = {}
    for spec in specs:
        if spec.name in overrides and overrides[spec.name] is not None:
            value, source = overrides[spec.name], "operator-override"
        else:
            value, source = spec.recommended, "recommended"
        error = spec.validate(value)
        if error:
            raise ParamValidationError(f"{spec.name}: {error}")
        resolved[spec.name] = ParamValue(spec=spec, value=value, source=source,
                                         warning=spec.warn(value))
    return resolved


def params_preview(resolved: dict[str, ParamValue]) -> list[dict[str, Any]]:
    """A JSON-friendly preview of resolved params for an operator confirmation."""
    preview = []
    for pv in resolved.values():
        row = {
            "name": pv.name,
            "kind": pv.spec.kind,
            "value": pv.value,
            "recommended": pv.spec.recommended,
            "source": pv.source,
            "description": pv.spec.description,
            "rationale": pv.spec.rationale,
        }
        if pv.warning:
            row["warning"] = pv.warning
        preview.append(row)
    return preview


def values(resolved: dict[str, ParamValue]) -> dict[str, Any]:
    """Collapse resolved params to a plain ``{name: value}`` mapping."""
    return {name: pv.value for name, pv in resolved.items()}
