"""Bind operator inputs once for standalone dispatch and composed planning.

Values stay in the finding's private overrides; only identity fields enter its
public entity. Validation messages name parameter keys, never their values.
"""
from __future__ import annotations

from .findings import NormalizedFinding
from .recommend import resolve_params


class InputError(ValueError):
    """A public, payload-free dispatch error."""


# --target is a principal/group/object for these techniques, not a generic host.
TARGET_PARAM = {
    "ADD-MEMBER": "group", "TARGETED-KERBEROAST": "victim",
    "WRITE-DACL": "target", "WRITE-OWNER": "target", "GENERIC-ALL": "target",
    "FORCE-CHANGE-PASSWORD": "victim", "DCSYNC": "dc_host",
    "KERBEROAST": "principal", "ASREP": "principal", "SHADOW-CREDS": "account",
    "LAPS": "target_host", "RBCD": "delegate_to",
    "CONSTRAINED-DELEG-PT": "target_host", "OPENSHARES-WRITE": "share",
    "ADCS-ESC1": "ca_host", "ESC8": "ca_host", "ESC11": "ca_host",
    "CERTIFRIED": "ca_host", "COERCION": "victim_dc",
    "UNCONSTRAINED-DELEG": "victim_dc", "NTLM-RELAY": "relay_target",
    "GPO-ABUSE": "gpo_guid",
}

# Param -> finding entity aliases used by existing executors' defaults/identity.
ENTITY_ALIAS = {"account": "victim", "delegate_to": "host", "dc_host": "host"}
PUBLIC_ENTITY = frozenset({
    "target", "trustee", "rights", "group", "member", "victim", "principal",
    "spn", "pivot", "host", "ca_host", "ca", "template", "gpo_guid", "linked_host",
    "share", "account", "target_host", "victim_dc", "relay_target",
})


def finding_from_inputs(ctx, edge, target=None, params=None):
    """Return a complete, validated binding, or fail before any tools execute."""
    overrides = dict(params or {})
    target_param = TARGET_PARAM[edge.technique]
    if target is not None:
        overrides.setdefault(target_param, target)
    if edge.technique == "DCSYNC":
        overrides.setdefault("dc_host", ctx.config.dc_ip)
    host = overrides.get(target_param) or ""
    entity = {}
    for key, value in overrides.items():
        if key in PUBLIC_ENTITY:
            entity[key] = value
            entity[ENTITY_ALIAS.get(key, key)] = value
    finding = NormalizedFinding(
        source={}, finding_id="operator-" + edge.technique,
        host=host, technique=edge.technique, technique_class=edge.technique_class,
        entity=entity, _overrides=overrides)
    specs = edge.param_specs(ctx, finding)
    known = {s.name for s in specs}
    if set(overrides) - known:
        raise InputError("unknown_parameter")
    missing = [s.name for s in specs if s.required
               and overrides.get(s.name, s.recommended) in (None, "")]
    if missing:
        raise InputError("missing_required_params: " + ", ".join(sorted(missing)))
    try:
        resolve_params(specs, overrides)
    except Exception as exc:
        ctx._private_errors.append(str(exc))
        raise InputError("invalid_parameter") from None
    return finding
