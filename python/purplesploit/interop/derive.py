"""Deterministic findings and graph derivation from imported Aranum data."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Optional, TYPE_CHECKING
from uuid import NAMESPACE_URL, uuid5

from purplesploit.core.findings import Finding, Severity
from purplesploit.interop.aranum import _step_text

if TYPE_CHECKING:
    from purplesploit.core.attack_graph import AttackGraph, AttackPath
    from purplesploit.interop.aranum import AranumBundle


@dataclass
class DerivationResult:
    """Newly derived records and the graph populated from one imported bundle."""

    findings: list[Finding]
    graph: "AttackGraph"
    lateral_paths: list["AttackPath"]
    summary: dict[str, int]


def _finding_id(kind: str, *parts: Any) -> str:
    """Build a stable identifier from a finding's canonical semantic key."""
    key = ["purplesploit", "aranum-derived", kind, *parts]
    canonical = json.dumps(key, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return str(uuid5(NAMESPACE_URL, canonical))


def _text(value: Any) -> str:
    return "" if value is None else str(value).strip()


def _auth_observations(bundle: "AranumBundle") -> list[Any]:
    observations = []
    for observation in getattr(bundle, "observations", ()) or ():
        attributes = getattr(observation, "attributes", {})
        if (
            getattr(observation, "kind", None) == "identity"
            and isinstance(attributes, dict)
            and attributes.get("record_type") == "auth_outcome"
        ):
            observations.append(observation)
    return sorted(
        observations,
        key=lambda item: (
            _text(getattr(getattr(item, "auth_context", None), "account_ref", None)),
            _text(getattr(item, "target", None)),
            _text(item.attributes.get("transport")),
            _text(item.attributes.get("outcome")),
            _text(getattr(item, "observation_id", None)),
        ),
    )


def _posture_observations(bundle: "AranumBundle") -> list[Any]:
    observations = []
    for observation in getattr(bundle, "observations", ()) or ():
        attributes = getattr(observation, "attributes", {})
        if (
            getattr(observation, "kind", None) == "policy"
            and isinstance(attributes, dict)
            and attributes.get("record_type") == "posture_check"
        ):
            observations.append(observation)
    return sorted(
        observations,
        key=lambda item: (
            _text(getattr(item, "target", None)),
            _text(item.attributes.get("scope")),
            _text(item.attributes.get("check_id")),
            _text(item.attributes.get("status")),
            _text(getattr(item, "observation_id", None)),
        ),
    )


def _posture_severity(status: str) -> Severity:
    if status == "FAIL":
        return Severity.HIGH
    if status == "WARN":
        return Severity.MEDIUM
    if status in {"PASS", "NA"}:
        return Severity.INFO
    return Severity.LOW


def derive_from_bundle(
    bundle: "AranumBundle", graph: Optional["AttackGraph"] = None,
) -> DerivationResult:
    """Derive findings and lateral candidates from an already imported bundle.

    Missing or incomplete signals are ignored. This function performs no I/O and
    invokes no assessment tool.
    """
    from purplesploit.core.attack_graph import AttackGraph, NodeType

    graph = graph if graph is not None else AttackGraph()
    observations = list(getattr(bundle, "observations", ()) or ())
    graph.ingest_observations(observations)

    auth_observations = _auth_observations(bundle)
    successes = []
    lockouts = []
    for observation in auth_observations:
        context = getattr(observation, "auth_context", None)
        account_ref = _text(getattr(context, "account_ref", None))
        host = _text(getattr(observation, "target", None))
        outcome = _text(observation.attributes.get("outcome")).lower()
        if not account_ref or not host:
            continue
        if outcome == "success":
            successes.append(observation)
        elif outcome == "lockout":
            lockouts.append(observation)

    findings = []

    local_accounts: dict[str, dict[str, set[str]]] = {}
    for observation in successes:
        context = observation.auth_context
        if context.scope != "local":
            continue
        account_ref = _text(context.account_ref)
        values = local_accounts.setdefault(account_ref, {"hosts": set(), "transports": set()})
        values["hosts"].add(_text(observation.target))
        transport = _text(observation.attributes.get("transport"))
        if transport:
            values["transports"].add(transport)

    for account_ref in sorted(local_accounts):
        hosts = sorted(local_accounts[account_ref]["hosts"])
        if len(hosts) < 2:
            continue
        transports = sorted(local_accounts[account_ref]["transports"])
        findings.append(Finding(
            id=_finding_id("local-reuse", account_ref, hosts, transports),
            title=f"Local-account credential reuse: {account_ref}",
            severity=Severity.HIGH,
            description=(
                f"Local account {account_ref} authenticated successfully on hosts "
                f"{', '.join(hosts)} using transports {', '.join(transports) or 'unspecified'}."
            ),
            target=", ".join(hosts),
            impact="The same local-account credential is effective across multiple hosts.",
            remediation="Use unique local credentials per host and rotate the reused credential.",
            tags=["credential-reuse", "local"],
            metadata={"account_ref": account_ref, "hosts": hosts, "transports": transports},
            module_name="interop/derive",
            discovered_at=None,
        ))

    domain_access: dict[tuple[str, str], dict[str, Any]] = {}
    for observation in successes:
        context = observation.auth_context
        if context.scope != "domain":
            continue
        account_ref = _text(context.account_ref)
        host = _text(observation.target)
        key = (account_ref, host)
        values = domain_access.setdefault(
            key,
            {"domain": _text(context.domain), "transports": set()},
        )
        transport = _text(observation.attributes.get("transport"))
        if transport:
            values["transports"].add(transport)

    for account_ref, host in sorted(domain_access):
        values = domain_access[(account_ref, host)]
        domain = values["domain"]
        transports = sorted(values["transports"])
        findings.append(Finding(
            id=_finding_id("domain-effective", account_ref, domain, host, transports),
            title=f"Domain account effective on host: {account_ref}",
            severity=Severity.INFO,
            description=(
                f"Domain account {account_ref} authenticated successfully on {host} "
                f"using transports {', '.join(transports) or 'unspecified'}."
            ),
            target=host,
            impact="This records confirmed effective access for the domain account on the host.",
            remediation="Review whether this domain account requires access to the host.",
            tags=["effective-access", "domain"],
            metadata={
                "account_ref": account_ref,
                "domain": domain or None,
                "hosts": [host],
                "transports": transports,
            },
            module_name="interop/derive",
            discovered_at=None,
        ))

    kb = getattr(bundle, "kb", {})
    kb = kb if isinstance(kb, dict) else {}
    kb_checks = kb.get("checks")
    kb_checks = kb_checks if isinstance(kb_checks, dict) else {}
    for observation in _posture_observations(bundle):
        attributes = observation.attributes
        host = _text(observation.target)
        check_id = _text(attributes.get("check_id")) or "unknown"
        status = _text(attributes.get("status")).upper() or "UNKNOWN"
        scope = _text(attributes.get("scope")) or "host"
        entry = kb_checks.get(check_id)
        entry = entry if isinstance(entry, dict) else {}
        remediation = _step_text(entry.get("fix"))
        validation = _step_text(entry.get("test"))
        if not remediation:
            remediation = (
                f"Harden per posture check {check_id} (status {status}) on {host}; "
                "consult the aranum KB class for this check or the applicable CIS/STIG baseline."
            )
        if not validation:
            validation = (
                f"Re-run aranum posture enumeration for {check_id} on {host} "
                "and confirm status PASS."
            )
        title = _text(entry.get("title")) or check_id
        references = entry.get("refs") if isinstance(entry.get("refs"), list) else []
        attack_ids = entry.get("attack_ids") if isinstance(entry.get("attack_ids"), list) else []
        findings.append(Finding(
            id=_finding_id(
                "posture", host, scope, check_id, status,
                _text(getattr(observation, "observation_id", None)),
            ),
            title=f"Posture check {check_id}: {title}",
            severity=_posture_severity(status),
            description=(
                f"Aranum posture check {check_id} reported {status} on {host}.\n\n"
                f"Validation: {validation}"
            ),
            target=host,
            service="posture",
            impact=_text(entry.get("why")) or f"Posture check {check_id} did not report a passing state.",
            remediation=remediation,
            references=[str(value) for value in references],
            mitre_techniques=[str(value) for value in attack_ids],
            tags=["posture", scope],
            notes=[f"Validation: {validation}"],
            metadata={
                "check_id": check_id,
                "status": status,
                "scope": scope,
                "validation": validation,
                "kb_hit": bool(entry),
                "kb_digest": kb.get("digest"),
                "auth_context": (
                    observation.auth_context.to_dict()
                    if getattr(observation, "auth_context", None) is not None
                    else None
                ),
            },
            module_name="interop/derive",
            discovered_at=None,
        ))

    for observation in lockouts:
        context = observation.auth_context
        account_ref = _text(context.account_ref)
        host = _text(observation.target)
        transport = _text(observation.attributes.get("transport"))
        findings.append(Finding(
            id=_finding_id(
                "lockout", account_ref, host, transport,
                _text(getattr(observation, "observation_id", None)),
            ),
            title=f"Account lockout during enumeration: {account_ref} on {host}",
            severity=Severity.MEDIUM,
            description=(
                f"Account {account_ref} was reported locked out during enumeration of {host}"
                f" via {transport or 'an unspecified transport'}."
            ),
            target=host,
            service=transport or None,
            impact="Further authentication attempts may be unavailable and the account owner may be disrupted.",
            remediation="Review the lockout, restore access if appropriate, and verify the applicable lockout policy.",
            tags=["lockout"],
            metadata={"account_ref": account_ref, "host": host, "transport": transport or None},
            module_name="interop/derive",
            discovered_at=None,
        ))

    success_hosts = set()
    for observation in successes:
        context = observation.auth_context
        account_ref = _text(context.account_ref)
        host = _text(observation.target)
        if not account_ref or not host:
            continue
        host_node = graph.add_node(NodeType.HOST, label=host, identifier=host)
        credential = graph.add_credential(
            username=account_ref,
            domain=_text(context.domain) or None,
            cred_type=_text(context.auth_method) or "password",
        )
        graph.link_credential_to_host(
            credential.id,
            host_node.id,
            service=_text(observation.attributes.get("transport")) or None,
        )
        success_hosts.add(host)

    lateral_by_id = {}
    for host in sorted(success_hosts):
        host_node = graph.add_node(NodeType.HOST, label=host, identifier=host)
        for path in graph.find_lateral_paths(host_node.id):
            lateral_by_id[path.id] = path
    lateral_paths = [lateral_by_id[path_id] for path_id in sorted(lateral_by_id)]

    findings.sort(key=lambda item: (item.id, item.title))
    summary = {
        "reuse": sum("credential-reuse" in item.tags for item in findings),
        "effective": sum("effective-access" in item.tags for item in findings),
        "posture": sum("posture" in item.tags for item in findings),
        "lockout": sum("lockout" in item.tags for item in findings),
    }
    return DerivationResult(findings, graph, lateral_paths, summary)


__all__ = ["DerivationResult", "derive_from_bundle"]
