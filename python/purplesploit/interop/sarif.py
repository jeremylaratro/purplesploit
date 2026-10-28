"""Forgiving, deterministic import of Aranum SARIF 2.1.0 findings."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
from typing import Any

from purplesploit.core.findings import Finding, Severity


_SEVERITIES = {item.value: item for item in Severity}
_LEVEL_SEVERITIES = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.INFO,
}


def _text(value: Any) -> str:
    """Return a useful scalar as text without leaking malformed containers."""
    if isinstance(value, str):
        return value.strip()
    if value is not None and not isinstance(value, (dict, list, tuple, set)):
        return str(value).strip()
    return ""


def _nested_text(value: Any, key: str = "text") -> str:
    return _text(value.get(key)) if isinstance(value, dict) else ""


def _port(value: Any) -> int | None:
    """Match the bundle importer's zero/empty host-scoped port convention."""
    if value in (None, "", 0, "0"):
        return None
    try:
        if isinstance(value, bool):
            return None
        number = int(value)
        if str(number) != str(value) or not 1 <= number <= 65535:
            return None
        return number
    except (TypeError, ValueError, OverflowError):
        return None


def _logical_target(result: dict[str, Any]) -> tuple[str, int | None]:
    locations = result.get("locations")
    if not isinstance(locations, list):
        return "", None
    for location in locations:
        if not isinstance(location, dict):
            continue
        logical_locations = location.get("logicalLocations")
        if not isinstance(logical_locations, list):
            continue
        for logical in logical_locations:
            if not isinstance(logical, dict):
                continue
            name = _text(logical.get("fullyQualifiedName"))
            if not name:
                continue
            if ":" not in name:
                return name, None
            host, raw_port = name.rsplit(":", 1)
            return host, _port(raw_port)
    return "", None


def _rule_descriptors(run: dict[str, Any]) -> dict[str, dict[str, Any]]:
    tool = run.get("tool")
    driver = tool.get("driver") if isinstance(tool, dict) else None
    rules = driver.get("rules") if isinstance(driver, dict) else None
    if not isinstance(rules, list):
        return {}
    descriptors: dict[str, dict[str, Any]] = {}
    for descriptor in rules:
        if not isinstance(descriptor, dict):
            continue
        rule_id = _text(descriptor.get("id"))
        if rule_id and rule_id not in descriptors:
            descriptors[rule_id] = descriptor
    return descriptors


def _severity(properties: dict[str, Any], level: Any) -> Severity:
    source = _text(properties.get("severity")).lower()
    if source in _SEVERITIES:
        return _SEVERITIES[source]
    return _LEVEL_SEVERITIES.get(_text(level).lower(), Severity.MEDIUM)


def _stable_id(
    result: dict[str, Any], properties: dict[str, Any], rule_id: str,
    host: str, port: int | None, message: str,
) -> str:
    finding_id = _text(properties.get("finding_id"))
    if finding_id:
        return finding_id
    fingerprints = result.get("fingerprints") or result.get("partialFingerprints")
    try:
        identity_tail: Any = (
            fingerprints
            if isinstance(fingerprints, (dict, list)) and fingerprints
            else message
        )
        encoded = json.dumps(
            [rule_id, host, port, identity_tail],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        encoded = json.dumps(
            [rule_id, host, port, message], separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    return sha256(encoded).hexdigest()


def _finding_from_result(
    result: dict[str, Any], descriptors: dict[str, dict[str, Any]],
) -> Finding | None:
    properties = result.get("properties")
    properties = properties if isinstance(properties, dict) else {}
    message = result.get("message")
    message_text = _nested_text(message)
    logical_host, logical_port = _logical_target(result)

    supplied_rule_id = _text(result.get("ruleId"))
    rule_id = supplied_rule_id or "finding"
    descriptor = descriptors.get(rule_id, {})
    descriptor_name = _text(descriptor.get("name"))
    short_description = _nested_text(descriptor.get("shortDescription"))
    property_host = _text(properties.get("host"))
    host = property_host or logical_host

    # An empty object contains no result to salvage. Any normal SARIF identity,
    # message, target, or Aranum property is enough to preserve the result.
    if not any((supplied_rule_id, message_text, host, properties)):
        return None

    port = _port(properties.get("port")) if "port" in properties else logical_port
    title = message_text or descriptor_name or short_description or rule_id
    impact = _nested_text(descriptor.get("fullDescription"))
    remediation = _nested_text(descriptor.get("help"))
    help_uri = _text(descriptor.get("helpUri"))
    category = _text(properties.get("category"))
    kb_id = _text(properties.get("kb_id"))
    identifier = _stable_id(result, properties, rule_id, host, port, message_text)
    try:
        raw_output = json.dumps(result, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError, OverflowError):
        raw_output = ""

    return Finding(
        id=identifier,
        title=title,
        severity=_severity(properties, result.get("level")),
        target=host,
        host=host or None,
        port=port,
        service=category or kb_id or None,
        impact=impact,
        remediation=remediation,
        references=[help_uri] if help_uri else [],
        module_name="interop/sarif",
        raw_output=raw_output,
        tags=["aranum-sarif"],
        discovered_at=None,
        metadata={
            "rule_id": rule_id,
            "confidence": properties.get("confidence"),
            "scope": properties.get("scope"),
            "category": properties.get("category"),
            "kb_id": properties.get("kb_id"),
        },
    )


def _load(value: dict | str | Path) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if not isinstance(value, (str, Path)):
        return None
    try:
        document = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, TypeError, ValueError):
        return None
    return document if isinstance(document, dict) else None


def import_aranum_sarif(value: dict | str | Path) -> list[Finding]:
    """Map every salvageable Aranum SARIF result without raising on bad input."""
    try:
        document = _load(value)
        if document is None:
            return []
        runs = document.get("runs")
        if not isinstance(runs, list):
            return []
        findings: list[Finding] = []
        for run in runs:
            if not isinstance(run, dict):
                continue
            descriptors = _rule_descriptors(run)
            results = run.get("results")
            if not isinstance(results, list):
                continue
            for result in results:
                if not isinstance(result, dict):
                    continue
                try:
                    finding = _finding_from_result(result, descriptors)
                except Exception:
                    continue
                if finding is not None:
                    findings.append(finding)
        return sorted(
            findings,
            key=lambda item: (
                item.target,
                _text(item.metadata.get("rule_id")),
                item.id,
            ),
        )
    except Exception:
        return []
