"""Pure Aranum SARIF mapping and bundle-fallback contracts."""

import json
from pathlib import Path
import shutil

import pytest

from purplesploit.core.findings import Severity
from purplesploit.interop.aranum import import_aranum_bundle
from purplesploit.interop.sarif import import_aranum_sarif


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "interop" / "aranum"
SARIF_FIXTURE = FIXTURES / "fx-sarif.sarif.json"


def test_enriched_and_bare_results_map_without_losing_findings():
    findings = import_aranum_sarif(SARIF_FIXTURE)

    assert [item.id for item in findings] == ["FX-SARIF-BARE", "FX-SARIF-ENRICHED"]
    enriched = next(item for item in findings if item.id == "FX-SARIF-ENRICHED")
    assert enriched.title == "Deprecated TLS protocol accepted"
    assert enriched.severity is Severity.CRITICAL
    assert (enriched.target, enriched.host, enriched.port) == (
        "web-lab.invalid", "web-lab.invalid", 443,
    )
    assert enriched.service == "tls"
    assert enriched.impact and enriched.remediation
    assert enriched.references == ["https://example.invalid/kb/TLS-WEAK-PROTOCOL"]
    assert enriched.tags == ["aranum-sarif"]
    assert enriched.module_name == "interop/sarif" and enriched.discovered_at is None
    assert enriched.metadata == {
        "rule_id": "TLS-WEAK-PROTOCOL",
        "confidence": "high",
        "scope": "service",
        "category": "tls",
        "kb_id": "TLS-WEAK-PROTOCOL",
    }

    bare = next(item for item in findings if item.id == "FX-SARIF-BARE")
    assert bare.severity is Severity.LOW
    assert bare.target == "bare-lab.invalid" and bare.port is None
    assert bare.impact == bare.remediation == ""
    assert bare.references == []


def test_severity_and_logical_location_fallbacks():
    document = {
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "aranum", "rules": []}},
            "results": [
                {
                    "ruleId": "prop-severity",
                    "level": "note",
                    "message": {"text": "property severity wins"},
                    "properties": {"host": "property.invalid", "port": 8443,
                                   "severity": "high", "finding_id": "z-property"},
                },
                {
                    "ruleId": "level-severity",
                    "level": "error",
                    "message": {"text": "level severity is used"},
                    "locations": [{"logicalLocations": [
                        {"fullyQualifiedName": "logical.invalid:22"},
                    ]}],
                    "properties": {"severity": "not-a-severity", "finding_id": "a-logical"},
                },
                {
                    "ruleId": "unknown-severity",
                    "level": "other",
                    "message": {"text": "unknown defaults"},
                    "locations": [{"logicalLocations": [
                        {"fullyQualifiedName": "host-scoped.invalid:0"},
                    ]}],
                    "properties": {"finding_id": "m-default"},
                },
                {
                    "ruleId": "note-severity",
                    "level": "note",
                    "message": {"text": "note maps to info"},
                    "properties": {"host": "note.invalid", "finding_id": "n-note"},
                },
            ],
        }],
    }

    findings = {item.id: item for item in import_aranum_sarif(document)}
    assert findings["z-property"].severity is Severity.HIGH
    assert (findings["z-property"].target, findings["z-property"].port) == (
        "property.invalid", 8443,
    )
    assert findings["a-logical"].severity is Severity.HIGH
    assert (findings["a-logical"].target, findings["a-logical"].port) == (
        "logical.invalid", 22,
    )
    assert findings["m-default"].severity is Severity.MEDIUM
    assert findings["m-default"].target == "host-scoped.invalid"
    assert findings["m-default"].port is None
    assert findings["n-note"].severity is Severity.INFO


def test_missing_message_uses_descriptor_then_rule_id_for_title():
    document = {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "described", "name": "Descriptor title",
                "shortDescription": {"text": "Short title"},
            }]}},
            "results": [
                {"ruleId": "described", "properties": {"finding_id": "described-id"}},
                {"ruleId": "bare-rule", "properties": {"finding_id": "bare-id"}},
            ],
        }],
    }

    findings = {item.id: item for item in import_aranum_sarif(document)}
    assert findings["described-id"].title == "Descriptor title"
    assert findings["bare-id"].title == "bare-rule"


def test_identity_and_order_are_deterministic_without_finding_ids():
    document = {
        "runs": [{
            "results": [
                {"ruleId": "z-rule", "message": {"text": "same"},
                 "properties": {"host": "z.invalid"}},
                {"ruleId": "a-rule", "message": {"text": "same"},
                 "fingerprints": {"aranum/v1": "stable"},
                 "properties": {"host": "a.invalid", "port": "0"}},
            ],
        }],
    }

    first = import_aranum_sarif(document)
    second = import_aranum_sarif(document)
    assert [item.id for item in first] == [item.id for item in second]
    assert [item.target for item in first] == ["a.invalid", "z.invalid"]
    assert all(len(item.id) == 64 for item in first)


@pytest.mark.parametrize(
    "value,expected_count",
    [
        ({}, 0),
        ({"runs": "bad"}, 0),
        ({"version": "1.0.0", "runs": [
            "bad", {}, {"results": "bad"},
            {"results": [{"message": {"text": "salvaged despite version"}}]},
        ]}, 1),
        ({"runs": [{"results": [{}, "bad"]}]}, 0),
        ({"runs": [{"results": [{"ruleId": "missing-message"}]}]}, 1),
        ({"runs": [{"results": [{"message": {"text": "missing location"}}]}]}, 1),
        ([], 0),
        (None, 0),
    ],
)
def test_malformed_shapes_never_raise(value, expected_count):
    assert len(import_aranum_sarif(value)) == expected_count


def test_unreadable_invalid_and_non_object_files_return_empty(tmp_path):
    invalid = tmp_path / "invalid.sarif"
    invalid.write_text("{not json", encoding="utf-8")
    array = tmp_path / "array.sarif"
    array.write_text("[]", encoding="utf-8")

    assert import_aranum_sarif(tmp_path / "missing.sarif") == []
    assert import_aranum_sarif(tmp_path) == []
    assert import_aranum_sarif(invalid) == []
    assert import_aranum_sarif(array) == []


def test_sarif_only_bundle_uses_deterministic_fallback_and_marker(tmp_path):
    destination = tmp_path / "sarif-only"
    destination.mkdir()
    shutil.copyfile(SARIF_FIXTURE, destination / "results.sarif")

    bundle = import_aranum_bundle(destination)

    assert [item.id for item in bundle.findings] == [
        "FX-SARIF-BARE", "FX-SARIF-ENRICHED",
    ]
    fallback = [
        item for item in bundle.observations
        if item.attributes.get("marker") == "sarif_fallback"
    ]
    assert len(fallback) == 1
    assert fallback[0].attributes["source_file"] == "results.sarif"
    assert "2 findings" in fallback[0].attributes["reason"]


def test_manifest_declared_sarif_precedes_root_scan(tmp_path):
    destination = tmp_path / "declared-sarif"
    destination.mkdir()
    shutil.copyfile(SARIF_FIXTURE, destination / "z-declared.sarif")
    (destination / "a-unlisted.sarif").write_text(json.dumps({
        "runs": [{"results": [{
            "ruleId": "unlisted", "message": {"text": "must not win"},
            "properties": {"finding_id": "UNLISTED"},
        }]}],
    }), encoding="utf-8")
    (destination / "bundle-manifest.json").write_text(json.dumps({
        "schema_version": "1",
        "run_id": "sarif-declared-test",
        "status": "complete",
        "files": [{"path": "z-declared.sarif"}],
    }), encoding="utf-8")

    bundle = import_aranum_bundle(destination)
    assert [item.id for item in bundle.findings] == [
        "FX-SARIF-BARE", "FX-SARIF-ENRICHED",
    ]
    marker = next(
        item for item in bundle.observations
        if item.attributes.get("marker") == "sarif_fallback"
    )
    assert marker.attributes["source_file"] == "z-declared.sarif"


def test_full_bundle_finding_count_and_ids_remain_pre_p5_values(tmp_path):
    copied = tmp_path / "fx-2"
    shutil.copytree(FIXTURES / "fx-2", copied)
    shutil.copyfile(SARIF_FIXTURE, copied / "ignored.sarif")

    bundle = import_aranum_bundle(copied)

    assert [item.id for item in bundle.findings] == [
        "2d36fbba-6cd8-515c-8b63-a31e9c6e463d",
        "e2d5b052-ad22-52a5-823f-33a1beac1ad4",
        "b308d813-2bcd-524e-9245-aa0a06e4bef6",
        "738c7032-0e7d-54d4-a63d-a006235e8367",
        "9fc9397b-60f5-5e2f-a0a2-b1e1f44f68c7",
    ]
    assert not [
        item for item in bundle.observations
        if item.attributes.get("marker") == "sarif_fallback"
    ]
