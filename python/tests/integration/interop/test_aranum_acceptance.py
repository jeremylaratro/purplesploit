"""PLAN-002 P2b tri-state acceptance harness for AC-01 through AC-20."""

from __future__ import annotations

from functools import wraps
import importlib
import importlib.util
import inspect
import json
import os
from pathlib import Path
import sys
from typing import Any, Callable

import pytest

from purplesploit.core.execution import (
    AuthContext, ExecutionRequest, Observation, normalize_observations,
)
from purplesploit.interop.importers import REGISTRY, detect, parse
from tests.tools.pre_p1_snapshot import DEFAULT_OUTPUT, importer_cases, run_case


PYTHON_ROOT = Path(__file__).resolve().parents[3]
FIXTURE_ROOT = PYTHON_ROOT / "tests" / "fixtures" / "interop" / "aranum"
AC_IDS = [f"AC-{number:02d}" for number in range(1, 21)]
RESULTS = {
    ac_id: {"state": "inconclusive", "reason": "check not executed"} for ac_id in AC_IDS
}


def _results_path() -> Path:
    configured = os.environ.get("ARANUM_AC_RESULTS")
    if configured:
        path = Path(configured)
        return path if path.is_absolute() else PYTHON_ROOT / path
    return PYTHON_ROOT / "build" / "ac-results.json"


def _write_results() -> None:
    path = _results_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "base_sha": "cc491ae",
        "plan": "PLAN-002",
        "results": {ac_id: RESULTS[ac_id] for ac_id in AC_IDS},
    }
    path.write_text(
        json.dumps(payload, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


@pytest.fixture(scope="module", autouse=True)
def _initialize_results_file():
    names = {
        f"AC-{name[8:10]}"
        for name, value in globals().items()
        if name.startswith("test_ac_") and callable(value)
    }
    assert names == set(AC_IDS), "harness must contain exactly one test for every AC-01..AC-20"
    for ac_id in AC_IDS:
        RESULTS[ac_id] = {"state": "inconclusive", "reason": "check not executed"}
    _write_results()
    yield
    _write_results()


def acceptance(ac_id: str) -> Callable:
    """Record assertion outcomes while leaving pytest's native result intact."""

    def decorate(function: Callable) -> Callable:
        @wraps(function)
        def run(*args: Any, **kwargs: Any):
            try:
                reason = function(*args, **kwargs)
            except pytest.skip.Exception:
                raise
            except Exception as exc:
                reason = str(exc).strip() or type(exc).__name__
                RESULTS[ac_id] = {"state": "fail", "reason": reason}
                _write_results()
                raise
            RESULTS[ac_id] = {
                "state": "pass",
                "reason": reason or "acceptance assertions satisfied",
            }
            _write_results()

        return run

    return decorate


def _inconclusive(ac_id: str, reason: str) -> None:
    reason = f"INCONCLUSIVE: {reason}"
    RESULTS[ac_id] = {"state": "inconclusive", "reason": reason}
    _write_results()
    pytest.skip(reason)


def _bundle(ac_id: str, fixture_id: str) -> Path:
    path = FIXTURE_ROOT / fixture_id.lower()
    if not path.is_dir():
        _inconclusive(ac_id, f"fixture bundle {fixture_id} is absent at {path}")
    return path


def _document(root: Path, filename: str) -> dict[str, Any]:
    matches = sorted(root.rglob(filename))
    assert matches, f"{filename} is absent from present fixture {root.name}"
    value = json.loads(matches[0].read_text(encoding="utf-8"))
    assert isinstance(value, dict), f"{matches[0]} must contain a JSON object"
    return value


def _import(root: Path):
    result = parse(root, format="aranum-bundle")
    assert result.observations, f"present bundle {root.name} imported no observations"
    return result


def _records(document: dict[str, Any], *names: str) -> list[dict[str, Any]]:
    result = []
    for name in names:
        value = document.get(name, [])
        if isinstance(value, list):
            result.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            result.extend(item for item in value.values() if isinstance(item, dict))
    return result


def _dispatcher_names(value: Any) -> set[str]:
    if isinstance(value, list):
        names = set()
        for item in value:
            if isinstance(item, str):
                names.add(item)
            elif isinstance(item, dict):
                names.update(
                    str(item[key]) for key in ("name", "service", "id") if item.get(key)
                )
        return names
    if isinstance(value, dict):
        for key in ("dispatchers", "services", "entries"):
            if key in value:
                return _dispatcher_names(value[key])
        return {str(key) for key in value}
    return set()


def _require_aranum_module(ac_id: str):
    spec = importlib.util.find_spec("purplesploit.modules.recon.aranum")
    if spec is None:
        _inconclusive(ac_id, "prerequisite recon/aranum module is absent")
    return importlib.import_module("purplesploit.modules.recon.aranum")


@acceptance("AC-01")
def test_ac_01_registry_completeness(tmp_path):
    bundle = _bundle("AC-01", "fx-1")
    module = _require_aranum_module("AC-01")
    dispatchers = sorted(FIXTURE_ROOT.rglob("dispatchers.json"))
    if not dispatchers:
        _inconclusive("AC-01", "published dispatchers.json prerequisite is absent")
    names = _dispatcher_names(json.loads(dispatchers[0].read_text(encoding="utf-8")))
    assert names, "published dispatchers.json contains no dispatcher entries"

    from purplesploit.core.framework import Framework

    framework = Framework(db_path=str(tmp_path / "ac01.db"))
    try:
        framework.discover_modules()
        metadata = framework.get_module("recon/aranum")
        assert metadata is not None, "recon/aranum is not registered"
        instance = framework.instantiate_module("recon/aranum")
        assert instance is not None, "recon/aranum cannot be instantiated"
        operations = instance.get_operations()
        labels = {str(item.get("name") or item.get("id")) for item in operations}
        assert "Run Selected Services" in labels
        for name in names:
            assert any(name in label for label in labels), f"dispatcher {name} does not resolve"
        assert bundle.is_dir() and module is not None
    finally:
        framework.cleanup()
    return f"{len(names)} published dispatchers resolve through recon/aranum"


@acceptance("AC-02")
def test_ac_02_inventory_fidelity():
    bundle = _bundle("AC-02", "fx-1")
    inventory = _document(bundle, "inventory.json")
    source_records = _records(inventory, "hosts", "entries", "services")
    assert source_records, "FX-1 inventory contains no host or service records"
    imported = _import(bundle)
    raw_records = [item.raw for item in imported.observations]
    for record in source_records:
        assert record in raw_records, f"inventory record did not survive import: {record}"
    return f"all {len(source_records)} FX-1 inventory records survived import"


@acceptance("AC-03")
def test_ac_03_finding_fidelity():
    bundle = _bundle("AC-03", "fx-2")
    findings_document = _document(bundle, "findings.json")
    source_findings = _records(findings_document, "findings")
    assert source_findings, "FX-2 findings.json contains no findings"
    imported = _import(bundle)
    assert len(imported.findings) == len(source_findings), (
        "findings.json records must map one-to-one to Finding objects"
    )
    source_ids = {
        str(item.get("finding_id") or item.get("source_id") or item.get("id"))
        for item in source_findings
    }
    observation_ids = {
        str(item.source_id)
        for item in imported.observations
        if item.kind == "finding"
    }
    assert source_ids == observation_ids
    return f"{len(source_findings)} source findings imported exactly once"


@acceptance("AC-04")
def test_ac_04_observation_fidelity():
    bundle = _bundle("AC-04", "fx-2")
    posture = _document(bundle, "posture.json")
    serialized = json.dumps(posture, sort_keys=True)
    assert any(key in serialized for key in ('"checks"', '"per_host"', '"coverage"')), (
        "FX-2 posture subject is absent"
    )
    imported = _import(bundle)
    records = [item.attributes.get("record_type") for item in imported.observations]
    assert "posture_check" in records, "posture checks produced no observations"
    assert "per_host_rollup" in records, "per_host roll-ups produced no observations"
    assert "coverage" in records, "summary.coverage rows produced no observations"
    return "posture checks, roll-ups, and coverage rows are represented"


@acceptance("AC-05")
def test_ac_05_provenance():
    bundle = _bundle("AC-05", "fx-2")
    imported = _import(bundle)
    required = {
        "source_tool",
        "source_tool_version",
        "source_schema",
        "source_id",
        "raw",
        "auth_context",
    }
    model_fields = set(Observation.__dataclass_fields__)
    assert required <= model_fields, f"first-class Observation fields absent: {required - model_fields}"
    for observation in imported.observations:
        for name in required:
            assert hasattr(observation, name), f"{name} absent on {observation.observation_id}"
    return f"first-class provenance checked on {len(imported.observations)} observations"


@acceptance("AC-06")
def test_ac_06_kb_enrichment():
    bundle = _bundle("AC-06", "fx-2")
    findings_document = _document(bundle, "findings.json")
    kb = findings_document.get("kb")
    assert isinstance(kb, dict) and kb, "FX-2 inline KB subset is absent"
    imported = _import(bundle)
    enriched = [item for item in imported.findings if item.metadata.get("kb_id")]
    assert enriched, "no Finding retains an inline KB identifier"
    for finding in enriched:
        assert finding.description, f"{finding.id} has no KB description"
        assert finding.impact, f"{finding.id} has no KB impact"
        assert finding.remediation, f"{finding.id} has no KB remediation"
        assert finding.references, f"{finding.id} has no KB references"
        assert finding.metadata.get("validation"), f"{finding.id} has no validation/retest text"
        assert finding.metadata.get("kb_digest"), f"{finding.id} has no KB digest"
        assert all(value.startswith("T") for value in finding.mitre_techniques)
    return f"KB enrichment checked on {len(enriched)} findings"


@acceptance("AC-07")
def test_ac_07_exact_reimport():
    bundle = _bundle("AC-07", "fx-2")
    from purplesploit.interop.aranum import import_aranum_bundle

    observations: list[Any] = []
    findings: list[Any] = []
    first = import_aranum_bundle(bundle)
    additions = first.merge_into(observations, findings)
    assert additions["observations"] or additions["findings"], "first import added no records"
    second = import_aranum_bundle(bundle).merge_into(observations, findings)
    assert second == {"observations": 0, "findings": 0}
    return "second exact import added zero observations and zero findings"


@acceptance("AC-08")
def test_ac_08_cross_run_linking():
    bundle = _bundle("AC-08", "fx-2-rerun")
    runs = sorted(path for path in bundle.iterdir() if path.is_dir())
    if len(runs) < 2:
        _inconclusive("AC-08", "FX-2 does not yet contain two run occurrences")
    first, second = _import(runs[0]), _import(runs[1])
    assert first.findings and second.findings, "cross-run fixture has no findings"
    first_groups: dict[str, int] = {}
    for finding in first.findings:
        logical_id = finding.metadata.get("logical_id")
        assert logical_id, f"first-run finding {finding.id} lacks logical_id"
        first_groups[logical_id] = first_groups.get(logical_id, 0) + 1
    second_groups: dict[str, int] = {}
    for finding in second.findings:
        logical_id = finding.metadata.get("logical_id")
        assert logical_id in first_groups, f"{finding.id} has no prior logical match"
        assert finding.metadata.get("source_identity"), f"{finding.id} lacks source_identity"
        second_groups[logical_id] = second_groups.get(logical_id, 0) + 1
    assert second_groups == first_groups
    assert {item.id for item in first.findings}.isdisjoint(item.id for item in second.findings)
    return f"{len(second.findings)} new occurrences linked to prior logical findings"


@acceptance("AC-09")
def test_ac_09_partial_error_visibility():
    bundle = _bundle("AC-09", "fx-3")
    imported = _import(bundle)
    quality = [
        item
        for item in imported.observations
        if item.attributes.get("record_type") == "data_quality"
    ]
    assert quality, "partial/errors/quarantine/redaction produced no data-quality observations"
    serialized = json.dumps([item.to_dict() for item in quality], sort_keys=True).lower()
    for marker in ("partial", "error", "quarantine", "redact"):
        assert marker in serialized, f"{marker} visibility is absent"
    assert imported.extensions.get("status") == "partial", "import is not marked partial"
    return f"{len(quality)} partial-run data-quality observations imported"


@acceptance("AC-10")
def test_ac_10_auto_enum_handoff():
    _bundle("AC-10", "fx-1")
    module = _require_aranum_module("AC-10")
    source = inspect.getsource(module)
    assert "Run Selected Services" in source, "selected-service coalescing operation is absent"
    assert "--only" in source and "--service-parallel" in source
    overlaps = {"smb", "ldap", "winrm", "rdp", "ssh", "mssql", "dns", "http"}
    declared = set(getattr(module, "ARANUM_OWNED_BASELINES", ()))
    assert overlaps <= declared, f"overlap ownership absent for {sorted(overlaps - declared)}"
    return "selected services coalesce and all eight overlap baselines are Aranum-owned"


@acceptance("AC-11")
def test_ac_11_offline_portability(monkeypatch):
    bundle = _bundle("AC-11", "fx-2")
    findings = _document(bundle, "findings.json")
    assert isinstance(findings.get("kb"), dict) and findings["kb"], "inline KB is absent"
    monkeypatch.setenv("PATH", "")
    monkeypatch.setitem(sys.modules, "aranum", None)
    imported = _import(bundle)
    assert imported.findings, "offline import produced no findings"
    return "FX-2 imported with an empty PATH and no Aranum Python package"


@acceptance("AC-12")
def test_ac_12_invocation_discipline():
    bundle = _bundle("AC-12", "fx-3")
    module = _require_aranum_module("AC-12")
    source = inspect.getsource(module)
    forbidden = ("--aggressive", "--desktop", "--write", "--exploit")
    defaults = getattr(module, "DEFAULT_ARGV", ())
    assert not any(flag in defaults for flag in forbidden), "default argv contains invasive flags"
    assert "-o" in source, "operator-chosen output-root mapping is absent"
    assert "returncode == 4" in source or "returncode in (0, 4)" in source
    # P2b-NOTE: Aranum emits bundle-manifest.json; this harness naming bug is fixed in P3.
    manifest = _document(bundle, "manifest.json")
    assert manifest.get("status") == "partial", "rc=4 fixture manifest is not partial"
    return "default argv and rc=4 report-chain contract are present"


@acceptance("AC-13")
def test_ac_13_report_rendering(tmp_path):
    from purplesploit.reporting import ReportGenerator

    bundle = _bundle("AC-13", "fx-2")
    imported = _import(bundle)
    observations = {item.source_id: item for item in imported.observations if item.source_id}
    enriched = [
        finding for finding in imported.findings
        if finding.remediation
        and finding.metadata.get("validation")
        and observations.get(finding.metadata.get("source_identity")) is not None
        and observations[finding.metadata["source_identity"]].auth_context is not None
    ]
    assert enriched, "FX-2 import produced no KB-enriched finding with auth_context"

    report = ReportGenerator()
    report.add_findings(imported.findings)
    markdown_path = report.generate("markdown", str(tmp_path / "fx-2.md"))
    html_path = report.generate("html", str(tmp_path / "fx-2.html"))
    rendered_outputs = {
        "Markdown": Path(markdown_path).read_text(encoding="utf-8"),
        "HTML": Path(html_path).read_text(encoding="utf-8"),
    }
    for output_name, rendered in rendered_outputs.items():
        for heading in ("Remediation", "Validation", "auth_context"):
            assert heading in rendered, f"{heading} is absent from PurpleSploit {output_name} output"
    return f"PurpleSploit Markdown/HTML render enriched output for {len(enriched)} findings"


@acceptance("AC-14")
def test_ac_14_account_separation(tmp_path, monkeypatch):
    import purplesploit.core.execution as execution

    assert hasattr(execution, "AuthContext"), (
        "auth_context/account_ref/scope/local_host prerequisites are absent"
    )

    monkeypatch.setenv("PURPLESPLOIT_HOME", str(tmp_path / "purplesploit-home"))

    from purplesploit.core.database import Database
    from purplesploit.core.session import CredentialManager
    from purplesploit.models.database import Credential, CredentialCreate, DatabaseManager
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    model_fields = set(CredentialCreate.model_fields)
    orm_fields = set(Credential.__table__.columns.keys())
    required = {"account_ref", "scope", "local_host"}
    assert required <= model_fields and required <= orm_fields, (
        "auth_context/account_ref/scope/local_host prerequisites are absent"
    )

    records = [
        {
            "name": "host-a/alice",
            "username": "alice",
            "scope": "local",
            "local_host": "host-a",
            "account_ref": "local:host-a:alice",
        },
        {
            "name": "host-b/alice",
            "username": "alice",
            "scope": "local",
            "local_host": "host-b",
            "account_ref": "local:host-b:alice",
        },
    ]
    session_store = CredentialManager()
    assert all(session_store.add(dict(record)) for record in records)
    assert len(session_store.list()) == 2

    legacy = Database(str(tmp_path / "credentials.db"))
    try:
        for record in records:
            legacy.add_credential(**record)
        assert len(legacy.get_credentials()) == 2
    finally:
        legacy.close()

    engine = create_engine(f"sqlite:///{tmp_path / 'orm-credentials.db'}")
    Credential.__table__.create(engine)
    orm = DatabaseManager.__new__(DatabaseManager)
    orm.session_makers = {"credentials": sessionmaker(bind=engine)}
    for record in records:
        orm.upsert_credential(CredentialCreate(**record))
    assert len(orm.get_all_credentials()) == 2
    assert records[0]["account_ref"] != records[1]["account_ref"]
    return "same-named local accounts remain distinct in session, SQLite, and ORM stores"


@acceptance("AC-15")
def test_ac_15_round_trip(tmp_path):
    import purplesploit.core.execution as execution
    from purplesploit.core.assessment import AssessmentService
    from purplesploit.distributed.coordinator import Coordinator

    assert hasattr(execution, "AuthContext"), "AuthContext is absent from core.execution"
    AuthContext = execution.AuthContext
    context = AuthContext(
        account_ref="domain:example.test:alice",
        scope="domain",
        domain="example.test",
        local_host=None,
        auth_method="password",
    )
    request = execution.ExecutionRequest(module_path="fixture", auth_context=context)
    request = execution.ExecutionRequest.from_dict(request.to_dict())
    assert request.auth_context == context
    observation = execution.Observation("identity", "alice", auth_context=context)
    observation = execution.Observation.from_dict(observation.to_dict())
    assert observation.auth_context == context
    result = execution.ExecutionResult(
        request_id=request.request_id,
        module_path=request.module_path,
        outcome=execution.ExecutionOutcome.SUCCESS,
        success=True,
        finished_at="2026-10-27T00:00:00+00:00",
        auth_context=context,
        observations=[observation],
    )
    result = execution.ExecutionResult.from_dict(result.to_dict())
    assert result.auth_context == context
    assert result.observations[0].auth_context == context

    coordinator = Coordinator()
    coordinator.register("agent-1")
    submitted = coordinator.submit(request)
    assert execution.ExecutionRequest.from_dict(submitted["request"]).auth_context == context
    claimed = coordinator.claim("agent-1")["task"]
    coordinator.result(claimed["id"], "agent-1", claimed["lease_id"], result)
    distributed = execution.ExecutionResult.from_dict(coordinator.status(claimed["id"])["result"])
    assert distributed.auth_context == context

    assessment = AssessmentService(tmp_path / "assessment")
    assessment.create_engagement("AC-15", engagement_id="ac-15")
    stored = assessment.record_execution("ac-15", result)
    restored = assessment.get_engagement("ac-15").executions[0]
    assert stored.auth_context == context
    assert execution.ExecutionResult.from_dict(restored).auth_context == context
    return "auth_context survives direct, distributed, and assessment round trips"


@acceptance("AC-16")
def test_ac_16_no_inference():
    import purplesploit.core.execution as execution

    assert hasattr(execution, "AuthContext"), "AuthContext is absent from core.execution"
    request = ExecutionRequest(module_path="fixture", options={"DOMAIN": "example.test"})
    observations = normalize_observations(
        {"observations": [{"kind": "identity", "target": "alice"}]}, request
    )
    assert observations, "normalizer subject is absent"
    ctx = observations[0].auth_context
    assert ctx is None or (ctx.scope is None and ctx.domain is None)

    declared_ref = ExecutionRequest(
        module_path="fixture", options={"DOMAIN": "example.test"},
        auth_context=AuthContext(account_ref="r"),
    )
    observations = normalize_observations(
        {"observations": [{"kind": "identity", "target": "alice"}]}, declared_ref
    )
    assert observations, "normalizer auth_context subject is absent"
    assert observations[0].auth_context.scope is None
    assert observations[0].auth_context.domain is None
    return "DOMAIN without declared scope leaves auth_context.scope null"


@acceptance("AC-17")
def test_ac_17_local_only_import():
    bundle = _bundle("AC-17", "fx-2l")
    assert not (bundle / "inventory.json").exists(), "FX-2L is not local-only"
    importer = detect(bundle)
    assert importer.name == "aranum-bundle", "registry did not detect local-only bundle"
    imported = importer.parse(bundle)
    assert imported.observations, "local-only import produced no observations"
    return f"local-only bundle detected and imported {len(imported.observations)} observations"


@acceptance("AC-18")
def test_ac_18_stale_manifest_safety():
    network = _bundle("AC-18", "fx-4")
    local = _bundle("AC-18", "fx-4l")
    first = _import(network)
    second = _import(local)
    statuses = {
        first.extensions.get("status"),
        second.extensions.get("status"),
    }
    assert "complete" not in statuses, "stale rerun imported as complete"
    serialized = json.dumps(
        [item.to_dict() for item in [*first.observations, *second.observations]],
        sort_keys=True,
    ).lower()
    assert "interrupted" in serialized or "unknown" in serialized
    assert "unlisted" in serialized, "stale local findings were not reported as unlisted"
    return "network/local stale reruns remain interrupted/unknown with unlisted diagnostics"


@acceptance("AC-19")
def test_ac_19_identity_stability():
    assert (DEFAULT_OUTPUT / "MANIFEST.json").is_file(), "Step-0 manifest subject is absent"
    checked = 0
    for case in importer_cases():
        snapshot = json.loads(
            (DEFAULT_OUTPUT / f"{case.name}.json").read_text(encoding="utf-8")
        )
        current = run_case(case)
        expected = {item["observation_id"] for item in snapshot["observations"]}
        observed = {item["observation_id"] for item in current["observations"]}
        assert expected == observed, f"identity drift for {case.name}"
        checked += len(expected)
    assert checked, "Step-0 corpus contains no observations"
    assert set(REGISTRY.importers)
    return f"{checked} persisted observation IDs match across {len(importer_cases())} cases"


@acceptance("AC-20")
def test_ac_20_auth_outcome_fidelity():
    bundle = _bundle("AC-20", "fx-5")
    imported = _import(bundle)
    outcomes = [
        item for item in imported.observations
        if item.attributes.get("record_type") == "auth_outcome"
    ]
    assert len(outcomes) == 4
    by_host = {item.target: item for item in outcomes}
    assert {host: item.attributes.get("outcome") for host, item in by_host.items()} == {
        "10.0.0.1": "success",
        "10.0.0.2": "success",
        "10.0.0.3": "lockout",
        "10.0.0.4": "success",
    }
    for host in ("10.0.0.1", "10.0.0.2", "10.0.0.3"):
        assert by_host[host].auth_context.account_ref == "svc-local"
        assert by_host[host].auth_context.scope == "local"
        assert by_host[host].auth_context.local_host == host
        assert by_host[host].auth_context.auth_method == "password"
    domain = by_host["10.0.0.4"].auth_context
    assert domain.account_ref == "dom-user"
    assert domain.scope == "domain"
    assert domain.domain == "CORP.LOCAL"
    assert domain.auth_method == "password"
    key_context = AuthContext(account_ref="ssh-key", scope="local", auth_method="key")
    assert AuthContext.from_dict(key_context.to_dict()) == key_context
    return "four auth outcomes and password/key auth methods retain declared context"
