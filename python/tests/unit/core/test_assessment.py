"""Assessment lifecycle acceptance and portable local-store contracts."""

from copy import deepcopy
import builtins
import json
from pathlib import Path

import pytest

from purplesploit.core.assessment import (
    AssessmentProfile, AssessmentRepository, AssessmentService, COVERAGE_STATES,
    Engagement, MethodologyCatalog, TestCase as AssessmentCase, TestPlan as AssessmentPlan,
    export_profile, import_profile,
)
from purplesploit.core.execution import ExecutionOutcome, ExecutionResult, Observation
from purplesploit.core.findings import Finding, FindingStatus, Severity


FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "assessment" / "operator-profile.json"


@pytest.fixture
def service(tmp_path):
    result = AssessmentService(tmp_path / "assessments")
    result.create_engagement("Synthetic assessment", engagement_id="eng-1", targets=["192.0.2.10"])
    result.add_plan("eng-1", AssessmentPlan("plan-1", "Checklist", cases=[
        AssessmentCase("case-1", "Inspect exposed service"),
        AssessmentCase("case-2", "Compare API roles"),
        AssessmentCase("case-3", "Review inherited permissions"),
    ]))
    return result


def completed(execution_id="exec-1"):
    return ExecutionResult(execution_id, success=True, outcome=ExecutionOutcome.SUCCESS,
                           finished_at="2026-10-26T10:00:00+00:00",
                           observations=[Observation("service", "192.0.2.10", port=443,
                                                     source_execution_id=execution_id)],
                           stdout_ref="runs/exec-1/stdout.txt")


def test_full_lifecycle_persists_and_compares(service):
    evidence = service.add_evidence("eng-1", "runs/request-response.json", title="Role comparison", id="evidence-1")
    baseline = service.create_baseline("eng-1", "initial")
    assert baseline["coverage"]["tested"] == 0
    observation = Observation("finding", "192.0.2.10", attributes={"behavior": "cross-role object read"})
    entry = service.add_manual_observation("eng-1", observation, case_id="case-2", evidence_refs=[evidence.id])
    assert observation.engagement_id is None
    assert entry.observation["engagement_id"] == "eng-1"
    service.add_note("eng-1", "Coordinate remediation with service owner", case_id="case-2")
    hypothesis = service.add_hypothesis("eng-1", "Object ownership checks are missing", case_id="case-2")
    service.update_hypothesis("eng-1", hypothesis.id, status="supported", note="Two identity responses differ")
    finding = Finding(id="finding-1", title="Object access across identities", severity=Severity.HIGH)
    original = deepcopy(finding.to_dict())
    service.link_finding("eng-1", finding, case_ids=["case-2"], evidence_refs=[evidence.id])
    review = service.add_review("eng-1", "finding", finding.id, "peer")
    service.update_review("eng-1", review.id, state="in_review")
    review = service.update_review("eng-1", review.id, state="approved", disposition="confirmed")
    assert review.disposition == "confirmed"
    remediation = service.add_remediation("eng-1", finding.id, "API team", due_at="2026-11-15", reference="TRACK-100")
    service.update_remediation("eng-1", remediation.id, status="in_progress")
    service.update_remediation("eng-1", remediation.id, status="resolved", note="Object policy deployed")
    execution = completed()
    saved_execution = service.record_execution("eng-1", execution, case_ids=["case-1"], evidence_refs=[evidence.id])
    assert execution.engagement_id is None
    assert saved_execution.observations[0].engagement_id == "eng-1"
    service.add_retest("eng-1", "fixed", original_finding_id=finding.id, original_case_id="case-2",
                       evidence_refs=[evidence.id], execution_id=execution.request_id)
    service.record_check("eng-1", "case-3", "not_applicable", note="No inherited permissions in this target")
    coverage = service.coverage("eng-1")
    assert coverage["summary"]["coverage_percent"] == 100.0
    assert coverage["summary"]["states"]["automated"] == 1
    assert coverage["summary"]["states"]["manual"] == 1
    assert coverage["certification"] is False
    service = AssessmentService(service.repository.path)
    restored = service.get_engagement("eng-1")
    assert restored.findings[0].snapshot == original
    assert finding.status is FindingStatus.DRAFT
    assert restored.remediations[0].status == "resolved"
    assert restored.hypotheses[0].status == "supported"
    comparison = service.compare("eng-1", "initial")
    assert comparison["changes"]["added_findings"] == [finding.id]
    assert comparison["changes"]["fixed_findings"] == [finding.id]
    assert comparison["retest"][finding.id]["outcome"] == "fixed"
    assert comparison["baseline"] == baseline
    assert comparison["current"]["remediation"][remediation.id]["status"] == "resolved"
    assert comparison["changes"]["changed_checks"] == ["case-1", "case-2", "case-3"]


def test_repository_exact_roundtrip_determinism_and_list(tmp_path):
    repository = AssessmentRepository(tmp_path / "store")
    assert repository.list() == []
    engagement = Engagement("Round trip", id="zeta", metadata={"unicode": "π", "nested": {"z": None, "a": [1, False]}})
    repository.create(engagement)
    payload = (repository.path / "zeta.json").read_bytes()
    loaded = repository.load("zeta")
    assert loaded == engagement
    repository.update(loaded)
    assert (repository.path / "zeta.json").read_bytes() == payload
    repository.create(Engagement("Alpha", id="alpha"))
    assert [item.id for item in repository.list()] == ["alpha", "zeta"]
    with pytest.raises(ValueError, match="already exists"):
        repository.create(engagement)
    with pytest.raises(FileNotFoundError):
        repository.update(Engagement("Missing", id="missing"))


def test_atomic_replace_failure_preserves_previous_document(service, monkeypatch):
    before = service.export_engagement("eng-1")

    def fail(*args):
        raise OSError("Synthetic replacement failure")

    monkeypatch.setattr("purplesploit.core.assessment.os.replace", fail)
    with pytest.raises(OSError, match="replacement failure"):
        service.update_engagement("eng-1", name="Changed")
    assert service.export_engagement("eng-1") == before
    assert not list(service.repository.path.glob("*.tmp"))


def test_service_update_and_export_import(service, tmp_path):
    service.update_engagement("eng-1", name="Updated", targets=["api.example.test"], phases=["planning", "manual"], metadata={"owner": "ops"})
    exported = service.export_engagement("eng-1")
    assert exported == service.export_engagement("eng-1")
    other = AssessmentService(tmp_path / "imported")
    imported = other.import_engagement(exported)
    assert imported == service.get_engagement("eng-1")
    assert other.export_engagement("eng-1") == exported
    assert other.list_engagements()[0].targets == ["api.example.test"]
    with pytest.raises(ValueError, match="Only"):
        service.update_engagement("eng-1", id="renamed")


@pytest.mark.parametrize("state", sorted(COVERAGE_STATES - {"automated"}))
def test_all_explicit_coverage_states(service, state):
    evidence = service.add_evidence("eng-1", "fixture://proof")
    service.record_check("eng-1", "case-1", state, evidence_refs=[evidence.id])
    row = service.coverage("eng-1")["checks"][0]
    assert row["state"] == state
    assert row["tested"] == (state in {"tested", "manual", "imported"})
    assert row["evidence_refs"] == [evidence.id]


@pytest.mark.parametrize("outcome", [ExecutionOutcome.FAILED, ExecutionOutcome.RUNNING, ExecutionOutcome.TIMED_OUT,
                                     ExecutionOutcome.CANCELLED, ExecutionOutcome.ERROR, ExecutionOutcome.REJECTED])
def test_incomplete_or_failed_execution_is_an_attempt_not_coverage(service, outcome):
    execution = ExecutionResult("attempt", outcome=outcome)
    service.record_execution("eng-1", execution, case_ids=["case-1"])
    row = service.coverage("eng-1")["checks"][0]
    assert row["state"] == "not_tested" and not row["tested"]
    assert row["execution_id"] == "attempt"


def test_success_requires_finished_timestamp(service):
    service.record_execution("eng-1", ExecutionResult("pending", success=True, outcome=ExecutionOutcome.SUCCESS), case_ids=["case-1"])
    assert service.coverage("eng-1")["summary"]["tested"] == 0


def test_notes_do_not_assert_coverage_and_latest_check_wins(service):
    service.add_note("eng-1", "Need to test", case_id="case-1")
    assert service.coverage("eng-1")["summary"]["tested"] == 0
    service.record_check("eng-1", "case-1", "manual")
    service.record_check("eng-1", "case-1", "not_tested", note="Target changed; repeat the check")
    assert service.coverage("eng-1")["checks"][0]["state"] == "not_tested"
    assert service.coverage("eng-1")["summary"]["total"] == 3


def test_evidence_can_be_attached_after_entry_and_links_are_deduplicated(service):
    entry = service.add_note("eng-1", "A manual note")
    evidence = service.add_evidence("eng-1", "proof.txt")
    result = service.attach_evidence("eng-1", "manual_entry", entry.id, [evidence.id, evidence.id])
    assert result.evidence_refs == [evidence.id]
    with pytest.raises(ValueError, match="Unknown evidence reference"):
        service.attach_evidence("eng-1", "manual_entry", entry.id, ["missing"])
    assert service.get_engagement("eng-1").manual_entries[0].evidence_refs == [evidence.id]


def test_later_evidence_attachment_is_included_in_manual_coverage(service):
    entry = service.add_manual_observation("eng-1", Observation("service", "192.0.2.10"), case_id="case-1")
    evidence = service.add_evidence("eng-1", "observed-service.txt")
    service.attach_evidence("eng-1", "manual_entry", entry.id, [evidence.id])
    row = service.coverage("eng-1")["checks"][0]
    assert row["state"] == "manual"
    assert row["observation_ids"] == [entry.observation["observation_id"]]
    assert row["evidence_refs"] == [evidence.id]


@pytest.mark.parametrize("action", [
    lambda s: s.record_check("eng-1", "missing", "manual"),
    lambda s: s.record_check("eng-1", "case-1", "manual", evidence_refs=["missing"]),
    lambda s: s.record_check("eng-1", "case-1", "manual", execution_id="missing"),
    lambda s: s.record_check("eng-1", "case-1", "manual", observation_ids=["missing"]),
    lambda s: s.record_check("eng-1", "case-1", "automated"),
    lambda s: s.record_check("eng-1", "case-1", "finished"),
    lambda s: s.add_hypothesis("eng-1", "Maybe", case_id="missing"),
    lambda s: s.add_review("eng-1", "finding", "missing", "peer"),
    lambda s: s.add_review("eng-1", "planet", "missing", "peer"),
    lambda s: s.add_remediation("eng-1", "missing", "owner"),
    lambda s: s.add_retest("eng-1", "fixed"),
    lambda s: s.add_retest("eng-1", "fixed", original_case_id="missing"),
    lambda s: s.add_retest("eng-1", "passed", original_case_id="case-1"),
    lambda s: s.attach_evidence("eng-1", "unknown", "missing", []),
    lambda s: s.attach_evidence("eng-1", "finding", "missing", []),
])
def test_invalid_links_fail_without_persisting_partial_mutations(service, action):
    before = service.export_engagement("eng-1")
    with pytest.raises(ValueError):
        action(service)
    assert service.export_engagement("eng-1") == before


def test_retest_requires_finding_case_relationship(service):
    service.link_finding("eng-1", Finding(id="finding"), case_ids=["case-1"])
    with pytest.raises(ValueError, match="not linked"):
        service.add_retest("eng-1", "fixed", original_finding_id="finding", original_case_id="case-2")
    service.add_retest("eng-1", "persists", original_finding_id="finding", original_case_id="case-1")
    service.create_baseline("eng-1", "before-fix")
    service.add_retest("eng-1", "partial", original_finding_id="finding")
    assert service.compare("eng-1", "before-fix")["retest"]["finding"]["outcome"] == "partial"


def test_canonical_finding_refresh_retains_links_and_baseline(service):
    finding = Finding(id="canonical", title="Initial result")
    service.link_finding("eng-1", finding, case_ids=["case-1"])
    service.create_baseline("eng-1", "draft")
    finding.confirm("Peer verified")
    updated = service.refresh_finding("eng-1", finding)
    assert updated.snapshot["status"] == "confirmed"
    assert updated.case_ids == ["case-1"]
    comparison = service.compare("eng-1", "draft")
    assert comparison["baseline"]["findings"][finding.id]["snapshot"]["status"] == "draft"
    assert comparison["current"]["findings"][finding.id]["snapshot"]["status"] == "confirmed"
    assert comparison["changes"]["changed_findings"] == [finding.id]


@pytest.mark.parametrize("state", ["requested", "in_review", "approved", "changes_requested"])
@pytest.mark.parametrize("disposition", ["open", "confirmed", "false_positive", "accepted_risk", "duplicate"])
def test_review_and_disposition_states_are_explicit(service, state, disposition):
    result = service.add_review("eng-1", "case", "case-1", "peer", state=state, disposition=disposition)
    assert service.get_engagement("eng-1").reviews[0] == result


def test_invalid_review_remediation_hypothesis_values(service):
    service.link_finding("eng-1", Finding(id="finding"))
    with pytest.raises(ValueError, match="review state"):
        service.add_review("eng-1", "finding", "finding", "peer", state="done")
    with pytest.raises(ValueError, match="disposition"):
        service.add_review("eng-1", "finding", "finding", "peer", disposition="verified")
    with pytest.raises(ValueError, match="due_at"):
        service.add_remediation("eng-1", "finding", "owner", due_at="tomorrow")
    with pytest.raises(ValueError, match="hypothesis status"):
        service.add_hypothesis("eng-1", "A thought", status="proven")
    with pytest.raises(ValueError, match="Unsupported remediation"):
        service.update_remediation("eng-1", "missing", finding_id="other")


def test_cross_engagement_execution_and_observation_rejected(service):
    observation = Observation("host", "192.0.2.10", engagement_id="another")
    with pytest.raises(ValueError, match="different engagement"):
        service.add_manual_observation("eng-1", observation)
    execution = completed()
    execution.engagement_id = "another"
    with pytest.raises(ValueError, match="different engagement"):
        service.record_execution("eng-1", execution)
    execution.engagement_id = None
    execution.observations[0].engagement_id = "another"
    with pytest.raises(ValueError, match="different engagement"):
        service.record_execution("eng-1", execution)


def test_duplicate_ids_and_invalid_methodology_links(service):
    with pytest.raises(ValueError, match="Duplicate"):
        service.add_plan("eng-1", AssessmentPlan("another", "Duplicate", cases=[AssessmentCase("case-1", "Duplicate")]))
    with pytest.raises(ValueError, match="pin"):
        service.add_plan("eng-1", AssessmentPlan("another", "Unpinned", cases=[
            AssessmentCase("other", "Check", methodology_id="owasp-wstg", control_id="WSTG-INFO-01")]))
    with pytest.raises(ValueError, match="Unknown methodology control"):
        service.add_plan("eng-1", AssessmentPlan("another", "Bad control", cases=[
            AssessmentCase("other", "Check", methodology_id="owasp-wstg", control_id="MISSING")],
            methodology_versions={"owasp-wstg": "4.2"}))


def test_methodology_catalog_is_real_pinned_data_and_generates_checklists(service):
    catalog = MethodologyCatalog()
    profiles = catalog.list()
    assert {item["id"] for item in profiles} == {"nist-sp800-115", "ptes", "owasp-wstg", "owasp-asvs", "owasp-api-top10", "mitre-attack"}
    for profile in profiles:
        assert profile["source"].startswith("http")
        assert profile["scope"] == "representative_subset"
        assert profile["certification"] is False
        plan = catalog.plan(profile["id"], target="192.0.2.10", plan_id=profile["id"])
        service.add_plan("eng-1", plan)
        assert plan.methodology_versions[profile["id"]] == profile["version"]
        assert all(case.version == profile["profile_version"] for case in plan.cases)
        assert all(case.control_id and case.methodology_id == profile["id"] for case in plan.cases)
    assert service.coverage("eng-1")["summary"]["total"] == 27
    with pytest.raises(ValueError, match="Unknown"):
        catalog.get("missing")
    with pytest.raises(ValueError, match="Unknown"):
        catalog.get("owasp-wstg", "latest")


def test_operator_profile_json_yaml_and_workflow_roundtrip(service):
    profile = import_profile(FIXTURE.read_text())
    assert profile.version == "2.1.0"
    exported = export_profile(profile)
    assert export_profile(import_profile(exported)) == exported
    yaml = pytest.importorskip("yaml")
    assert yaml.safe_load(export_profile(profile, "yaml")) == profile.to_dict()
    assert import_profile(export_profile(profile, "yaml"), "yaml") == profile
    service.apply_profile("eng-1", profile)
    restored = service.get_engagement("eng-1")
    assert restored.profiles[0] == profile
    assert restored.plans[-1] == profile.plans[0]
    assert restored.profiles[0].workflow_templates[0]["steps"][0]["module"] == "web/httpx"
    assert restored.profiles[0].workflow_refs == ["api-inventory"]


def test_json_profiles_work_without_optional_yaml(monkeypatch):
    original_import = builtins.__import__

    def unavailable(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("Optional dependency absent")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", unavailable)
    profile = import_profile(FIXTURE.read_text())
    assert import_profile(export_profile(profile)) == profile
    with pytest.raises(ValueError, match="PyYAML"):
        export_profile(profile, "yaml")
    with pytest.raises(ValueError, match="PyYAML"):
        import_profile("name: example", "yaml")


@pytest.mark.parametrize("content", ["[]", "null", "{", '{"id":"x"}', '{"id":"x","name":"name","schema_version":9}',
                                     '{"id":"x","name":"name","plans":null}',
                                     '{"id":"x","name":"name","workflow_templates":[{}]}'])
def test_malformed_profiles_are_rejected(content):
    with pytest.raises(ValueError):
        import_profile(content)


@pytest.mark.parametrize("format", ["xml", "toml", "pickle"])
def test_only_json_and_optional_yaml_profiles(format):
    with pytest.raises(ValueError, match="format"):
        import_profile("{}", format)
    with pytest.raises(ValueError, match="format"):
        export_profile(AssessmentProfile("id", "name"), format)


@pytest.mark.parametrize("changes", [
    {"name": ""}, {"targets": "host"}, {"phases": [1]}, {"metadata": []},
    {"schema_version": 2}, {"created_at": "yesterday"}, {"plans": None},
    {"plans": [{"id": "p", "name": "plan", "cases": None}]},
    {"checks": [{"id": "x", "case_id": "missing", "state": "tested"}]},
    {"unexpected": True}, {"metadata": {"nonfinite": float("nan")}},
    {"executions": None}, {"executions": {}}, {"baselines": {"bad": {}}},
    {"metadata": {"tuple": (1, 2)}}, {"metadata": {1: "non-string key"}},
    {"schema_version": True},
])
def test_malformed_engagements_are_rejected(service, changes):
    data = service.get_engagement("eng-1").to_dict()
    data.update(changes)
    with pytest.raises(ValueError):
        Engagement.from_dict(data)


def test_malformed_repository_and_identity_mismatch(service):
    path = service.repository.path / "eng-1.json"
    original = path.read_text()
    path.write_text("{")
    with pytest.raises(ValueError, match="Malformed"):
        service.get_engagement("eng-1")
    data = json.loads(original)
    data["id"] = "another"
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match="filename"):
        service.get_engagement("eng-1")
    with pytest.raises(ValueError, match="portable"):
        service.get_engagement("../other")


def test_baseline_cannot_be_overwritten_and_comparison_requires_known_baseline(service):
    service.create_baseline("eng-1", "before")
    with pytest.raises(ValueError, match="already exists"):
        service.create_baseline("eng-1", "before")
    with pytest.raises(ValueError, match="Unknown baseline"):
        service.compare("eng-1", "missing")


def test_empty_and_all_not_applicable_coverage_is_finite(tmp_path):
    service = AssessmentService(tmp_path)
    service.create_engagement("Empty", engagement_id="empty")
    assert service.coverage("empty")["summary"]["coverage_percent"] == 0.0
    service.add_plan("empty", AssessmentPlan("p", "Plan", cases=[AssessmentCase("c", "Check")]))
    service.record_check("empty", "c", "not_applicable")
    assert service.coverage("empty")["summary"]["coverage_percent"] == 0.0


def test_invalid_attached_profile_is_rejected_before_repository_write(service):
    before = service.export_engagement("eng-1")
    engagement = service.get_engagement("eng-1")
    engagement.profiles.append(AssessmentProfile("p", "Profile", metadata=[]))
    with pytest.raises(ValueError, match="metadata"):
        service.repository.update(engagement)
    assert service.export_engagement("eng-1") == before
