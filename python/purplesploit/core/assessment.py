"""Capability-scoped assessment lifecycle records and local JSON persistence.

This store complements the execution and canonical finding contracts. It stores
finding snapshots and references, never a second independently edited finding.
Methodology coverage describes the selected checklist, not certification.
"""

from __future__ import annotations

from collections import Counter
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import date, datetime
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any
from uuid import uuid4

from .execution import ExecutionOutcome, ExecutionResult, Observation, utc_now


SCHEMA_VERSION = 1
COVERAGE_STATES = frozenset({"tested", "not_tested", "not_applicable", "automated", "manual", "imported"})
TESTED_STATES = frozenset({"tested", "automated", "manual", "imported"})
REVIEW_STATES = frozenset({"requested", "in_review", "approved", "changes_requested"})
DISPOSITIONS = frozenset({"open", "confirmed", "false_positive", "accepted_risk", "duplicate"})
REMEDIATION_STATES = frozenset({"open", "in_progress", "resolved", "deferred", "wont_fix"})
RETEST_OUTCOMES = frozenset({"fixed", "persists", "partial", "inconclusive", "not_tested"})
METHODOLOGY_PATH = Path(__file__).resolve().parents[1] / "data" / "methodologies"


def _id() -> str:
    return str(uuid4())


def _text(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _strings(value: Any, label: str) -> None:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item.strip() for item in value):
        raise ValueError(f"{label} must be a list of nonempty strings")


def _choice(value: str, choices: frozenset, label: str) -> None:
    if not isinstance(value, str) or value not in choices:
        raise ValueError(f"Invalid {label}: {value!r}; expected one of {sorted(choices)}")


def _json(value: Any) -> str:
    try:
        encoded = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n"
        if json.loads(encoded) != value:
            raise ValueError("Value would change during JSON round-trip")
        return encoded
    except (TypeError, ValueError) as exc:
        raise ValueError("Assessment values must be finite JSON values") from exc


class Record:
    def to_dict(self) -> dict[str, Any]:
        return deepcopy(asdict(self))

    @classmethod
    def from_dict(cls, value: dict[str, Any]):
        if not isinstance(value, dict):
            raise ValueError(f"{cls.__name__} must be an object")
        try:
            return cls(**deepcopy(value))
        except TypeError as exc:
            raise ValueError(f"Invalid {cls.__name__}: {exc}") from exc


@dataclass
class EvidenceReference(Record):
    ref: str
    id: str = field(default_factory=_id)
    title: str = ""
    media_type: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestCase(Record):
    id: str
    title: str
    description: str = ""
    version: str = "1"
    target: str = ""
    methodology_id: str | None = None
    control_id: str | None = None
    workflow_refs: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestPlan(Record):
    id: str
    name: str
    version: str = "1"
    cases: list[TestCase] = field(default_factory=list)
    methodology_versions: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, value):
        data = deepcopy(value)
        if not isinstance(data, dict):
            raise ValueError("TestPlan must be an object")
        if not isinstance(data.get("cases", []), list):
            raise ValueError("cases must be a list")
        data["cases"] = [TestCase.from_dict(item) for item in data.get("cases", [])]
        return super().from_dict(data)


@dataclass
class CheckRecord(Record):
    case_id: str
    state: str
    id: str = field(default_factory=_id)
    outcome: str = ""
    note: str = ""
    execution_id: str | None = None
    observation_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)
    recorded_at: str = field(default_factory=utc_now)


@dataclass
class ManualEntry(Record):
    observation: dict[str, Any]
    id: str = field(default_factory=_id)
    entry_type: str = "observation"
    case_id: str | None = None
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class Hypothesis(Record):
    text: str
    id: str = field(default_factory=_id)
    status: str = "open"
    case_id: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    note: str = ""


@dataclass
class PeerReview(Record):
    subject_type: str
    subject_id: str
    reviewer: str
    state: str = "requested"
    disposition: str = "open"
    id: str = field(default_factory=_id)
    note: str = ""
    recorded_at: str = field(default_factory=utc_now)


@dataclass
class FindingLink(Record):
    id: str
    snapshot: dict[str, Any]
    case_ids: list[str] = field(default_factory=list)
    evidence_refs: list[str] = field(default_factory=list)


@dataclass
class Remediation(Record):
    finding_id: str
    owner: str
    status: str = "open"
    due_at: str | None = None
    reference: str = ""
    id: str = field(default_factory=_id)
    note: str = ""


@dataclass
class Retest(Record):
    outcome: str
    original_finding_id: str | None = None
    original_case_id: str | None = None
    evidence_refs: list[str] = field(default_factory=list)
    execution_id: str | None = None
    id: str = field(default_factory=_id)
    note: str = ""
    recorded_at: str = field(default_factory=utc_now)


@dataclass
class AssessmentProfile(Record):
    id: str
    name: str
    version: str = "1"
    plans: list[TestPlan] = field(default_factory=list)
    workflow_refs: list[str] = field(default_factory=list)
    workflow_templates: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("AssessmentProfile must be an object")
        data = deepcopy(value)
        if not isinstance(data.get("plans", []), list):
            raise ValueError("plans must be a list")
        data["plans"] = [TestPlan.from_dict(item) for item in data.get("plans", [])]
        result = super().from_dict(data)
        result.validate()
        return result

    def validate(self):
        _text(self.id, "profile id")
        _text(self.name, "profile name")
        _text(self.version, "profile version")
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported profile schema_version")
        _strings(self.workflow_refs, "workflow_refs")
        if not isinstance(self.metadata, dict):
            raise ValueError("profile metadata must be an object")
        if not isinstance(self.workflow_templates, list):
            raise ValueError("workflow_templates must be a list")
        # Workflow.from_dict preserves the existing engine's portable contract.
        from .workflow import Workflow
        for template in self.workflow_templates:
            try:
                Workflow.from_dict(template)
            except (TypeError, KeyError, ValueError, AttributeError) as exc:
                raise ValueError(f"Invalid workflow template: {exc}") from exc
        probe = Engagement(id="profile-validation", name=self.name, plans=self.plans)
        probe.validate()
        _json(self.to_dict())


@dataclass
class Engagement(Record):
    name: str
    id: str = field(default_factory=_id)
    created_at: str = field(default_factory=utc_now)
    targets: list[str] = field(default_factory=list)
    phases: list[str] = field(default_factory=lambda: ["planning", "testing", "analysis", "reporting", "retest"])
    metadata: dict[str, Any] = field(default_factory=dict)
    plans: list[TestPlan] = field(default_factory=list)
    evidence: list[EvidenceReference] = field(default_factory=list)
    manual_entries: list[ManualEntry] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    reviews: list[PeerReview] = field(default_factory=list)
    findings: list[FindingLink] = field(default_factory=list)
    remediations: list[Remediation] = field(default_factory=list)
    retests: list[Retest] = field(default_factory=list)
    checks: list[CheckRecord] = field(default_factory=list)
    executions: list[dict[str, Any]] = field(default_factory=list)
    profiles: list[AssessmentProfile] = field(default_factory=list)
    baselines: dict[str, dict[str, Any]] = field(default_factory=dict)
    schema_version: int = SCHEMA_VERSION

    @classmethod
    def from_dict(cls, value):
        if not isinstance(value, dict):
            raise ValueError("Engagement must be an object")
        data = deepcopy(value)
        types = {"plans": TestPlan, "evidence": EvidenceReference, "manual_entries": ManualEntry,
                 "hypotheses": Hypothesis, "reviews": PeerReview, "findings": FindingLink,
                 "remediations": Remediation, "retests": Retest, "checks": CheckRecord,
                 "profiles": AssessmentProfile}
        for key, kind in types.items():
            if not isinstance(data.get(key, []), list):
                raise ValueError(f"{key} must be a list")
            data[key] = [kind.from_dict(item) for item in data.get(key, [])]
        result = super().from_dict(data)
        result.validate()
        return result

    def validate(self):
        _text(self.id, "engagement id")
        _text(self.name, "engagement name")
        _text(self.created_at, "created_at")
        try:
            datetime.fromisoformat(self.created_at)
        except ValueError as exc:
            raise ValueError("Invalid created_at") from exc
        if type(self.schema_version) is not int or self.schema_version != SCHEMA_VERSION:
            raise ValueError("Unsupported assessment schema_version")
        _strings(self.targets, "targets")
        _strings(self.phases, "phases")
        if not isinstance(self.metadata, dict) or not isinstance(self.baselines, dict):
            raise ValueError("metadata and baselines must be objects")
        if not isinstance(self.executions, list):
            raise ValueError("executions must be a list")
        for name, snapshot in self.baselines.items():
            _text(name, "baseline name")
            if not isinstance(snapshot, dict) or any(not isinstance(snapshot.get(key), dict)
                                                     for key in ("checks", "coverage", "findings", "reviews", "remediation")):
                raise ValueError("Invalid baseline snapshot")
        collections = [self.plans, self.evidence, self.manual_entries, self.hypotheses,
                       self.reviews, self.findings, self.remediations, self.retests, self.checks, self.profiles]
        for collection in collections:
            if not isinstance(collection, list):
                raise ValueError("Record collections must be lists")
            ids = [_text(item.id, "record id") for item in collection]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate record id")
        for profile in self.profiles:
            profile.validate()
        cases = [case for plan in self.plans for case in plan.cases]
        case_ids = {_text(case.id, "case id") for case in cases}
        if len(case_ids) != len(cases):
            raise ValueError("Duplicate case id across plans")
        for plan in self.plans:
            _text(plan.name, "plan name")
            _text(plan.version, "plan version")
            if not isinstance(plan.methodology_versions, dict):
                raise ValueError("methodology_versions must be an object")
            if not isinstance(plan.cases, list):
                raise ValueError("cases must be a list")
            for case in plan.cases:
                _text(case.title, "case title")
                _text(case.version, "case version")
                _strings(case.workflow_refs, "workflow_refs")
                if case.methodology_id is not None:
                    _text(case.methodology_id, "methodology_id")
                if case.control_id is not None:
                    _text(case.control_id, "control_id")
                if bool(case.methodology_id) != bool(case.control_id):
                    raise ValueError("methodology_id and control_id must be paired")
                if case.methodology_id and case.methodology_id not in plan.methodology_versions:
                    raise ValueError("Plan must pin each case methodology version")
                if case.methodology_id:
                    _text(case.methodology_id, "methodology_id")
                    _text(case.control_id, "control_id")
                    _text(plan.methodology_versions[case.methodology_id], "methodology version")
                    catalog = MethodologyCatalog()
                    known = {item["id"] for item in catalog.list()}
                    if case.methodology_id in known:
                        profile = catalog.get(case.methodology_id, plan.methodology_versions[case.methodology_id])
                        if case.control_id not in {item["id"] for item in profile["checks"]}:
                            raise ValueError("Unknown methodology control")
        evidence_ids = {item.id for item in self.evidence}
        finding_ids = {item.id for item in self.findings}
        execution_ids = set()
        observation_ids = set()
        for execution in self.executions:
            try:
                result = ExecutionResult.from_dict(deepcopy(execution))
            except (TypeError, ValueError, AttributeError) as exc:
                raise ValueError("Invalid execution record") from exc
            if result.engagement_id != self.id:
                raise ValueError("Execution belongs to a different engagement")
            _text(result.request_id, "execution id")
            if result.request_id in execution_ids:
                raise ValueError("Duplicate execution id")
            execution_ids.add(result.request_id)
            for observation in result.observations:
                if observation.engagement_id != self.id:
                    raise ValueError("Observation belongs to a different engagement")
                observation_ids.add(observation.observation_id)
        for entry in self.manual_entries:
            _choice(entry.entry_type, frozenset({"observation", "note"}), "manual entry type")
            try:
                observation = Observation.from_dict(deepcopy(entry.observation))
            except (TypeError, ValueError, AttributeError) as exc:
                raise ValueError("Invalid manual observation") from exc
            if observation.engagement_id != self.id:
                raise ValueError("Observation belongs to a different engagement")
            observation_ids.add(observation.observation_id)
        def link(value, known, label):
            if value is not None and (not isinstance(value, str) or value not in known):
                raise ValueError(f"Unknown {label}: {value}")
        for item in self.evidence:
            _text(item.ref, "evidence ref")
        for item in [*self.manual_entries, *self.hypotheses, *self.checks, *self.findings, *self.retests]:
            _strings(item.evidence_refs, "evidence_refs")
            for ref in item.evidence_refs:
                link(ref, evidence_ids, "evidence reference")
        for item in [*self.manual_entries, *self.hypotheses, *self.checks]:
            link(item.case_id, case_ids, "case")
        for hypothesis in self.hypotheses:
            _text(hypothesis.text, "hypothesis")
            _choice(hypothesis.status, frozenset({"open", "supported", "rejected", "inconclusive"}), "hypothesis status")
        for finding in self.findings:
            if not isinstance(finding.snapshot, dict) or finding.snapshot.get("id") != finding.id:
                raise ValueError("Finding snapshot must retain canonical finding id")
            _strings(finding.case_ids, "finding case_ids")
            for case_id in finding.case_ids:
                link(case_id, case_ids, "case")
        subjects = {"finding": finding_ids, "case": case_ids, "hypothesis": {x.id for x in self.hypotheses},
                    "observation": observation_ids, "manual_entry": {x.id for x in self.manual_entries}}
        for review in self.reviews:
            _text(review.reviewer, "reviewer")
            _choice(review.state, REVIEW_STATES, "review state")
            _choice(review.disposition, DISPOSITIONS, "disposition")
            if not isinstance(review.subject_type, str) or review.subject_type not in subjects:
                raise ValueError("Unknown review subject type")
            link(review.subject_id, subjects[review.subject_type], "review subject")
            _text(review.subject_id, "review subject")
        for remediation in self.remediations:
            link(remediation.finding_id, finding_ids, "finding")
            _text(remediation.finding_id, "finding id")
            _text(remediation.owner, "remediation owner")
            _choice(remediation.status, REMEDIATION_STATES, "remediation status")
            if remediation.due_at is not None:
                try:
                    date.fromisoformat(remediation.due_at)
                except (TypeError, ValueError) as exc:
                    raise ValueError("due_at must be an ISO date (YYYY-MM-DD)") from exc
        for check in self.checks:
            _text(check.case_id, "case id")
            _choice(check.state, COVERAGE_STATES, "coverage state")
            link(check.execution_id, execution_ids, "execution")
            _strings(check.observation_ids, "observation_ids")
            for observation_id in check.observation_ids:
                link(observation_id, observation_ids, "observation")
            if check.state == "automated":
                if not check.execution_id:
                    raise ValueError("Automated coverage requires an execution")
                execution = next(x for x in self.executions if x["request_id"] == check.execution_id)
                if not _completed_execution(execution):
                    raise ValueError("Automated coverage requires a successful completed execution")
        for retest in self.retests:
            _choice(retest.outcome, RETEST_OUTCOMES, "retest outcome")
            if not (retest.original_finding_id or retest.original_case_id):
                raise ValueError("Retest requires an original finding or case")
            link(retest.original_finding_id, finding_ids, "original finding")
            link(retest.original_case_id, case_ids, "original case")
            link(retest.execution_id, execution_ids, "execution")
            if retest.original_finding_id and retest.original_case_id:
                finding = next(x for x in self.findings if x.id == retest.original_finding_id)
                if retest.original_case_id not in finding.case_ids:
                    raise ValueError("Retest finding is not linked to the original case")
        _json(self.to_dict())


def _completed_execution(execution):
    return (execution.get("outcome") == ExecutionOutcome.SUCCESS.value
            and execution.get("success") is True and bool(execution.get("finished_at")))


class AssessmentRepository:
    """One exact JSON document per engagement, replaced atomically on update.

    This is a local feature store, with no cross-process merge/locking contract.
    Callers must coordinate concurrent writers to the same engagement.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)

    def _path(self, engagement_id):
        _text(engagement_id, "engagement id")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", engagement_id):
            raise ValueError("engagement id must be a portable filename identifier")
        return self.path / f"{engagement_id}.json"

    def save(self, engagement: Engagement) -> Engagement:
        engagement.validate()
        target = self._path(engagement.id)
        payload = _json(engagement.to_dict())
        self.path.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path,
                                             prefix=f".{engagement.id}.", suffix=".tmp", delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, target)
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
        return Engagement.from_dict(engagement.to_dict())

    def create(self, engagement: Engagement) -> Engagement:
        if self._path(engagement.id).exists():
            raise ValueError(f"Engagement already exists: {engagement.id}")
        return self.save(engagement)

    def load(self, engagement_id: str) -> Engagement:
        try:
            data = json.loads(self._path(engagement_id).read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError(f"Malformed engagement JSON: {engagement_id}") from exc
        engagement = Engagement.from_dict(data)
        if engagement.id != engagement_id:
            raise ValueError("Stored engagement id does not match its filename")
        return engagement

    def list(self) -> list[Engagement]:
        if not self.path.exists():
            return []
        return [self.load(path.stem) for path in sorted(self.path.glob("*.json"))]

    def update(self, engagement: Engagement) -> Engagement:
        if not self._path(engagement.id).exists():
            raise FileNotFoundError(engagement.id)
        return self.save(engagement)


class MethodologyCatalog:
    def __init__(self, path: str | Path = METHODOLOGY_PATH):
        self.path = Path(path)

    def list(self) -> list[dict[str, Any]]:
        profiles = []
        for path in sorted(self.path.glob("*.json")):
            profile = json.loads(path.read_text(encoding="utf-8"))
            for key in ("id", "name", "version", "source", "profile_version"):
                _text(profile.get(key), f"methodology {key}")
            if profile.get("scope") != "representative_subset" or not profile.get("checks"):
                raise ValueError("Methodology must declare a nonempty representative subset")
            ids = [_text(check.get("id"), "control id") for check in profile["checks"]]
            if len(ids) != len(set(ids)):
                raise ValueError("Duplicate methodology control id")
            profiles.append(profile)
        return profiles

    def get(self, methodology_id: str, version: str | None = None) -> dict[str, Any]:
        matches = [item for item in self.list() if item["id"] == methodology_id
                   and (version is None or item["version"] == version)]
        if len(matches) != 1:
            raise ValueError(f"Unknown or ambiguous methodology: {methodology_id}@{version}")
        return matches[0]

    def plan(self, methodology_id: str, *, target: str = "", plan_id: str | None = None,
             version: str | None = None) -> TestPlan:
        profile = self.get(methodology_id, version)
        identity = plan_id or f"{methodology_id}-{_id()}"
        return TestPlan(identity, profile["name"], profile["profile_version"],
                        cases=[TestCase(f"{identity}:{check['id']}", check["title"],
                                        description=check.get("description", ""), target=target,
                                        version=profile["profile_version"],
                                        methodology_id=profile["id"], control_id=check["id"])
                               for check in profile["checks"]],
                        methodology_versions={profile["id"]: profile["version"]})


def export_profile(profile: AssessmentProfile, format: str = "json") -> str:
    profile.validate()
    if format.lower() == "json":
        return _json(profile.to_dict())
    if format.lower() not in {"yaml", "yml"}:
        raise ValueError("Profile format must be json or yaml")
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("YAML profiles require optional PyYAML; JSON is available") from exc
    return yaml.safe_dump(profile.to_dict(), sort_keys=True, allow_unicode=True)


def import_profile(content: str, format: str = "json") -> AssessmentProfile:
    if not isinstance(content, str):
        raise ValueError("Profile content must be text")
    if format.lower() == "json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError("Malformed profile JSON") from exc
    elif format.lower() in {"yaml", "yml"}:
        try:
            import yaml
        except ImportError as exc:
            raise ValueError("YAML profiles require optional PyYAML; JSON is available") from exc
        try:
            data = yaml.safe_load(content)
        except yaml.YAMLError as exc:
            raise ValueError("Malformed profile YAML") from exc
    else:
        raise ValueError("Profile format must be json or yaml")
    return AssessmentProfile.from_dict(data)


class AssessmentService:
    """Service API for CLI/API adapters; every mutation validates and persists."""

    def __init__(self, repository: AssessmentRepository | str | Path):
        repository_contract = ("create", "load", "list", "update")
        self.repository = (
            repository
            if all(callable(getattr(repository, name, None)) for name in repository_contract)
            else AssessmentRepository(repository)
        )
        self.methodologies = MethodologyCatalog()

    def create_engagement(self, name: str, *, targets=None, phases=None, metadata=None,
                          engagement_id: str | None = None) -> Engagement:
        values = {"name": name, "targets": deepcopy([] if targets is None else targets),
                  "metadata": deepcopy({} if metadata is None else metadata)}
        if phases is not None:
            values["phases"] = deepcopy(phases)
        if engagement_id is not None:
            values["id"] = engagement_id
        return self.repository.create(Engagement(**values))

    def get_engagement(self, engagement_id: str) -> Engagement:
        return self.repository.load(engagement_id)

    def list_engagements(self) -> list[Engagement]:
        return self.repository.list()

    def update_engagement(self, engagement_id: str, **changes) -> Engagement:
        if set(changes) - {"name", "targets", "phases", "metadata"}:
            raise ValueError("Only name, targets, phases, metadata can be updated directly")
        engagement = self.get_engagement(engagement_id)
        for key, value in changes.items():
            setattr(engagement, key, deepcopy(value))
        return self.repository.update(engagement)

    def _append(self, engagement_id, collection, record):
        engagement = self.get_engagement(engagement_id)
        getattr(engagement, collection).append(deepcopy(record))
        self.repository.update(engagement)
        return deepcopy(record)

    def add_plan(self, engagement_id: str, plan: TestPlan) -> TestPlan:
        return self._append(engagement_id, "plans", plan)

    def add_evidence(self, engagement_id: str, ref: str, **values) -> EvidenceReference:
        return self._append(engagement_id, "evidence", EvidenceReference(ref, **values))

    def attach_evidence(self, engagement_id: str, subject_type: str, subject_id: str,
                        evidence_refs: list[str]):
        collections = {"finding": "findings", "manual_entry": "manual_entries", "hypothesis": "hypotheses",
                       "check": "checks", "retest": "retests"}
        if not isinstance(subject_type, str) or subject_type not in collections:
            raise ValueError("Unsupported evidence subject type")
        engagement = self.get_engagement(engagement_id)
        record = next((item for item in getattr(engagement, collections[subject_type]) if item.id == subject_id), None)
        if record is None:
            raise ValueError("Unknown evidence subject")
        _strings(evidence_refs, "evidence_refs")
        record.evidence_refs = list(dict.fromkeys([*record.evidence_refs, *evidence_refs]))
        self.repository.update(engagement)
        return deepcopy(record)

    def add_manual_observation(self, engagement_id: str, observation: Observation, *, case_id=None,
                               evidence_refs=None, entry_type="observation") -> ManualEntry:
        data = observation.to_dict()
        if data.get("engagement_id") not in (None, engagement_id):
            raise ValueError("Observation belongs to a different engagement")
        data["engagement_id"] = engagement_id
        entry = ManualEntry(data, entry_type=entry_type, case_id=case_id,
                            evidence_refs=deepcopy(evidence_refs or []))
        engagement = self.get_engagement(engagement_id)
        engagement.manual_entries.append(entry)
        if case_id is not None and entry_type == "observation":
            engagement.checks.append(CheckRecord(case_id, "manual", observation_ids=[data["observation_id"]],
                                    evidence_refs=deepcopy(evidence_refs or [])))
        self.repository.update(engagement)
        return deepcopy(entry)

    def add_note(self, engagement_id: str, text: str, *, target="", case_id=None,
                 evidence_refs=None) -> ManualEntry:
        _text(text, "note")
        # Explicit identity keeps two separately entered notes independently reviewable.
        observation = Observation("note", target, attributes={"text": text}, observation_id=_id())
        return self.add_manual_observation(engagement_id, observation, case_id=case_id,
                                           evidence_refs=evidence_refs, entry_type="note")

    def add_hypothesis(self, engagement_id: str, text: str, **values) -> Hypothesis:
        return self._append(engagement_id, "hypotheses", Hypothesis(text, **values))

    def update_hypothesis(self, engagement_id: str, hypothesis_id: str, *, status: str, note="") -> Hypothesis:
        return self._update_record(engagement_id, "hypotheses", hypothesis_id, status=status, note=note)

    def link_finding(self, engagement_id: str, finding, *, case_ids=None, evidence_refs=None) -> FindingLink:
        snapshot = deepcopy(finding.to_dict() if hasattr(finding, "to_dict") else finding)
        if not isinstance(snapshot, dict):
            raise ValueError("Finding must be a canonical Finding or JSON object")
        return self._append(engagement_id, "findings", FindingLink(snapshot.get("id", ""), snapshot,
                            case_ids=deepcopy(case_ids or []), evidence_refs=deepcopy(evidence_refs or [])))

    def refresh_finding(self, engagement_id: str, finding) -> FindingLink:
        """Refresh a linked snapshot from the canonical finding after it changes."""
        snapshot = deepcopy(finding.to_dict() if hasattr(finding, "to_dict") else finding)
        if not isinstance(snapshot, dict):
            raise ValueError("Finding must be a canonical Finding or JSON object")
        return self._update_record(engagement_id, "findings", snapshot.get("id"), snapshot=snapshot)

    def add_review(self, engagement_id: str, subject_type: str, subject_id: str,
                   reviewer: str, **values) -> PeerReview:
        return self._append(engagement_id, "reviews", PeerReview(subject_type, subject_id, reviewer, **values))

    def update_review(self, engagement_id: str, review_id: str, *, state: str,
                      disposition: str = "open", note="") -> PeerReview:
        return self._update_record(engagement_id, "reviews", review_id, state=state,
                                   disposition=disposition, note=note)

    def add_remediation(self, engagement_id: str, finding_id: str, owner: str, **values) -> Remediation:
        return self._append(engagement_id, "remediations", Remediation(finding_id, owner, **values))

    def update_remediation(self, engagement_id: str, remediation_id: str, **changes) -> Remediation:
        if set(changes) - {"owner", "status", "due_at", "reference", "note"}:
            raise ValueError("Unsupported remediation fields")
        return self._update_record(engagement_id, "remediations", remediation_id, **changes)

    def _update_record(self, engagement_id, collection, record_id, **changes):
        engagement = self.get_engagement(engagement_id)
        record = next((item for item in getattr(engagement, collection) if item.id == record_id), None)
        if record is None:
            raise ValueError(f"Unknown {collection} record: {record_id}")
        for key, value in changes.items():
            setattr(record, key, deepcopy(value))
        self.repository.update(engagement)
        return deepcopy(record)

    def record_check(self, engagement_id: str, case_id: str, state: str, **values) -> CheckRecord:
        return self._append(engagement_id, "checks", CheckRecord(case_id, state, **values))

    def record_execution(self, engagement_id: str, execution: ExecutionResult, *, case_ids=None,
                         evidence_refs=None) -> ExecutionResult:
        data = execution.to_dict()
        if data.get("engagement_id") not in (None, engagement_id):
            raise ValueError("Execution belongs to a different engagement")
        data["engagement_id"] = engagement_id
        for observation in data["observations"]:
            if observation.get("engagement_id") not in (None, engagement_id):
                raise ValueError("Observation belongs to a different engagement")
            observation["engagement_id"] = engagement_id
        engagement = self.get_engagement(engagement_id)
        engagement.executions.append(data)
        for case_id in case_ids or []:
            engagement.checks.append(CheckRecord(case_id, "automated" if _completed_execution(data) else "not_tested",
                                    execution_id=execution.request_id, outcome=data["outcome"],
                                    observation_ids=[item["observation_id"] for item in data["observations"]],
                                    evidence_refs=deepcopy(evidence_refs or [])))
        self.repository.update(engagement)
        return ExecutionResult.from_dict(data)

    def add_retest(self, engagement_id: str, outcome: str, **values) -> Retest:
        return self._append(engagement_id, "retests", Retest(outcome, **values))

    def apply_profile(self, engagement_id: str, profile: AssessmentProfile) -> Engagement:
        profile.validate()
        engagement = self.get_engagement(engagement_id)
        engagement.profiles.append(deepcopy(profile))
        engagement.plans.extend(deepcopy(profile.plans))
        return self.repository.update(engagement)

    def coverage(self, engagement_id: str) -> dict[str, Any]:
        return compute_coverage(self.get_engagement(engagement_id))

    def create_baseline(self, engagement_id: str, name: str) -> dict[str, Any]:
        _text(name, "baseline name")
        engagement = self.get_engagement(engagement_id)
        if name in engagement.baselines:
            raise ValueError("Baseline already exists")
        snapshot = _comparison_snapshot(engagement)
        engagement.baselines[name] = snapshot
        self.repository.update(engagement)
        return deepcopy(snapshot)

    def compare(self, engagement_id: str, baseline: str) -> dict[str, Any]:
        engagement = self.get_engagement(engagement_id)
        if baseline not in engagement.baselines:
            raise ValueError("Unknown baseline")
        before = deepcopy(engagement.baselines[baseline])
        current = _comparison_snapshot(engagement)
        old_ids, new_ids = set(before["findings"]), set(current["findings"])
        retests = {item.original_finding_id or f"case:{item.original_case_id}": item.to_dict()
                   for item in engagement.retests}
        return {"engagement_id": engagement_id, "baseline": before, "current": current, "retest": retests,
                "changes": {"added_findings": sorted(new_ids - old_ids),
                            "removed_findings": sorted(old_ids - new_ids),
                            "retained_findings": sorted(old_ids & new_ids),
                            "changed_findings": sorted(key for key in old_ids & new_ids
                                                       if before["findings"][key] != current["findings"][key]),
                            "fixed_findings": sorted(key for key, value in retests.items()
                                                     if key in new_ids and value["outcome"] == "fixed"),
                            "changed_checks": sorted(key for key in set(before["checks"]) | set(current["checks"])
                                                     if before["checks"].get(key) != current["checks"].get(key))}}

    def export_engagement(self, engagement_id: str) -> str:
        return _json(self.get_engagement(engagement_id).to_dict())

    def import_engagement(self, content: str) -> Engagement:
        try:
            engagement = Engagement.from_dict(json.loads(content))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ValueError("Malformed engagement JSON") from exc
        return self.repository.create(engagement)


def compute_coverage(engagement: Engagement) -> dict[str, Any]:
    """Latest check per case; attempts and notes alone never imply coverage.

    `state` retains all six operator-facing distinctions; `tested` also groups
    completed automated, manual, imported and unqualified tested records.
    Evidence is linked by registered reference ID, not copied or interpreted.
    """
    engagement.validate()
    latest = {item.case_id: item for item in engagement.checks}
    rows = []
    for plan in engagement.plans:
        for case in plan.cases:
            check = latest.get(case.id)
            state = check.state if check else "not_tested"
            evidence_refs = list(check.evidence_refs) if check else []
            if check:
                for entry in engagement.manual_entries:
                    if entry.observation["observation_id"] in check.observation_ids:
                        evidence_refs.extend(entry.evidence_refs)
            rows.append({"plan_id": plan.id, "case_id": case.id, "title": case.title,
                         "methodology_id": case.methodology_id, "control_id": case.control_id,
                         "methodology_version": plan.methodology_versions.get(case.methodology_id),
                         "target": case.target, "state": state, "tested": state in TESTED_STATES,
                         "check_id": check.id if check else None,
                         "execution_id": check.execution_id if check else None,
                         "observation_ids": list(check.observation_ids) if check else [],
                         "evidence_refs": list(dict.fromkeys(evidence_refs))})
    counts = Counter(row["state"] for row in rows)
    applicable = len(rows) - counts["not_applicable"]
    tested = sum(row["tested"] for row in rows)
    return {"engagement_id": engagement.id, "scope": "selected_checklist_only",
            "certification": False, "checks": rows,
            "summary": {"total": len(rows), "applicable": applicable, "tested": tested,
                        "coverage_percent": round(tested * 100 / applicable, 2) if applicable else 0.0,
                        "states": {state: counts[state] for state in sorted(COVERAGE_STATES)}}}


def _comparison_snapshot(engagement):
    coverage = compute_coverage(engagement)
    return {"checks": {row["case_id"]: row for row in coverage["checks"]},
            "coverage": coverage["summary"],
            "findings": {item.id: item.to_dict() for item in engagement.findings},
            "reviews": {item.id: item.to_dict() for item in engagement.reviews},
            "remediation": {item.id: item.to_dict() for item in engagement.remediations}}
