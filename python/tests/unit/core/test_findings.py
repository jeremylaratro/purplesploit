"""
Unit tests for purplesploit.core.findings module.

Tests cover:
- FindingStatus and Severity enums
- Evidence dataclass
- Finding dataclass and lifecycle methods
- FindingsManager CRUD operations
- Duplicate detection
- Export/import functionality
- Statistics generation
"""

import pytest
import json
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import MagicMock, patch

from purplesploit.core.findings import (
    FindingStatus,
    Severity,
    Evidence,
    Finding,
    FindingsManager,
)


# =============================================================================
# Severity Enum Tests
# =============================================================================

class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_from_cvss_critical(self):
        """Test CVSS 9.0+ returns CRITICAL."""
        assert Severity.from_cvss(9.0) == Severity.CRITICAL
        assert Severity.from_cvss(10.0) == Severity.CRITICAL
        assert Severity.from_cvss(9.5) == Severity.CRITICAL

    def test_from_cvss_high(self):
        """Test CVSS 7.0-8.9 returns HIGH."""
        assert Severity.from_cvss(7.0) == Severity.HIGH
        assert Severity.from_cvss(8.9) == Severity.HIGH
        assert Severity.from_cvss(7.5) == Severity.HIGH

    def test_from_cvss_medium(self):
        """Test CVSS 4.0-6.9 returns MEDIUM."""
        assert Severity.from_cvss(4.0) == Severity.MEDIUM
        assert Severity.from_cvss(6.9) == Severity.MEDIUM
        assert Severity.from_cvss(5.5) == Severity.MEDIUM

    def test_from_cvss_low(self):
        """Test CVSS 0.1-3.9 returns LOW."""
        assert Severity.from_cvss(0.1) == Severity.LOW
        assert Severity.from_cvss(3.9) == Severity.LOW
        assert Severity.from_cvss(2.0) == Severity.LOW

    def test_from_cvss_info(self):
        """Test CVSS 0 returns INFO."""
        assert Severity.from_cvss(0.0) == Severity.INFO
        assert Severity.from_cvss(0) == Severity.INFO


# =============================================================================
# FindingStatus Enum Tests
# =============================================================================

class TestFindingStatus:
    """Tests for FindingStatus enum."""

    def test_status_values(self):
        """Test all status values exist."""
        assert FindingStatus.DRAFT.value == "draft"
        assert FindingStatus.CONFIRMED.value == "confirmed"
        assert FindingStatus.REPORTED.value == "reported"
        assert FindingStatus.REMEDIATED.value == "remediated"
        assert FindingStatus.VERIFIED.value == "verified"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.ACCEPTED_RISK.value == "accepted_risk"


# =============================================================================
# Evidence Tests
# =============================================================================

class TestEvidence:
    """Tests for Evidence dataclass."""

    def test_evidence_creation(self):
        """Test basic evidence creation."""
        evidence = Evidence(
            title="Test Evidence",
            description="Test description",
            content="Test content",
        )

        assert evidence.title == "Test Evidence"
        assert evidence.description == "Test description"
        assert evidence.content == "Test content"
        assert evidence.id is not None
        assert evidence.evidence_type == "text"

    def test_evidence_with_file(self):
        """Test evidence with file path."""
        evidence = Evidence(
            title="Screenshot",
            file_path="/path/to/screenshot.png",
            evidence_type="screenshot",
        )

        assert evidence.file_path == "/path/to/screenshot.png"
        assert evidence.evidence_type == "screenshot"

    def test_evidence_to_dict(self):
        """Test evidence serialization."""
        evidence = Evidence(
            title="Test",
            content="test content",
            tags=["test", "unit"],
        )

        data = evidence.to_dict()

        assert data["title"] == "Test"
        assert data["content"] == "test content"
        assert data["tags"] == ["test", "unit"]
        assert "id" in data
        assert "captured_at" in data

    def test_evidence_from_dict(self):
        """Test evidence deserialization."""
        data = {
            "id": "abc123",
            "finding_id": "find1",
            "title": "Test",
            "description": "Desc",
            "content": "Content",
            "evidence_type": "log",
            "captured_at": "2024-01-15T10:00:00",
            "tags": ["test"],
        }

        evidence = Evidence.from_dict(data)

        assert evidence.id == "abc123"
        assert evidence.title == "Test"
        assert evidence.evidence_type == "log"
        assert isinstance(evidence.captured_at, datetime)


# =============================================================================
# Finding Tests
# =============================================================================

class TestFinding:
    """Tests for Finding dataclass."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            title="SQL Injection",
            severity=Severity.HIGH,
            description="SQL injection in login form",
            target="192.168.1.100",
        )

        assert finding.title == "SQL Injection"
        assert finding.severity == Severity.HIGH
        assert finding.status == FindingStatus.DRAFT
        assert finding.target == "192.168.1.100"
        assert finding.id is not None

    def test_finding_with_all_fields(self):
        """Test finding with all optional fields."""
        finding = Finding(
            title="Critical Vuln",
            severity=Severity.CRITICAL,
            description="Description",
            target="10.0.0.1",
            port=443,
            service="https",
            protocol="tcp",
            url="https://10.0.0.1/vulnerable",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cve_ids=["CVE-2024-1234"],
            cwe_ids=["CWE-89"],
            mitre_tactics=["TA0001"],
            mitre_techniques=["T1190"],
            impact="Full system compromise",
            remediation="Patch immediately",
            references=["https://example.com/advisory"],
        )

        assert finding.port == 443
        assert finding.cvss_score == 9.8
        assert "CVE-2024-1234" in finding.cve_ids
        assert "CWE-89" in finding.cwe_ids

    def test_add_evidence(self):
        """Test adding evidence to finding."""
        finding = Finding(
            title="Test",
            severity=Severity.MEDIUM,
            description="Test",
            target="test",
        )

        evidence = finding.add_evidence(
            title="PoC Screenshot",
            content="Screenshot data",
            evidence_type="screenshot",
        )

        assert len(finding.evidence) == 1
        assert finding.evidence[0].title == "PoC Screenshot"
        assert evidence.finding_id == finding.id

    def test_confirm_finding(self):
        """Test confirming a finding."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )

        finding.confirm("Verified by manual testing")

        assert finding.status == FindingStatus.CONFIRMED
        assert finding.confirmed_at is not None
        assert any("Confirmed" in note for note in finding.notes)

    def test_mark_reported(self):
        """Test marking finding as reported."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )

        finding.mark_reported()

        assert finding.status == FindingStatus.REPORTED
        assert finding.reported_at is not None

    def test_mark_remediated(self):
        """Test marking finding as remediated."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )

        finding.mark_remediated("Patch applied")

        assert finding.status == FindingStatus.REMEDIATED
        assert finding.remediated_at is not None
        assert any("Remediated" in note for note in finding.notes)

    def test_verify_remediation_success(self):
        """Test successful remediation verification."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )
        finding.mark_remediated()

        finding.verify_remediation(True, "Vuln no longer present")

        assert finding.status == FindingStatus.VERIFIED
        assert finding.verified_at is not None

    def test_verify_remediation_failure(self):
        """Test failed remediation verification."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )
        finding.mark_remediated()

        finding.verify_remediation(False, "Still exploitable")

        assert finding.status == FindingStatus.CONFIRMED

    def test_mark_false_positive(self):
        """Test marking as false positive."""
        finding = Finding(
            title="Test",
            severity=Severity.HIGH,
            description="Test",
            target="test",
        )

        finding.mark_false_positive("Scanner misidentified benign behavior")

        assert finding.status == FindingStatus.FALSE_POSITIVE
        assert any("False Positive" in note for note in finding.notes)

    def test_accept_risk(self):
        """Test accepting risk."""
        finding = Finding(
            title="Test",
            severity=Severity.MEDIUM,
            description="Test",
            target="test",
        )

        finding.accept_risk("Business decision", "Security Lead")

        assert finding.status == FindingStatus.ACCEPTED_RISK
        assert any("Accepted Risk" in note for note in finding.notes)
        assert any("Security Lead" in note for note in finding.notes)

    def test_add_note(self):
        """Test adding notes."""
        finding = Finding(
            title="Test",
            severity=Severity.LOW,
            description="Test",
            target="test",
        )

        finding.add_note("Initial investigation")
        finding.add_note("Further analysis needed")

        assert len(finding.notes) == 2

    def test_finding_to_dict(self):
        """Test finding serialization."""
        finding = Finding(
            title="Test Finding",
            severity=Severity.HIGH,
            description="Test description",
            target="192.168.1.1",
            port=80,
            cvss_score=7.5,
        )
        finding.add_evidence(title="Test Evidence", content="test")

        data = finding.to_dict()

        assert data["title"] == "Test Finding"
        assert data["severity"] == "high"
        assert data["status"] == "draft"
        assert data["port"] == 80
        assert len(data["evidence"]) == 1

    def test_finding_from_dict(self):
        """Test finding deserialization."""
        data = {
            "id": "find123",
            "title": "Deserialized Finding",
            "severity": "critical",
            "status": "confirmed",
            "description": "Test",
            "target": "10.0.0.1",
            "port": 443,
            "cvss_score": 9.5,
            "evidence": [{"id": "ev1", "title": "Evidence", "content": "data"}],
            "discovered_at": "2024-01-15T10:00:00",
            "confirmed_at": "2024-01-16T10:00:00",
        }

        finding = Finding.from_dict(data)

        assert finding.id == "find123"
        assert finding.title == "Deserialized Finding"
        assert finding.severity == Severity.CRITICAL
        assert finding.status == FindingStatus.CONFIRMED
        assert isinstance(finding.discovered_at, datetime)
        assert len(finding.evidence) == 1


# =============================================================================
# FindingsManager Tests
# =============================================================================

class TestFindingsManager:
    """Tests for FindingsManager class."""

    @pytest.fixture
    def findings_manager(self, tmp_path):
        """Create a FindingsManager with temporary storage."""
        return FindingsManager(storage_path=str(tmp_path / "findings"))

    def test_initial_state(self, findings_manager):
        """Test initial state of FindingsManager."""
        assert findings_manager.findings == {}
        assert findings_manager.storage_path.exists()

    def test_create_finding(self, findings_manager):
        """Test creating a finding."""
        finding = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="SQL injection vulnerability",
            target="192.168.1.100",
        )

        assert finding is not None
        assert finding.title == "SQL Injection"
        assert finding.id in findings_manager.findings

    def test_create_finding_with_extras(self, findings_manager):
        """Test creating a finding with additional fields."""
        finding = findings_manager.create(
            title="XSS",
            severity="medium",
            description="XSS in search",
            target="example.com",
            port=80,
            service="http",
            cve_ids=["CVE-2024-5678"],
        )

        assert finding.port == 80
        assert "CVE-2024-5678" in finding.cve_ids

    def test_create_duplicate_returns_existing(self, findings_manager):
        """Test creating duplicate finding returns existing one."""
        finding1 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="Test",
            target="192.168.1.100",
        )

        finding2 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="Different description",
            target="192.168.1.100",
        )

        assert finding1.id == finding2.id
        assert len(findings_manager.findings) == 1

    def test_get_finding(self, findings_manager):
        """Test getting a finding by ID."""
        created = findings_manager.create(
            title="Test",
            severity="low",
            description="Test",
            target="test",
        )

        found = findings_manager.get(created.id)

        assert found is not None
        assert found.id == created.id

    def test_get_nonexistent(self, findings_manager):
        """Test getting non-existent finding returns None."""
        assert findings_manager.get("nonexistent") is None

    def test_update_finding(self, findings_manager):
        """Test updating a finding."""
        finding = findings_manager.create(
            title="Original",
            severity="low",
            description="Original desc",
            target="test",
        )

        updated = findings_manager.update(
            finding.id,
            title="Updated",
            severity=Severity.HIGH,
        )

        assert updated.title == "Updated"
        assert updated.severity == Severity.HIGH

    def test_update_nonexistent(self, findings_manager):
        """Test updating non-existent finding returns None."""
        result = findings_manager.update("nonexistent", title="test")
        assert result is None

    def test_delete_finding(self, findings_manager):
        """Test deleting a finding."""
        finding = findings_manager.create(
            title="Test",
            severity="low",
            description="Test",
            target="test",
        )

        result = findings_manager.delete(finding.id)

        assert result is True
        assert finding.id not in findings_manager.findings

    def test_delete_nonexistent(self, findings_manager):
        """Test deleting non-existent finding returns False."""
        result = findings_manager.delete("nonexistent")
        assert result is False

    def test_list_findings(self, findings_manager):
        """Test listing all findings."""
        for i in range(3):
            findings_manager.create(
                title=f"Finding {i}",
                severity="medium",
                description="Test",
                target=f"target{i}",
            )

        findings = findings_manager.list_findings()

        assert len(findings) == 3

    def test_list_findings_filter_by_status(self, findings_manager):
        """Test filtering findings by status."""
        f1 = findings_manager.create(
            title="Draft Finding",
            severity="low",
            description="Test",
            target="target1",
        )
        f2 = findings_manager.create(
            title="Confirmed Finding",
            severity="high",
            description="Test",
            target="target2",
        )
        f2.confirm()

        draft_findings = findings_manager.list_findings(status=FindingStatus.DRAFT)
        confirmed_findings = findings_manager.list_findings(status=FindingStatus.CONFIRMED)

        assert len(draft_findings) == 1
        assert len(confirmed_findings) == 1

    def test_list_findings_filter_by_severity(self, findings_manager):
        """Test filtering findings by severity."""
        findings_manager.create(
            title="High Finding",
            severity="high",
            description="Test",
            target="target1",
        )
        findings_manager.create(
            title="Low Finding",
            severity="low",
            description="Test",
            target="target2",
        )

        high_findings = findings_manager.list_findings(severity=Severity.HIGH)

        assert len(high_findings) == 1
        assert high_findings[0].title == "High Finding"

    def test_list_findings_filter_by_target(self, findings_manager):
        """Test filtering findings by target."""
        findings_manager.create(
            title="Finding 1",
            severity="low",
            description="Test",
            target="192.168.1.100",
        )
        findings_manager.create(
            title="Finding 2",
            severity="low",
            description="Test",
            target="192.168.1.200",
        )

        filtered = findings_manager.list_findings(target="192.168.1.100")

        assert len(filtered) == 1
        assert filtered[0].target == "192.168.1.100"

    def test_list_findings_filter_by_tags(self, findings_manager):
        """Test filtering findings by tags."""
        f1 = findings_manager.create(
            title="Web Finding",
            severity="medium",
            description="Test",
            target="target1",
        )
        f1.tags = ["web", "owasp"]

        f2 = findings_manager.create(
            title="Network Finding",
            severity="medium",
            description="Test",
            target="target2",
        )
        f2.tags = ["network"]

        web_findings = findings_manager.list_findings(tags=["web"])

        assert len(web_findings) == 1
        assert web_findings[0].title == "Web Finding"

    def test_list_findings_sorted_by_severity(self, findings_manager):
        """Test findings are sorted by severity."""
        findings_manager.create(
            title="Low",
            severity="low",
            description="Test",
            target="target1",
        )
        findings_manager.create(
            title="Critical",
            severity="critical",
            description="Test",
            target="target2",
        )
        findings_manager.create(
            title="Medium",
            severity="medium",
            description="Test",
            target="target3",
        )

        findings = findings_manager.list_findings()

        assert findings[0].severity == Severity.CRITICAL
        assert findings[2].severity == Severity.LOW

    def test_get_statistics(self, findings_manager):
        """Test getting findings statistics."""
        f1 = findings_manager.create(
            title="Critical Finding",
            severity="critical",
            description="Test",
            target="192.168.1.1",
            cvss_score=9.8,
        )
        f1.add_evidence(title="Evidence", content="data")

        findings_manager.create(
            title="Medium Finding",
            severity="medium",
            description="Test",
            target="192.168.1.1",
        )

        stats = findings_manager.get_statistics()

        assert stats["total"] == 2
        assert stats["by_severity"]["critical"] == 1
        assert stats["by_severity"]["medium"] == 1
        assert stats["by_target"]["192.168.1.1"] == 2
        assert stats["with_evidence"] == 1
        assert stats["with_cvss"] == 1

    def test_add_evidence_to_finding(self, findings_manager):
        """Test adding evidence through manager."""
        finding = findings_manager.create(
            title="Test",
            severity="low",
            description="Test",
            target="test",
        )

        evidence = findings_manager.add_evidence(
            finding.id,
            title="PoC Screenshot",
            content="Screenshot data",
            evidence_type="screenshot",
        )

        assert evidence is not None
        assert len(finding.evidence) == 1

    def test_add_evidence_nonexistent_finding(self, findings_manager):
        """Test adding evidence to non-existent finding."""
        result = findings_manager.add_evidence(
            "nonexistent",
            title="Test",
            content="data",
        )
        assert result is None

    def test_transition_status(self, findings_manager):
        """Test transitioning finding status."""
        finding = findings_manager.create(
            title="Test",
            severity="high",
            description="Test",
            target="test",
        )

        result = findings_manager.transition_status(
            finding.id,
            FindingStatus.CONFIRMED,
            "Verified manually",
        )

        assert result is True
        assert finding.status == FindingStatus.CONFIRMED

    def test_transition_status_nonexistent(self, findings_manager):
        """Test transitioning status of non-existent finding."""
        result = findings_manager.transition_status(
            "nonexistent",
            FindingStatus.CONFIRMED,
        )
        assert result is False

    def test_export_json(self, findings_manager, tmp_path):
        """Test exporting findings to JSON."""
        findings_manager.create(
            title="Test Finding",
            severity="high",
            description="Test",
            target="test",
        )

        output_path = str(tmp_path / "export.json")
        findings_manager.export_json(output_path)

        assert Path(output_path).exists()
        with open(output_path) as f:
            data = json.load(f)
            assert len(data) == 1
            assert data[0]["title"] == "Test Finding"

    def test_import_json(self, findings_manager, tmp_path):
        """Test importing findings from JSON."""
        data = [
            {
                "id": "import1",
                "title": "Imported Finding",
                "severity": "high",
                "status": "draft",
                "description": "Imported",
                "target": "target",
            }
        ]

        input_path = str(tmp_path / "import.json")
        with open(input_path, 'w') as f:
            json.dump(data, f)

        imported = findings_manager.import_json(input_path)

        assert imported == 1
        assert "import1" in findings_manager.findings

    def test_import_json_no_duplicates(self, findings_manager, tmp_path):
        """Test importing doesn't overwrite existing findings."""
        existing = findings_manager.create(
            title="Existing",
            severity="low",
            description="Existing",
            target="target",
        )

        data = [
            {
                "id": existing.id,
                "title": "Should Not Overwrite",
                "severity": "high",
                "status": "draft",
                "description": "New",
                "target": "target",
            }
        ]

        input_path = str(tmp_path / "import.json")
        with open(input_path, 'w') as f:
            json.dump(data, f)

        imported = findings_manager.import_json(input_path)

        assert imported == 0
        assert findings_manager.findings[existing.id].title == "Existing"

    def test_persistence(self, tmp_path):
        """Test findings persist across manager instances."""
        storage_path = str(tmp_path / "findings")

        manager1 = FindingsManager(storage_path=storage_path)
        manager1.create(
            title="Persistent Finding",
            severity="high",
            description="Should persist",
            target="test",
        )

        manager2 = FindingsManager(storage_path=storage_path)

        assert len(manager2.findings) == 1
        finding = list(manager2.findings.values())[0]
        assert finding.title == "Persistent Finding"


# =============================================================================
# Duplicate Detection Tests
# =============================================================================

class TestDuplicateDetection:
    """Tests for duplicate finding detection."""

    @pytest.fixture
    def findings_manager(self, tmp_path):
        """Create a FindingsManager with temporary storage."""
        return FindingsManager(storage_path=str(tmp_path / "findings"))

    def test_exact_title_match(self, findings_manager):
        """Test exact title match is detected as duplicate."""
        f1 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="First",
            target="192.168.1.100",
        )

        f2 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="Second",
            target="192.168.1.100",
        )

        assert f1.id == f2.id

    def test_case_insensitive_match(self, findings_manager):
        """Test title matching is case insensitive."""
        f1 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="First",
            target="192.168.1.100",
        )

        f2 = findings_manager.create(
            title="sql injection",
            severity="high",
            description="Second",
            target="192.168.1.100",
        )

        assert f1.id == f2.id

    def test_different_targets_not_duplicate(self, findings_manager):
        """Test same title on different targets is not duplicate."""
        f1 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="First",
            target="192.168.1.100",
        )

        f2 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="Second",
            target="192.168.1.200",
        )

        assert f1.id != f2.id

    def test_false_positive_not_considered_duplicate(self, findings_manager):
        """Test false positives don't trigger duplicate detection."""
        f1 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="First",
            target="192.168.1.100",
        )
        f1.mark_false_positive("Not a real vulnerability")

        f2 = findings_manager.create(
            title="SQL Injection",
            severity="high",
            description="Real this time",
            target="192.168.1.100",
        )

        assert f1.id != f2.id

    def test_same_port_different_title_not_duplicate(self, findings_manager):
        """Test different titles on same port are not duplicates."""
        f1 = findings_manager.create(
            title="Remote Code Execution Vulnerability",
            severity="critical",
            description="First",
            target="192.168.1.100",
            port=443,
        )

        f2 = findings_manager.create(
            title="Remote Code Execution Attack",
            severity="critical",
            description="Second",
            target="192.168.1.100",
            port=443,
        )

        # Different titles are distinct findings even on same port
        assert f1.id != f2.id
