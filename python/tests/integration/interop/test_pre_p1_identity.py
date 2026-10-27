"""AC-19 baseline: every persisted pre-P1 observation keeps its identity."""

from hashlib import sha256
import json

import pytest

from tests.tools.pre_p1_snapshot import (
    BASE_SHA,
    DEFAULT_OUTPUT,
    importer_cases,
    registry_fixture_gaps,
    run_case,
)


def _manifest():
    return json.loads((DEFAULT_OUTPUT / "MANIFEST.json").read_text(encoding="utf-8"))


def test_pre_p1_manifest_is_complete_and_digest_verified():
    manifest = _manifest()
    cases = importer_cases()
    assert manifest["base_sha"] == BASE_SHA
    assert [entry["path"] for entry in manifest["files"]] == [
        f"{case.name}.json" for case in cases
    ]
    assert manifest["uncovered_importers"] == registry_fixture_gaps()
    for entry in manifest["files"]:
        content = (DEFAULT_OUTPUT / entry["path"]).read_bytes()
        assert sha256(content).hexdigest() == entry["sha256"]
        payload = json.loads(content)
        assert entry["record_count"] == len(payload["observations"]) + len(
            payload["findings"]
        )


@pytest.mark.parametrize("case", importer_cases(), ids=lambda case: case.name)
def test_pre_p1_observation_ids_are_stable(case):
    snapshot_path = DEFAULT_OUTPUT / f"{case.name}.json"
    snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))
    current = run_case(case)
    expected_ids = {item["observation_id"] for item in snapshot["observations"]}
    current_ids = {item["observation_id"] for item in current["observations"]}
    assert len(expected_ids) == len(snapshot["observations"])
    assert len(current_ids) == len(current["observations"])
    assert current_ids == expected_ids
