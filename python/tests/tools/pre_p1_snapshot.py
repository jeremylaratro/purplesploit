"""Deterministic PLAN-002 Step-0 importer corpus support.

The cases in this module are deliberately explicit.  Registry coverage is
checked against the live registry so adding an importer cannot silently omit it
from the pre-P1 identity corpus.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from hashlib import sha256
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterator


BASE_SHA = "cc491ae"
GENERATOR = "python/scripts/generate_pre_p1_snapshot.py"
PYTHON_ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ROOT = PYTHON_ROOT / "tests" / "fixtures"
DEFAULT_OUTPUT = FIXTURE_ROOT / "interop" / "pre-p1"


@dataclass(frozen=True)
class ImportCase:
    """One importer invocation over one committed fixture."""

    name: str
    importer: str
    fixture: str
    run: Callable[[], tuple[list[Any], list[Any]]]
    neutralize_observed_at: bool = False


def _fixture(relative: str) -> Path:
    return FIXTURE_ROOT / relative


def _fixture_source(relative: str) -> Path:
    """Return a stable path while callers are running from ``python/``."""
    return Path("tests") / "fixtures" / relative


@contextmanager
def _from_python_root() -> Iterator[None]:
    previous = Path.cwd()
    os.chdir(PYTHON_ROOT)
    try:
        yield
    finally:
        os.chdir(previous)


def _registry(relative: str, format_name: str, **options: Any) -> tuple[list[Any], list[Any]]:
    from purplesploit.interop.importers import REGISTRY

    with _from_python_root():
        result = REGISTRY.parse(_fixture_source(relative), format=format_name, **options)
    return result.observations, result.findings


def _nmap(relative: str) -> tuple[list[Any], list[Any]]:
    from purplesploit.modules.recon.nmap_importer import parse_nmap_xml

    with _from_python_root():
        result = parse_nmap_xml(_fixture_source(relative))
    return result["observations"], []


def _identity(function_name: str, relative: str) -> tuple[list[Any], list[Any]]:
    from purplesploit.interop import identity

    function = getattr(identity, function_name)
    path = _fixture(relative)
    document: Any
    if path.suffix == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
    else:
        document = path.read_text(encoding="utf-8")
    result = function(document, source=f"tests/fixtures/{relative}")
    return result.observations, []


def _canonical(function_name: str, relative: str) -> tuple[list[Any], list[Any]]:
    from purplesploit.interop import canonical

    path = _fixture(relative)
    if function_name == "CanonicalDocument.from_json":
        document = canonical.CanonicalDocument.from_json(path.read_text(encoding="utf-8"))
    else:
        function = getattr(canonical, function_name)
        document = function(json.loads(path.read_text(encoding="utf-8"))).document
    assert document is not None
    data = document.to_dict()
    return data["observations"], data["findings"]


def importer_cases() -> list[ImportCase]:
    """Return every central-fixture importer invocation available at the base."""
    registry_cases = [
        ("registry-nmap-canonical", "nmap-xml", "canonical/nmap.xml", {}),
        ("registry-nmap-cwp2", "nmap-xml", "nmap/cwp2.xml", {}),
        ("registry-nuclei", "nuclei-jsonl", "canonical/nuclei.jsonl", {}),
        (
            "registry-netexec",
            "netexec-log",
            "nxc/smb_modern.txt",
            {"arguments": ["--shares"]},
        ),
        (
            "registry-bloodhound",
            "bloodhound-json",
            "canonical/bloodhound_subset.json",
            {},
        ),
        ("registry-aranum-network", "aranum-bundle", "aranum/network", {}),
        ("registry-aranum-posture", "aranum-bundle", "aranum/posture", {}),
        ("registry-aranum-partial", "aranum-bundle", "aranum/partial", {}),
        ("registry-aws", "aws-json", "cloud/aws.json", {}),
        ("registry-azure", "azure-json", "cloud/azure.json", {}),
        ("registry-gcp", "gcp-json", "cloud/gcp.json", {}),
        ("registry-entra", "entra-json", "cloud/entra.json", {}),
        ("registry-kubernetes", "kubernetes-json", "containers/kubernetes.json", {}),
        ("registry-docker", "docker-json", "containers/docker.json", {}),
        # The provider-neutral container parser accepts the Docker fixture for
        # its Podman wrapper.  There is no producer-specific Podman fixture yet.
        ("registry-podman", "podman-json", "containers/docker.json", {}),
        ("registry-crictl", "crictl-json", "containers/crictl.json", {}),
        ("registry-trivy", "trivy-json", "containers/trivy.json", {}),
        ("registry-grype", "grype-json", "containers/grype.json", {}),
    ]
    cases = [
        ImportCase(
            name,
            f"interop.importers:{format_name}",
            fixture,
            lambda fixture=fixture, format_name=format_name, options=options: _registry(
                fixture, format_name, **options
            ),
        )
        for name, format_name, fixture, options in registry_cases
    ]
    for name, fixture in (
        ("nmap-parser-canonical", "canonical/nmap.xml"),
        ("nmap-parser-cwp2", "nmap/cwp2.xml"),
    ):
        cases.append(
            ImportCase(
                name,
                "modules.recon.nmap_importer:parse_nmap_xml",
                fixture,
                lambda fixture=fixture: _nmap(fixture),
                neutralize_observed_at=True,
            )
        )
    for function_name, fixture, suffix in (
        ("import_oidc_discovery", "identity/oidc.json", "oidc"),
        ("import_oauth_metadata", "identity/oidc.json", "oauth-metadata"),
        ("import_oauth_client", "identity/oauth_client.json", "oauth-client"),
        ("import_jwks", "identity/jwks.json", "jwks"),
        ("import_saml_metadata", "identity/metadata.xml", "saml-metadata"),
        ("import_saml_assertion", "identity/assertion.xml", "saml-assertion"),
        (
            "import_saml_assertion",
            "identity/encrypted_assertion.xml",
            "saml-encrypted-assertion",
        ),
    ):
        cases.append(
            ImportCase(
                f"identity-{suffix}",
                f"interop.identity:{function_name}",
                fixture,
                lambda function_name=function_name, fixture=fixture: _identity(
                    function_name, fixture
                ),
            )
        )
    for function_name, fixture, suffix in (
        ("CanonicalDocument.from_json", "canonical/golden.json", "canonical-json"),
        ("import_sarif", "canonical/tier1.sarif.json", "sarif"),
        ("import_defectdojo", "canonical/defectdojo-generic.json", "defectdojo"),
    ):
        cases.append(
            ImportCase(
                f"canonical-{suffix}",
                f"interop.canonical:{function_name}",
                fixture,
                lambda function_name=function_name, fixture=fixture: _canonical(
                    function_name, fixture
                ),
            )
        )
    return sorted(cases, key=lambda case: case.name)


def registry_fixture_gaps() -> dict[str, str]:
    """Fail if a live registry entry is absent from the central fixture corpus."""
    from purplesploit.interop.importers import REGISTRY

    covered = {
        case.importer.rsplit(":", 1)[-1]
        for case in importer_cases()
        if case.importer.startswith("interop.importers:")
    }
    missing = set(REGISTRY.importers) - covered
    if missing:
        raise AssertionError(
            f"Update the Step-0 corpus for registry change: missing={sorted(missing)}, "
            "expected=[]"
        )
    return {}


def _plain(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        value = value.to_dict()
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (date, datetime)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    if isinstance(value, set):
        return sorted((_plain(item) for item in value), key=_sort_key)
    return value


def _normalize_paths(value: Any) -> Any:
    if isinstance(value, str):
        return value.replace(str(PYTHON_ROOT.resolve()), "<PYTHON_ROOT>")
    if isinstance(value, dict):
        return {key: _normalize_paths(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_normalize_paths(item) for item in value]
    return value


def _sort_key(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def run_case(case: ImportCase) -> dict[str, Any]:
    """Run and canonicalize one case without changing identity-bearing fields."""
    observations, findings = case.run()
    observation_values = [_plain(item) for item in observations]
    if case.neutralize_observed_at:
        for item in observation_values:
            # Observation identity at this base excludes observed_at.  The
            # dedicated Nmap parser otherwise supplies utc_now() here.
            item["observed_at"] = None
    observation_values = [_normalize_paths(item) for item in observation_values]
    finding_values = [_normalize_paths(_plain(item)) for item in findings]
    observation_values.sort(
        key=lambda item: (str(item.get("observation_id", "")), _sort_key(item))
    )
    finding_values.sort(key=lambda item: (str(item.get("id", "")), _sort_key(item)))
    return {
        "fixture": f"python/tests/fixtures/{case.fixture}",
        "importer": case.importer,
        "normalizations": (
            ["observed_at=null (wall clock; excluded from observation identity)"]
            if case.neutralize_observed_at
            else []
        ),
        "observations": observation_values,
        "findings": finding_values,
    }


def render_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2, allow_nan=False) + "\n"
    ).encode("utf-8")


def generate_snapshot(output: Path = DEFAULT_OUTPUT) -> dict[str, Any]:
    """Write the corpus and return its digest manifest."""
    output.mkdir(parents=True, exist_ok=True)
    cases = importer_cases()
    expected_names = {f"{case.name}.json" for case in cases}
    for stale in output.glob("*.json"):
        if stale.name != "MANIFEST.json" and stale.name not in expected_names:
            stale.unlink()
    files = []
    for case in cases:
        payload = run_case(case)
        content = render_json(payload)
        path = output / f"{case.name}.json"
        path.write_bytes(content)
        files.append(
            {
                "path": path.name,
                "sha256": sha256(content).hexdigest(),
                "importer": case.importer,
                "record_count": len(payload["observations"]) + len(payload["findings"]),
            }
        )
    manifest = {
        "base_sha": BASE_SHA,
        "generator": GENERATOR,
        "files": files,
        "normalizations": [
            "absolute Python-root prefixes in non-identity path values become <PYTHON_ROOT>",
            "dedicated Nmap parser observed_at is null because its default is wall clock and is "
            "excluded from observation identity",
        ],
        "uncovered_importers": registry_fixture_gaps(),
    }
    (output / "MANIFEST.json").write_bytes(render_json(manifest))
    return manifest


def load_snapshot(output: Path = DEFAULT_OUTPUT) -> dict[str, dict[str, Any]]:
    manifest = json.loads((output / "MANIFEST.json").read_text(encoding="utf-8"))
    return {
        entry["path"]: json.loads((output / entry["path"]).read_text(encoding="utf-8"))
        for entry in manifest["files"]
    }
