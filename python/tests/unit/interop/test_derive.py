"""Pure account and posture derivation from imported Aranum observations."""

from pathlib import Path

from purplesploit.core.attack_graph import AttackGraph, EdgeType
from purplesploit.core.execution import AuthContext, Observation
from purplesploit.interop.aranum import AranumBundle, import_aranum_bundle
from purplesploit.interop.derive import derive_from_bundle


FIXTURES = Path(__file__).resolve().parents[2] / "fixtures" / "interop" / "aranum"


def _bundle(*observations, kb=None):
    return AranumBundle(
        run_root=Path("fixture"),
        bundle_fingerprint="fixture",
        run_id="fixture",
        status="complete",
        observations=list(observations),
        kb=kb or {},
    )


def _auth(host, outcome, account_ref="shared", scope="local", domain=None, transport="exec"):
    return Observation(
        kind="identity",
        target=host,
        attributes={
            "record_type": "auth_outcome",
            "outcome": outcome,
            "transport": transport,
        },
        auth_context=AuthContext(
            account_ref=account_ref,
            scope=scope,
            domain=domain,
            local_host=host if scope == "local" else None,
            auth_method="password",
        ),
        source_execution_id="fixture",
    )


def _posture(host, check_id, status="WARN"):
    return Observation(
        kind="policy",
        target=host,
        attributes={
            "record_type": "posture_check",
            "check_id": check_id,
            "scope": "host",
            "status": status,
            "observed_from": None,
        },
        source_execution_id="fixture",
    )


def test_derivation_is_deterministic_and_graph_idempotent():
    bundle = _bundle(
        _auth("host-b", "success"),
        _auth("host-a", "success"),
        _auth("host-c", "lockout"),
    )
    graph = AttackGraph()
    first = derive_from_bundle(bundle, graph)
    first_ids = [item.id for item in first.findings]
    first_edges = set(graph.edges)
    second = derive_from_bundle(bundle, graph)

    assert [item.id for item in second.findings] == first_ids
    assert set(graph.edges) == first_edges
    assert len(graph.edges) == len(first_edges)
    assert [path.id for path in second.lateral_paths] == [path.id for path in first.lateral_paths]


def test_reuse_groups_only_local_successes_by_account_ref():
    one_host = derive_from_bundle(_bundle(_auth("host-a", "success")))
    assert one_host.summary["reuse"] == 0

    result = derive_from_bundle(_bundle(
        _auth("host-a", "success"),
        _auth("host-b", "success"),
        _auth("host-c", "lockout"),
        _auth("host-d", "failure"),
    ))
    reuse = [item for item in result.findings if "credential-reuse" in item.tags]
    assert len(reuse) == 1
    assert reuse[0].metadata["hosts"] == ["host-a", "host-b"]
    assert "host-c" not in reuse[0].description
    assert "host-d" not in reuse[0].description


def test_local_and_domain_successes_route_to_distinct_finding_kinds():
    result = derive_from_bundle(_bundle(
        _auth("local-a", "success", account_ref="local-ref"),
        _auth("local-b", "success", account_ref="local-ref"),
        _auth(
            "domain-host",
            "success",
            account_ref="domain-ref",
            scope="domain",
            domain="EXAMPLE.TEST",
            transport="winrm",
        ),
    ))
    local = next(item for item in result.findings if item.metadata["account_ref"] == "local-ref")
    domain = next(item for item in result.findings if item.metadata["account_ref"] == "domain-ref")
    assert "credential-reuse" in local.tags and "effective-access" not in local.tags
    assert "effective-access" in domain.tags and "credential-reuse" not in domain.tags
    assert domain.target == "domain-host"


def test_posture_kb_hit_and_miss_have_remediation_and_validation():
    kb = {
        "digest": "fixture-kb",
        "checks": {
            "LIN-HIT": {
                "title": "Fixture check",
                "why": "Fixture impact",
                "fix": [{"label": "Harden", "text": "Apply the fixture setting."}],
                "test": [{"label": "Validate", "cmd": "fixture-check --verify"}],
                "refs": ["https://example.test/reference"],
                "attack_ids": ["T0000"],
            },
        },
    }
    result = derive_from_bundle(_bundle(
        _posture("linux-a", "LIN-HIT"),
        _posture("linux-b", "LIN-MISS", status="FAIL"),
        kb=kb,
    ))
    posture = {item.metadata["check_id"]: item for item in result.findings if "posture" in item.tags}

    assert "Apply the fixture setting." in posture["LIN-HIT"].remediation
    assert "fixture-check --verify" in posture["LIN-HIT"].metadata["validation"]
    assert posture["LIN-HIT"].metadata["kb_hit"] is True
    assert "Harden per posture check LIN-MISS" in posture["LIN-MISS"].remediation
    assert "confirm status PASS" in posture["LIN-MISS"].metadata["validation"]
    assert posture["LIN-MISS"].metadata["kb_hit"] is False
    assert all(item.remediation and item.metadata["validation"] for item in posture.values())


def test_importer_exposes_run_pinned_kb_and_defaults_to_empty():
    with_kb = import_aranum_bundle(FIXTURES / "fx-2")
    without_kb = import_aranum_bundle(FIXTURES / "fx-1")

    assert with_kb.kb.get("digest")
    assert isinstance(with_kb.kb.get("checks"), dict)
    assert "LIN-ACCT-NOPASSWD" in with_kb.kb["checks"]
    assert without_kb.kb == {}


def test_lockout_does_not_create_authentication_edge():
    result = derive_from_bundle(_bundle(
        _auth("success-host", "success"),
        _auth("locked-host", "lockout"),
    ))
    targets = {
        result.graph.nodes[edge.target_id].label
        for edge in result.graph.edges.values()
        if edge.edge_type == EdgeType.AUTHENTICATES_TO
    }
    assert targets == {"success-host"}
    assert result.summary["lockout"] == 1
