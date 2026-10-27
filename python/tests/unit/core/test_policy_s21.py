from datetime import datetime, timedelta, timezone

import pytest

from purplesploit.core.execution import ExecutionRequest
from purplesploit.core.policy import (
    ActionRisk,
    Approval,
    EngagementAuthorization,
    PolicyEngine,
    PolicyViolation,
    ScopeContract,
    SprayBudget,
    SprayBudgetLedger,
)
from purplesploit.core.store import CanonicalStore

from .test_store_s19 import engagement


def contract(now=None, **changes):
    now = now or datetime.now(timezone.utc)
    values = {
        "engagement_id": "eng-1",
        "authorized_by": "client@example.test",
        "authorization_reference": "SOW-2026-001",
        "starts_at": (now - timedelta(hours=1)).isoformat(),
        "ends_at": (now + timedelta(hours=1)).isoformat(),
        "scope": ScopeContract(
            include=["192.0.2.0/24", "*.example.test", "https://api.example.test/v1"],
            exclude=["192.0.2.99", "admin.example.test"],
            allowed_ports=[22, 80, 443, 445],
            allow_redirects=True,
            max_redirects=2,
        ),
        "allowed_risks": ["passive", "low", "medium"],
        "rate_per_minute": 2,
        "max_concurrency": 1,
    }
    values.update(changes)
    return EngagementAuthorization(**values)


def request(target="192.0.2.10", **changes):
    values = {
        "module_path": "recon/nmap",
        "operation_name": "Fast Scan",
        "options": {"RHOST": target},
        "engagement_id": "eng-1",
    }
    values.update(changes)
    return ExecutionRequest(**values)


def test_scope_exclusions_ports_redirects_and_resolved_addresses():
    engine = PolicyEngine()
    engine.register(contract())
    assert engine.explain(request())["allowed"]
    assert engine.explain(request("https://www.example.test:443/path"))["allowed"]
    assert not engine.explain(request("192.0.2.99"))["allowed"]
    assert not engine.explain(request("https://admin.example.test:443"))["allowed"]
    assert not engine.explain(request("https://www.example.test:8443"))["allowed"]
    redirected = request(
        "https://api.example.test:443/v1/users",
        redirect_chain=["https://api.example.test:443/v1/login"],
    )
    assert engine.explain(redirected)["allowed"]
    assert not engine.explain(request(
        redirect_chain=["https://outside.invalid", "https://api.example.test/v1"]
    ))["allowed"]
    assert not engine.explain(request(resolved_targets=["203.0.113.9"]))["allowed"]


def test_risk_requires_exact_scoped_approval():
    now = datetime.now(timezone.utc)
    high = request(
        module_path="impacket/psexec",
        operation_name="Execute Command",
        action_risk=ActionRisk.CRITICAL.value,
        side_effects=["remote command execution"],
    )
    engine = PolicyEngine()
    engine.register(contract(now))
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(high)
    assert error.value.code == "approval_required"
    approval = Approval(
        "APR-1", ["critical"], "lead@example.test",
        (now + timedelta(minutes=10)).isoformat(),
        module_patterns=["impacket/psexec"], target_patterns=["192.0.2.*"],
    )
    engine.register(contract(now, approvals=[approval]))
    high.approval_id = approval.id
    decision = engine.authorize(high)
    assert decision["allowed"] and decision["risk"] == "critical"
    engine.release(high.engagement_id, decision["reservation"])


def test_missing_engagement_window_rate_and_concurrency_fail_closed():
    now = datetime.now(timezone.utc)
    engine = PolicyEngine(clock=lambda: now)
    engine.register(contract(now))
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(request(engagement_id=None))
    assert error.value.code == "missing_engagement"
    decision = engine.authorize(request())
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(request("192.0.2.11"))
    assert error.value.code == "concurrency_budget"
    engine.release("eng-1", decision["reservation"])
    second = engine.authorize(request("192.0.2.11"))
    engine.release("eng-1", second["reservation"])
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(request("192.0.2.12"))
    assert error.value.code == "rate_budget"

    expired = PolicyEngine(clock=lambda: now)
    expired.register(contract(now, ends_at=(now - timedelta(seconds=1)).isoformat()))
    with pytest.raises(PolicyViolation) as error:
        expired.authorize(request())
    assert error.value.code == "outside_authorized_window"


def test_proxy_and_target_count_containment():
    engine = PolicyEngine()
    engine.register(contract(scope=ScopeContract(include=["192.0.2.0/24"], max_child_targets=1)))
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(request(proxy="socks5://127.0.0.1:1080"))
    assert error.value.code == "proxy_not_allowed"
    with pytest.raises(PolicyViolation) as error:
        engine.authorize(request(targets=["192.0.2.10", "192.0.2.11"]))
    assert error.value.code == "target_budget"


def test_cross_run_spray_budget_and_uncertainty_are_persistent(tmp_path):
    store = CanonicalStore(tmp_path / "canonical.db")
    store.put_engagement("eng-1", engagement())
    ledger = SprayBudgetLedger(
        store, SprayBudget(per_principal=2, per_domain=4, per_run=3, window_minutes=30)
    )
    reservations = ledger.reserve(
        engagement_id="eng-1", domain="EXAMPLE", attempts=[
            ("alice", "192.0.2.10"), ("bob", "192.0.2.10"),
        ]
    )
    ledger.record(reservations[0], "invalid_credential")
    ledger.record(reservations[1], "ambiguous")
    restarted = SprayBudgetLedger(
        store, SprayBudget(per_principal=2, per_domain=4, per_run=3, window_minutes=30)
    )
    usage = restarted.usage("eng-1", "EXAMPLE")
    assert usage == {
        "engagement_id": "eng-1", "domain": "EXAMPLE", "total": 2,
        "principals": {"alice": 1, "bob": 1}, "uncertain": 1,
    }
    restarted.reserve(
        engagement_id="eng-1", domain="EXAMPLE", attempts=[("alice", "192.0.2.11")]
    )
    with pytest.raises(PolicyViolation) as error:
        restarted.reserve(
            engagement_id="eng-1", domain="EXAMPLE", attempts=[("alice", "192.0.2.12")]
        )
    assert error.value.code == "spray_principal_budget"


def test_policy_disabled_is_explicit_not_implicitly_permissive():
    engine = PolicyEngine.disabled()
    result = engine.explain(ExecutionRequest(module_path="fixture", targets=["anything"]))
    assert result["allowed"] and result["decision"] == "policy_disabled"
