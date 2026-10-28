"""Unit coverage for PLAN-002 P6 credential-reuse orchestration."""

from types import SimpleNamespace
from unittest.mock import Mock

from purplesploit.core.credential_spray import LockoutPolicy
from purplesploit.core.reuse_campaign import (
    ARANUM_MODULE_PATH,
    CellExec,
    LockoutAccountant,
    ReuseCampaign,
)
from purplesploit.core.session import Session


def _raw(test, outcome):
    return {
        "host": test.host,
        "transport": test.transport,
        "outcome": outcome,
        "auth_context": {"account_ref": test.account_ref, "scope": test.scope},
    }


def test_build_matrix_is_exact_stable_and_stamps_declared_scope():
    corpus = [{"account_ref": "first"}, {"account_ref": "second"}]
    local = ReuseCampaign(
        corpus=corpus,
        hosts=["host-b", "host-a"],
        transports=["winrm", "exec"],
        scope="local",
        handoff=Mock(),
    )

    matrix = local.build_matrix()

    assert len(matrix) == 2 * 2 * 2
    assert [(item.host, item.account_ref, item.transport) for item in matrix] == [
        (host, account, transport)
        for host in ("host-a", "host-b")
        for account in ("first", "second")
        for transport in ("winrm", "exec")
    ]
    assert all(item.scope == "local" for item in matrix)
    assert all(item.domain is None and item.local_host == item.host for item in matrix)
    assert [item.aranum_owned for item in matrix[:2]] == [True, False]

    domain = ReuseCampaign(
        corpus=corpus[:1],
        hosts=["host-b", "host-a"],
        transports=["winrm"],
        scope="domain",
        domain="CORP.LOCAL",
        handoff=Mock(),
    ).build_matrix()
    assert all(item.scope == "domain" for item in domain)
    assert all(item.domain == "CORP.LOCAL" and item.local_host is None for item in domain)

    exact_duplicates = ReuseCampaign(
        corpus=[{"account_ref": "first"}, {"account_ref": "first"}],
        hosts=["host-a", "host-a"],
        transports=["winrm", "winrm"],
        scope="local",
        handoff=Mock(),
    ).build_matrix()
    assert len(exact_duplicates) == 1


def test_from_session_reads_credential_manager_corpus():
    session = Session()
    session.credentials.add({"username": "alice", "scope": "domain", "domain": "CORP"})

    campaign = ReuseCampaign.from_session(
        session,
        hosts=["host-a"],
        transports=["winrm"],
        scope="domain",
        domain="CORP",
        handoff=Mock(),
    )

    assert campaign.build_matrix()[0].account_ref == session.credentials.credentials[0]["account_ref"]


def test_lockout_accountant_is_count_based_and_deterministic():
    accountant = LockoutAccountant(LockoutPolicy(threshold=3))

    assert accountant.can_test("account") == (True, "")
    accountant.record("account", "success")
    assert accountant.failures.get("account", 0) == 0
    accountant.record("account", "failure")
    assert accountant.can_test("account") == (True, "")
    accountant.record("account", "failure")
    assert accountant.can_test("account") == (False, "near-threshold")

    accountant.record("locked-account", "lockout")
    assert accountant.can_test("locked-account") == (False, "locked")
    assert accountant.locked == {"locked-account"}


def test_run_routes_only_non_skipped_cells_in_matrix_order():
    seam = Mock(side_effect=[CellExec("failure"), CellExec("failure")])
    campaign = ReuseCampaign(
        corpus=[{"account_ref": "account"}],
        hosts=["host-c", "host-a", "host-b"],
        transports=["winrm"],
        scope="local",
        lockout_policy=LockoutPolicy(threshold=3),
        handoff=seam,
    )

    result = campaign.run()

    assert [call.args[0] for call in seam.call_args_list] == campaign.build_matrix()[:2]
    assert seam.call_count == 2
    assert [item.outcome for item in result.outcomes] == ["failure", "failure", "skipped"]
    assert result.outcomes[-1].reason == "skipped: account near-threshold"
    assert result.summary["tested"] == 2
    assert result.summary["skipped"] == 1


def test_observed_lockout_halts_remaining_cells():
    seam = Mock(return_value=CellExec("lockout", {"outcome": "lockout"}))
    campaign = ReuseCampaign(
        corpus=[{"account_ref": "account"}],
        hosts=["host-a", "host-b", "host-c"],
        transports=["exec"],
        scope="local",
        lockout_policy=LockoutPolicy(threshold=5),
        handoff=seam,
    )

    result = campaign.run()

    seam.assert_called_once_with(campaign.build_matrix()[0])
    assert [item.outcome for item in result.outcomes] == ["lockout", "skipped", "skipped"]
    assert all("locked" in item.reason for item in result.outcomes[1:])
    assert result.summary["tested"] == 1
    assert result.summary["skipped"] == 2
    assert result.summary["locked"] == 1


def test_collected_fx5_shaped_outcomes_feed_p4_derivation():
    outcomes = {
        "10.0.0.1": "success",
        "10.0.0.2": "success",
        "10.0.0.3": "lockout",
    }

    def seam(test):
        outcome = outcomes[test.host]
        return CellExec(outcome, _raw(test, outcome))

    result = ReuseCampaign(
        corpus=[{"account_ref": "svc-local"}],
        hosts=list(reversed(outcomes)),
        transports=["exec"],
        scope="local",
        lockout_policy=LockoutPolicy(threshold=5),
        handoff=seam,
    ).run()

    reuse = [item for item in result.findings if "credential-reuse" in item.tags]
    lockout = [item for item in result.findings if "lockout" in item.tags]
    assert len(reuse) == len(lockout) == 1
    assert reuse[0].metadata["account_ref"] == "svc-local"
    assert set(reuse[0].metadata["hosts"]) == {"10.0.0.1", "10.0.0.2"}
    assert lockout[0].target == "10.0.0.3"
    assert [item.target for item in result.bundle.observations] == list(outcomes)
    assert all(item.auth_context.scope == "local" for item in result.bundle.observations)


def test_empty_auth_outcome_is_forgiving_and_produces_no_observation():
    result = ReuseCampaign(
        corpus=[{"account_ref": "account"}],
        hosts=["host-a"],
        transports=["winrm"],
        scope="domain",
        domain="CORP.LOCAL",
        handoff=lambda test: CellExec("success", None),
    ).run()

    assert result.summary["tested"] == result.summary["success"] == 1
    assert result.bundle.observations == []
    assert result.findings == []


def test_default_handoff_resolves_recon_aranum_and_routes_exact_test():
    execute = Mock(return_value={"outcome": "success", "auth_outcome": {"ok": True}})
    module = SimpleNamespace(execute_credential_test=execute)
    framework = SimpleNamespace(instantiate_module=Mock(return_value=module))
    campaign = ReuseCampaign(
        corpus=[{"account_ref": "account"}],
        hosts=["host-a"],
        transports=["winrm"],
        scope="domain",
        domain="CORP.LOCAL",
        framework=framework,
    )

    result = campaign.run()

    framework.instantiate_module.assert_called_once_with(ARANUM_MODULE_PATH)
    execute.assert_called_once_with(campaign.build_matrix()[0])
    assert result.summary["success"] == 1
