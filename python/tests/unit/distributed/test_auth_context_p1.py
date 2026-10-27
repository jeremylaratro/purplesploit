"""P1 auth-context carry checks for distributed agent early outcomes."""

from purplesploit.core.execution import AuthContext, ExecutionOutcome, ExecutionRequest
from purplesploit.distributed.agent import Agent


def test_agent_exception_result_copies_request_auth_context():
    context = AuthContext(
        account_ref="account-1", scope="machine", domain="example.test",
        auth_method="hash",
    )
    request = ExecutionRequest("fixture", auth_context=context)

    def fail(_request):
        raise RuntimeError("fixture failure")

    result = Agent(None, fail)._execute({"request": request.to_dict()})

    assert result.outcome is ExecutionOutcome.ERROR
    assert result.auth_context == context


def test_agent_cancelled_result_copies_request_auth_context():
    context = AuthContext(account_ref="account-2", scope="local", local_host="host-a")
    request = ExecutionRequest("fixture", auth_context=context)
    agent = Agent(None, lambda _request: None)
    agent._cancel.set()

    result = agent._execute({"request": request.to_dict()})

    assert result.outcome is ExecutionOutcome.CANCELLED
    assert result.auth_context == context
