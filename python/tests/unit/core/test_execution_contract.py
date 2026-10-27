"""Technical execution contracts exercised through real discovered modules."""

import json
import subprocess

import pytest

from purplesploit.core.execution import (
    ExecutionOutcome, ExecutionRequest, ExecutionResult, Observation,
    normalize_observations, normalize_operation,
)
from purplesploit.core.framework import Framework


@pytest.fixture
def framework(tmp_path):
    instance = Framework(db_path=str(tmp_path / 'execution.db'))
    instance.discover_modules()
    yield instance
    instance.cleanup()


def test_contract_json_round_trip_preserves_identity():
    request = ExecutionRequest('network/nxc_rdp', options={'hash': None}, options_locked={'hash'})
    restored = ExecutionRequest.from_dict(json.loads(json.dumps(request.to_dict())))
    assert restored == request
    observation = Observation('service', '192.0.2.9', port=443, protocol='tcp', source_execution_id=request.request_id)
    result = ExecutionResult(request.request_id, observations=[observation])
    assert ExecutionResult.from_dict(json.loads(json.dumps(result.to_dict()))) == result
    assert Observation.from_dict(observation.to_dict()).observation_id == observation.observation_id


def test_instantiate_preserves_selection_history_and_isolates_options(framework):
    selected = framework.use_module('network/nxc_rdp')
    history = list(framework.session.module_history)
    first = framework.instantiate_module('network/nxc_rdp')
    second = framework.instantiate_module('network/nxc_rdp')
    first.set_option('RHOST', '192.0.2.8')
    assert first is not second and second.get_option('RHOST') is None
    assert framework.session.current_module is selected
    assert framework.session.module_history == history


def test_resolver_normalizes_manifest_without_changing_legacy_operations(framework):
    module = framework.instantiate_module('network/nxc_rdp')
    original_operations = module.get_operations()
    operation = framework.find_operation(module, 'test-auth')
    assert operation == framework.find_operation(module, 'Test Authentication')
    assert operation['handler'] == 'op_test_auth'
    assert framework.find_operation(module, 'Authentication') is None
    assert {'id', 'name', 'handler', 'interactive', 'background', 'requires', 'optional', 'emits', 'tool'} <= operation.keys()
    assert module.get_operations() == original_operations
    assert normalize_operation({'name': 'Renamed', 'handler': 'op_test_auth'})['id'] == 'test-auth'


def test_request_options_override_context_and_reach_real_process(framework, tmp_path, monkeypatch):
    selected = framework.use_module('network/nxc_rdp')
    framework.session.credentials.add({'username': 'context', 'hash': 'context-hash', 'password': 'context-password'})
    calls = []

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, '[+] authenticated', '')

    monkeypatch.setattr(subprocess, 'run', fake_run)
    request = ExecutionRequest(
        'network/nxc_rdp', 'test-auth',
        options={'RHOST': '192.0.2.11', 'USERNAME': 'fixture-user', 'PASSWORD': 'fixture-password', 'HASH': None},
        timeout_s=7, run_dir=str(tmp_path / 'run'), env={'CWP1_TEST': 'enabled'},
    )
    result = framework.execute_request(request)
    argv, kwargs = calls[0]
    assert '-H' not in argv
    assert argv[argv.index('-p') + 1] == 'fixture-password'
    assert kwargs['timeout'] == 7 and kwargs['stdin'] == subprocess.DEVNULL
    assert kwargs['cwd'] == str(tmp_path / 'run') and kwargs['env']['CWP1_TEST'] == 'enabled'
    assert result.success and result.exit_code == 0 and result.outcome is ExecutionOutcome.SUCCESS
    assert result.request_id == request.request_id
    assert result.stdout_ref and result.stderr_ref
    assert framework.session.current_module is selected
    assert json.loads(framework.database.get_module_history()[0]['results'])['execution']['request_id'] == request.request_id
    assert framework.session.module_history[-1]['execution']['request_id'] == request.request_id


@pytest.mark.parametrize('failure, outcome', [(3, ExecutionOutcome.FAILED), ('timeout', ExecutionOutcome.TIMED_OUT)])
def test_process_failure_is_truthful(framework, monkeypatch, failure, outcome):
    def fake_run(argv, **kwargs):
        if failure == 'timeout':
            raise subprocess.TimeoutExpired(argv, kwargs['timeout'], output='partial')
        return subprocess.CompletedProcess(argv, failure, '', 'failed')

    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = framework.execute_request(ExecutionRequest('network/nxc_rdp', 'test-auth', options={'RHOST': '192.0.2.1'}, timeout_s=1))
    assert result.outcome is outcome and not result.success
    assert result.timed_out == (failure == 'timeout')
    assert len(framework.database.get_module_history()) == 1


@pytest.mark.parametrize('options, operation, expected', [({}, 'test-auth', 'RHOST'), ({'BOGUS': 1}, 'test-auth', 'Unknown option'), ({'RHOST': '192.0.2.1'}, 'missing', 'Operation not found')])
def test_validation_failure_records_without_process(framework, monkeypatch, options, operation, expected):
    def forbidden(*args, **kwargs):
        pytest.fail('validation failure reached process')

    monkeypatch.setattr(subprocess, 'run', forbidden)
    result = framework.execute_request(ExecutionRequest('network/nxc_rdp', operation, options=options))
    assert not result.success and expected in result.error
    assert len(framework.database.get_module_history()) == 1


def test_observation_legacy_bridge_retains_endpoint_and_provenance():
    request = ExecutionRequest('recon/nmap', 'fast', options={'RHOST': '192.0.2.0/24'})
    legacy = {'parsed': {'hosts': [{'ip': '192.0.2.3', 'ports': [{'port': 53, 'protocol': 'udp', 'service': 'domain'}]}]}}
    observations = normalize_observations(legacy, request)
    assert [item.kind for item in observations] == ['host', 'service']
    service = observations[1]
    assert (service.target, service.port, service.protocol) == ('192.0.2.3', 53, 'udp')
    assert service.source_execution_id == request.request_id and service.module_path == 'recon/nmap'
    assert normalize_observations(legacy, request)[1].observation_id == service.observation_id


def test_list_argv_preserves_argument_boundaries(framework, monkeypatch):
    module = framework.instantiate_module('network/nxc_rdp')
    calls = []

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, '', '')

    monkeypatch.setattr(subprocess, 'run', fake_run)
    result = module.execute_command(['fixture-tool', 'value with spaces', '$(literal)'])
    assert calls == [['fixture-tool', 'value with spaces', '$(literal)']]
    assert result['execution']['exit_code'] == 0


def test_background_start_is_pending(framework, monkeypatch):
    class Process:
        pid = 1234

        def poll(self):
            return None

        def wait(self, timeout=None):
            return 0

    monkeypatch.setattr(subprocess, 'Popen', lambda *args, **kwargs: Process())
    result = framework.execute_request(ExecutionRequest('network/nxc_rdp', 'test-auth', options={'RHOST': '192.0.2.1'}, background=True))
    assert result.outcome is ExecutionOutcome.RUNNING and not result.success
    assert result.finished_at is None and result.pid == 1234
    assert result.handle.status().outcome is ExecutionOutcome.RUNNING
    assert result.handle.wait().success
    assert 'handle' not in result.to_dict()


def test_interactive_legacy_handler_is_manifested_and_rejected(framework, monkeypatch):
    module = framework.instantiate_module('network/nxc_rdp')
    assert framework.find_operation(module, 'Pass-the-Hash')['interactive'] is True
    result = framework.execute_request(ExecutionRequest('network/nxc_rdp', 'Pass-the-Hash', options={'RHOST': '192.0.2.1'}))
    assert not result.success and 'interactive' in result.error
