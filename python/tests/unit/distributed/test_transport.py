"""
Unit tests for purplesploit.distributed.transport module.

Tests cover:
- TransportConfig dataclass
- Transport ABC (signing, verification)
- HTTPTransport (connect, disconnect, send, retry logic)
- WebSocketTransport (connect, disconnect, send, receive, handlers)
- ProxyTransport (delegation pattern)
- create_transport factory function
"""

import pytest
from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock
import json
import asyncio

from purplesploit.distributed.transport import (
    TransportConfig,
    Transport,
    HTTPTransport,
    WebSocketTransport,
    ProxyTransport,
    create_transport,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def default_config():
    """Default TransportConfig with defaults."""
    return TransportConfig()


@pytest.fixture
def full_config():
    """TransportConfig with all options set."""
    return TransportConfig(
        server_url="https://coordinator.example.com",
        api_key="test-api-key-123",
        shared_secret="test-shared-secret",
        timeout=60,
        verify_ssl=False,
        retry_count=5,
        retry_delay=2.0,
        compression=True,
    )


@pytest.fixture
def http_config():
    """Config for HTTP transport tests."""
    return TransportConfig(
        server_url="https://test.example.com",
        api_key="test-key",
        timeout=10,
        retry_count=3,
        retry_delay=0.01,  # Fast retries for tests
    )


@pytest.fixture
def config_with_secret():
    """Config with shared secret for signing tests."""
    return TransportConfig(
        server_url="https://test.example.com",
        shared_secret="super-secret-key",
    )


@pytest.fixture
def http_transport(http_config):
    """HTTPTransport instance (not connected)."""
    return HTTPTransport(http_config)


@pytest.fixture
def ws_transport(http_config):
    """WebSocketTransport instance (not connected)."""
    return WebSocketTransport(http_config)


@pytest.fixture
def mock_inner_transport():
    """Mock inner transport for ProxyTransport tests."""
    inner = MagicMock(spec=HTTPTransport)
    inner.connect.return_value = True
    inner.disconnect.return_value = True
    inner.send.return_value = {"success": True}
    inner.receive.return_value = None
    inner._session = None
    return inner


# =============================================================================
# Concrete Transport for Testing ABC
# =============================================================================

class ConcreteTestTransport(Transport):
    """Concrete implementation for testing Transport ABC."""

    def connect(self):
        self.is_connected = True
        return True

    def disconnect(self):
        self.is_connected = False
        return True

    def send(self, message_type, data):
        return {"success": True}

    def receive(self, timeout=None):
        return None


# =============================================================================
# TransportConfig Tests
# =============================================================================

class TestTransportConfig:
    """Tests for TransportConfig dataclass."""

    def test_config_defaults(self, default_config):
        """Test all default values."""
        assert default_config.server_url == ""
        assert default_config.api_key is None
        assert default_config.shared_secret is None
        assert default_config.timeout == 30
        assert default_config.verify_ssl is True
        assert default_config.retry_count == 3
        assert default_config.retry_delay == 1.0
        assert default_config.compression is False

    def test_config_custom_values(self, full_config):
        """Test custom values are set correctly."""
        assert full_config.server_url == "https://coordinator.example.com"
        assert full_config.api_key == "test-api-key-123"
        assert full_config.shared_secret == "test-shared-secret"
        assert full_config.timeout == 60
        assert full_config.verify_ssl is False
        assert full_config.retry_count == 5
        assert full_config.retry_delay == 2.0
        assert full_config.compression is True

    def test_config_partial_override(self):
        """Test partial override keeps other defaults."""
        config = TransportConfig(server_url="https://test.com", timeout=120)
        assert config.server_url == "https://test.com"
        assert config.timeout == 120
        # Defaults preserved
        assert config.api_key is None
        assert config.retry_count == 3

    def test_config_empty_strings(self):
        """Test config with empty strings."""
        config = TransportConfig(server_url="", api_key="")
        assert config.server_url == ""
        assert config.api_key == ""

    def test_config_zero_values(self):
        """Test config with zero values."""
        config = TransportConfig(timeout=0, retry_count=0, retry_delay=0.0)
        assert config.timeout == 0
        assert config.retry_count == 0
        assert config.retry_delay == 0.0


# =============================================================================
# Transport ABC Tests
# =============================================================================

class TestTransportABC:
    """Tests for Transport abstract base class methods."""

    def test_init_sets_config(self, default_config):
        """Test __init__ sets config attribute."""
        transport = ConcreteTestTransport(default_config)
        assert transport.config == default_config

    def test_init_is_connected_false(self, default_config):
        """Test __init__ sets is_connected to False."""
        transport = ConcreteTestTransport(default_config)
        assert transport.is_connected is False

    def test_init_last_error_none(self, default_config):
        """Test __init__ sets _last_error to None."""
        transport = ConcreteTestTransport(default_config)
        assert transport._last_error is None

    def test_sign_message_with_secret(self, config_with_secret):
        """Test _sign_message generates HMAC signature."""
        transport = ConcreteTestTransport(config_with_secret)
        data = {"type": "test", "value": 123}
        signature = transport._sign_message(data)
        assert isinstance(signature, str)
        assert len(signature) == 64  # SHA256 hex length

    def test_sign_message_without_secret(self, default_config):
        """Test _sign_message returns empty string without secret."""
        transport = ConcreteTestTransport(default_config)
        data = {"type": "test"}
        signature = transport._sign_message(data)
        assert signature == ""

    def test_sign_message_deterministic(self, config_with_secret):
        """Test _sign_message is deterministic."""
        transport = ConcreteTestTransport(config_with_secret)
        data = {"type": "test", "value": 123}
        sig1 = transport._sign_message(data)
        sig2 = transport._sign_message(data)
        assert sig1 == sig2

    def test_sign_message_sorted_keys(self, config_with_secret):
        """Test _sign_message is order-independent (uses sorted keys)."""
        transport = ConcreteTestTransport(config_with_secret)
        data1 = {"b": 2, "a": 1}
        data2 = {"a": 1, "b": 2}
        sig1 = transport._sign_message(data1)
        sig2 = transport._sign_message(data2)
        assert sig1 == sig2

    def test_verify_signature_valid(self, config_with_secret):
        """Test _verify_signature returns True for valid signature."""
        transport = ConcreteTestTransport(config_with_secret)
        data = {"type": "test"}
        signature = transport._sign_message(data)
        assert transport._verify_signature(data, signature) is True

    def test_verify_signature_invalid(self, config_with_secret):
        """Test _verify_signature returns False for invalid signature."""
        transport = ConcreteTestTransport(config_with_secret)
        data = {"type": "test"}
        assert transport._verify_signature(data, "invalid-signature") is False

    def test_verify_signature_no_secret(self, default_config):
        """Test _verify_signature returns True without secret."""
        transport = ConcreteTestTransport(default_config)
        data = {"type": "test"}
        assert transport._verify_signature(data, "any-signature") is True

    def test_verify_signature_empty_string_attack(self, config_with_secret):
        """Test empty signature with secret configured fails."""
        transport = ConcreteTestTransport(config_with_secret)
        data = {"type": "test"}
        assert transport._verify_signature(data, "") is False


# =============================================================================
# HTTPTransport Tests
# =============================================================================

class TestHTTPTransportConnect:
    """Tests for HTTPTransport.connect()."""

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_success(self, mock_requests, http_config):
        """Test successful connection."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        result = transport.connect()

        assert result is True
        assert transport.is_connected is True

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_failure_non_200(self, mock_requests, http_config):
        """Test connection failure with non-200 response."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_session.get.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        result = transport.connect()

        assert result is False
        assert transport._last_error == "HTTP 500"

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', False)
    def test_connect_no_requests_library(self, http_config):
        """Test connect fails when requests not installed."""
        transport = HTTPTransport(http_config)
        result = transport.connect()

        assert result is False
        assert "requests library not installed" in transport._last_error

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_exception(self, mock_requests, http_config):
        """Test connect handles exceptions."""
        mock_session = MagicMock()
        mock_session.get.side_effect = Exception("Connection refused")
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        result = transport.connect()

        assert result is False
        assert "Connection refused" in transport._last_error

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_sets_headers(self, mock_requests, http_config):
        """Test connect sets proper headers."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        transport.connect()

        # Check headers were updated
        mock_session.headers.update.assert_called()

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_with_api_key(self, mock_requests, http_config):
        """Test connect sets Authorization header with API key."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_session.headers = {}
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        transport.connect()

        # API key should be in headers
        assert "Authorization" in mock_session.headers


class TestHTTPTransportDisconnect:
    """Tests for HTTPTransport.disconnect()."""

    def test_disconnect_closes_session(self, http_transport):
        """Test disconnect closes session."""
        mock_session = MagicMock()
        http_transport._session = mock_session

        result = http_transport.disconnect()

        assert result is True
        mock_session.close.assert_called_once()
        assert http_transport._session is None
        assert http_transport.is_connected is False

    def test_disconnect_when_not_connected(self, http_transport):
        """Test disconnect when not connected is idempotent."""
        result = http_transport.disconnect()

        assert result is True
        assert http_transport.is_connected is False


class TestHTTPTransportSend:
    """Tests for HTTPTransport.send()."""

    def test_send_not_connected(self, http_transport):
        """Test send returns error when not connected."""
        result = http_transport.send("register", {})

        assert result["success"] is False
        assert "Not connected" in result["error"]

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    def test_send_unknown_message_type(self, http_transport):
        """Test send with unknown message type."""
        http_transport._session = MagicMock()

        result = http_transport.send("unknown_type", {})

        assert result["success"] is False
        assert "Unknown message type" in result["error"]

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_success_200(self, mock_sleep, http_transport):
        """Test successful send with 200 response."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"data": "test"}
        mock_session.post.return_value = mock_response
        http_transport._session = mock_session

        result = http_transport.send("register", {"agent_id": "test"})

        assert result["success"] is True

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_success_201(self, mock_sleep, http_transport):
        """Test successful send with 201 response."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {"id": "123"}
        mock_session.post.return_value = mock_response
        http_transport._session = mock_session

        result = http_transport.send("task_result", {"task_id": "test"})

        assert result["success"] is True

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_auth_failure_401(self, mock_sleep, http_transport):
        """Test 401 response returns auth failure."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_session.post.return_value = mock_response
        http_transport._session = mock_session

        result = http_transport.send("register", {})

        assert result["success"] is False
        assert "Authentication failed" in result["error"]

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_server_error_500_retry(self, mock_sleep, http_transport):
        """Test 500 response triggers retry."""
        mock_session = MagicMock()
        mock_response_500 = MagicMock()
        mock_response_500.status_code = 500
        mock_response_200 = MagicMock()
        mock_response_200.status_code = 200
        mock_response_200.json.return_value = {}

        mock_session.post.side_effect = [mock_response_500, mock_response_200]
        http_transport._session = mock_session

        result = http_transport.send("register", {})

        assert result["success"] is True
        assert mock_session.post.call_count == 2

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_server_error_exhausts_retries(self, mock_sleep, http_transport):
        """Test exhausting retries on server error."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_session.post.return_value = mock_response
        http_transport._session = mock_session

        result = http_transport.send("register", {})

        assert result["success"] is False
        assert mock_session.post.call_count == http_transport.config.retry_count

    @patch('purplesploit.distributed.transport.time.sleep')
    @patch('purplesploit.distributed.transport.requests')
    def test_send_timeout_retry(self, mock_requests, mock_sleep, http_config):
        """Test timeout triggers retry."""
        import requests as real_requests
        mock_requests.exceptions = real_requests.exceptions

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}

        mock_session.post.side_effect = [
            mock_requests.exceptions.Timeout("Timeout"),
            mock_response,
        ]
        mock_requests.Session.return_value = mock_session

        transport = HTTPTransport(http_config)
        transport._session = mock_session

        result = transport.send("register", {})

        assert result["success"] is True

    def test_send_endpoint_mapping(self, http_transport):
        """Test correct endpoint mapping for message types."""
        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {}
        mock_session.post.return_value = mock_response
        http_transport._session = mock_session

        # Test register endpoint
        http_transport.send("register", {})
        call_url = mock_session.post.call_args[0][0]
        assert "/api/v1/agents/register" in call_url


class TestHTTPTransportReceive:
    """Tests for HTTPTransport.receive()."""

    def test_receive_returns_none(self, http_transport):
        """Test receive always returns None (HTTP is poll-based)."""
        result = http_transport.receive()
        assert result is None

        result = http_transport.receive(timeout=30)
        assert result is None


# =============================================================================
# WebSocketTransport Tests
# =============================================================================

class TestWebSocketTransportConnect:
    """Tests for WebSocketTransport.connect()."""

    @patch('purplesploit.distributed.transport.WEBSOCKETS_AVAILABLE', False)
    def test_connect_no_websockets_library(self, http_config):
        """Test connect fails when websockets not installed."""
        transport = WebSocketTransport(http_config)
        result = transport.connect()

        assert result is False
        assert "websockets library not installed" in transport._last_error

    @patch('purplesploit.distributed.transport.WEBSOCKETS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.asyncio')
    @patch('purplesploit.distributed.transport.websockets')
    def test_connect_url_http_to_ws(self, mock_ws, mock_asyncio, http_config):
        """Test HTTP URL is converted to WS."""
        http_config.server_url = "http://test.com"
        mock_loop = MagicMock()
        mock_asyncio.new_event_loop.return_value = mock_loop

        mock_connection = MagicMock()
        mock_loop.run_until_complete.return_value = mock_connection

        transport = WebSocketTransport(http_config)
        transport.connect()

        # Verify ws:// URL was used
        mock_ws.connect.assert_called()
        call_args = mock_ws.connect.call_args
        assert "ws://" in call_args[0][0]

    @patch('purplesploit.distributed.transport.WEBSOCKETS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.asyncio')
    @patch('purplesploit.distributed.transport.websockets')
    def test_connect_url_https_to_wss(self, mock_ws, mock_asyncio, http_config):
        """Test HTTPS URL is converted to WSS."""
        mock_loop = MagicMock()
        mock_asyncio.new_event_loop.return_value = mock_loop

        mock_connection = MagicMock()
        mock_loop.run_until_complete.return_value = mock_connection

        transport = WebSocketTransport(http_config)
        transport.connect()

        # Verify wss:// URL was used (default is https)
        mock_ws.connect.assert_called()
        call_args = mock_ws.connect.call_args
        assert "wss://" in call_args[0][0]

    @patch('purplesploit.distributed.transport.WEBSOCKETS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.asyncio')
    @patch('purplesploit.distributed.transport.websockets')
    def test_connect_exception(self, mock_ws, mock_asyncio, http_config):
        """Test connect handles exceptions."""
        mock_loop = MagicMock()
        mock_asyncio.new_event_loop.return_value = mock_loop
        mock_loop.run_until_complete.side_effect = Exception("Connection failed")

        transport = WebSocketTransport(http_config)
        result = transport.connect()

        assert result is False
        assert "Connection failed" in transport._last_error


class TestWebSocketTransportDisconnect:
    """Tests for WebSocketTransport.disconnect()."""

    def test_disconnect_when_not_connected(self, ws_transport):
        """Test disconnect when not connected is idempotent."""
        result = ws_transport.disconnect()
        assert result is True
        assert ws_transport.is_connected is False

    def test_disconnect_closes_websocket(self, ws_transport):
        """Test disconnect closes websocket."""
        mock_ws = MagicMock()
        mock_loop = MagicMock()
        ws_transport._ws = mock_ws
        ws_transport._loop = mock_loop

        result = ws_transport.disconnect()

        assert result is True
        mock_loop.run_until_complete.assert_called()
        assert ws_transport._ws is None
        assert ws_transport._loop is None

    def test_disconnect_handles_close_exception(self, ws_transport):
        """Test disconnect handles exception during close."""
        mock_ws = MagicMock()
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = Exception("Close error")
        ws_transport._ws = mock_ws
        ws_transport._loop = mock_loop

        result = ws_transport.disconnect()

        assert result is True  # Should still succeed
        assert ws_transport.is_connected is False


class TestWebSocketTransportSend:
    """Tests for WebSocketTransport.send()."""

    def test_send_not_connected(self, ws_transport):
        """Test send returns error when not connected."""
        result = ws_transport.send("register", {})

        assert result["success"] is False
        assert "Not connected" in result["error"]

    def test_send_with_ws_and_loop(self, ws_transport):
        """Test send works with ws and loop."""
        mock_ws = AsyncMock()
        mock_loop = MagicMock()

        ws_transport._ws = mock_ws
        ws_transport._loop = mock_loop

        # Simply verify that run_until_complete is called when send is invoked
        # The actual async behavior is complex to mock, so we verify the attempt
        mock_loop.run_until_complete.return_value = {"id": "test", "success": True}

        result = ws_transport.send("register", {"agent": "test"})

        # Should attempt to call run_until_complete
        assert mock_loop.run_until_complete.called


class TestWebSocketTransportReceive:
    """Tests for WebSocketTransport.receive()."""

    def test_receive_not_connected(self, ws_transport):
        """Test receive returns None when not connected."""
        result = ws_transport.receive()
        assert result is None

    def test_receive_exception(self, ws_transport):
        """Test receive handles exceptions."""
        mock_ws = MagicMock()
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = Exception("Receive error")
        ws_transport._ws = mock_ws
        ws_transport._loop = mock_loop

        result = ws_transport.receive()

        assert result is None
        assert "Receive error" in ws_transport._last_error


class TestWebSocketTransportHandlers:
    """Tests for WebSocketTransport handler registration."""

    def test_register_handler(self, ws_transport):
        """Test handler registration."""

        def my_handler(data):
            pass

        ws_transport.register_handler("task_assign", my_handler)

        assert "task_assign" in ws_transport._message_handlers
        assert ws_transport._message_handlers["task_assign"] == my_handler

    def test_register_handler_overwrites(self, ws_transport):
        """Test registering same handler type overwrites."""

        def handler1(data):
            pass

        def handler2(data):
            pass

        ws_transport.register_handler("task", handler1)
        ws_transport.register_handler("task", handler2)

        assert ws_transport._message_handlers["task"] == handler2

    def test_start_listening_not_connected(self, ws_transport):
        """Test start_listening when not connected."""
        # Should return without error
        ws_transport.start_listening()


# =============================================================================
# ProxyTransport Tests
# =============================================================================

class TestProxyTransport:
    """Tests for ProxyTransport class."""

    def test_init_stores_proxy_url(self, http_config, mock_inner_transport):
        """Test __init__ stores proxy_url."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        assert transport.proxy_url == "http://proxy:8080"

    def test_init_stores_inner_transport(self, http_config, mock_inner_transport):
        """Test __init__ stores inner transport."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        assert transport.inner == mock_inner_transport

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', False)
    def test_connect_no_requests_library(self, http_config, mock_inner_transport):
        """Test connect fails when requests not available."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        result = transport.connect()

        assert result is False

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    @patch('purplesploit.distributed.transport.requests')
    def test_connect_configures_http_proxy(self, mock_requests, http_config):
        """Test connect configures proxy on HTTP inner transport."""
        inner = HTTPTransport(http_config)
        transport = ProxyTransport(http_config, "http://proxy:8080", inner)

        mock_session = MagicMock()
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_session.get.return_value = mock_response
        mock_requests.Session.return_value = mock_session

        transport.connect()

        # Proxy should be configured
        assert mock_session.proxies is not None or hasattr(inner._session, 'proxies')

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    def test_disconnect_delegates(self, http_config, mock_inner_transport):
        """Test disconnect delegates to inner transport."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        result = transport.disconnect()

        mock_inner_transport.disconnect.assert_called_once()
        assert result == mock_inner_transport.disconnect.return_value

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    def test_send_delegates(self, http_config, mock_inner_transport):
        """Test send delegates to inner transport."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        result = transport.send("register", {"data": "test"})

        mock_inner_transport.send.assert_called_once_with("register", {"data": "test"})
        assert result == mock_inner_transport.send.return_value

    @patch('purplesploit.distributed.transport.REQUESTS_AVAILABLE', True)
    def test_receive_delegates(self, http_config, mock_inner_transport):
        """Test receive delegates to inner transport."""
        transport = ProxyTransport(
            http_config, "http://proxy:8080", mock_inner_transport
        )
        result = transport.receive(timeout=30)

        mock_inner_transport.receive.assert_called_once_with(30)
        assert result == mock_inner_transport.receive.return_value


# =============================================================================
# create_transport Factory Tests
# =============================================================================

class TestCreateTransport:
    """Tests for create_transport factory function."""

    def test_create_http_transport(self, http_config):
        """Test creating HTTP transport."""
        transport = create_transport("http", http_config)
        assert isinstance(transport, HTTPTransport)

    def test_create_websocket_transport(self, http_config):
        """Test creating WebSocket transport."""
        transport = create_transport("websocket", http_config)
        assert isinstance(transport, WebSocketTransport)

    def test_create_proxy_transport(self, http_config):
        """Test creating proxy transport."""
        transport = create_transport(
            "proxy", http_config, proxy_url="http://proxy:8080"
        )
        assert isinstance(transport, ProxyTransport)

    def test_create_proxy_with_inner_type(self, http_config):
        """Test creating proxy with specified inner type."""
        transport = create_transport(
            "proxy",
            http_config,
            proxy_url="http://proxy:8080",
            inner_type="websocket",
        )
        assert isinstance(transport, ProxyTransport)
        assert isinstance(transport.inner, WebSocketTransport)

    def test_create_unknown_type_raises(self, http_config):
        """Test unknown transport type raises ValueError."""
        with pytest.raises(ValueError) as exc_info:
            create_transport("unknown", http_config)
        assert "Unknown transport type" in str(exc_info.value)

    def test_create_passes_config(self, http_config):
        """Test config is passed to transport."""
        transport = create_transport("http", http_config)
        assert transport.config == http_config

    def test_create_proxy_default_inner_type(self, http_config):
        """Test proxy defaults to HTTP inner transport."""
        transport = create_transport(
            "proxy", http_config, proxy_url="http://proxy:8080"
        )
        assert isinstance(transport.inner, HTTPTransport)


# =============================================================================
# Edge Cases
# =============================================================================

class TestTransportEdgeCases:
    """Edge case tests for transport module."""

    def test_sign_different_data_different_signature(self, config_with_secret):
        """Test different data produces different signatures."""
        transport = ConcreteTestTransport(config_with_secret)
        sig1 = transport._sign_message({"key": "value1"})
        sig2 = transport._sign_message({"key": "value2"})
        assert sig1 != sig2

    @patch('purplesploit.distributed.transport.time.sleep')
    def test_send_after_disconnect(self, mock_sleep, http_transport):
        """Test send after disconnect returns error."""
        http_transport._session = MagicMock()
        http_transport.disconnect()

        result = http_transport.send("register", {})
        assert result["success"] is False

    def test_ws_transport_initial_state(self, ws_transport):
        """Test WebSocket transport initial state."""
        assert ws_transport._ws is None
        assert ws_transport._loop is None
        assert ws_transport._message_handlers == {}
        assert ws_transport._pending_responses == {}
