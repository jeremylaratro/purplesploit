"""
Transport Layer for Distributed PurpleSploit

Handles communication between agents and coordinator.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, Any, Optional, Callable, List
from datetime import datetime
import json
import logging
import asyncio
import ssl
import hashlib
import hmac
import time

logger = logging.getLogger(__name__)

# Optional imports
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False


@dataclass
class TransportConfig:
    """Base transport configuration."""
    server_url: str = ""
    api_key: Optional[str] = None
    shared_secret: Optional[str] = None
    timeout: int = 30
    verify_ssl: bool = True
    retry_count: int = 3
    retry_delay: float = 1.0
    compression: bool = False


class Transport(ABC):
    """
    Abstract base class for transport implementations.

    Transports handle:
    - Agent registration
    - Heartbeat/keepalive
    - Task assignment
    - Result submission
    - Findings synchronization
    """

    def __init__(self, config: TransportConfig):
        self.config = config
        self.is_connected = False
        self._last_error: Optional[str] = None

    @abstractmethod
    def connect(self) -> bool:
        """Establish connection to coordinator."""
        pass

    @abstractmethod
    def disconnect(self) -> bool:
        """Close connection."""
        pass

    @abstractmethod
    def send(self, message_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send a message and receive response."""
        pass

    @abstractmethod
    def receive(self, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Receive a message (for push-based transports)."""
        pass

    def _sign_message(self, data: Dict[str, Any]) -> str:
        """Sign a message with shared secret."""
        if not self.config.shared_secret:
            return ""
        message = json.dumps(data, sort_keys=True)
        signature = hmac.new(
            self.config.shared_secret.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature

    def _verify_signature(self, data: Dict[str, Any], signature: str) -> bool:
        """Verify message signature."""
        if not self.config.shared_secret:
            return True
        expected = self._sign_message(data)
        return hmac.compare_digest(expected, signature)


class HTTPTransport(Transport):
    """
    HTTP/REST-based transport.

    Uses polling for task assignment and HTTP requests for all communication.
    Suitable for environments where WebSocket connections are blocked.
    """

    def __init__(self, config: TransportConfig):
        super().__init__(config)
        self._session = None

    def connect(self) -> bool:
        """Establish HTTP session."""
        if not REQUESTS_AVAILABLE:
            self._last_error = "requests library not installed"
            return False

        try:
            self._session = requests.Session()
            self._session.headers.update({
                "Content-Type": "application/json",
                "User-Agent": "PurpleSploit-Agent/1.0",
            })

            if self.config.api_key:
                self._session.headers["Authorization"] = f"Bearer {self.config.api_key}"

            # Test connection
            response = self._session.get(
                f"{self.config.server_url}/api/v1/health",
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
            )

            if response.status_code == 200:
                self.is_connected = True
                return True
            else:
                self._last_error = f"HTTP {response.status_code}"
                return False

        except Exception as e:
            self._last_error = str(e)
            return False

    def disconnect(self) -> bool:
        """Close HTTP session."""
        if self._session:
            self._session.close()
            self._session = None
        self.is_connected = False
        return True

    def send(self, message_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send HTTP request."""
        if not self._session:
            return {"success": False, "error": "Not connected"}

        endpoint_map = {
            "register": "/api/v1/agents/register",
            "heartbeat": "/api/v1/agents/heartbeat",
            "task_request": "/api/v1/tasks/request",
            "task_result": "/api/v1/tasks/result",
            "findings_sync": "/api/v1/findings/sync",
        }

        endpoint = endpoint_map.get(message_type)
        if not endpoint:
            return {"success": False, "error": f"Unknown message type: {message_type}"}

        try:
            # Add signature
            payload = {
                "type": message_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data,
            }
            if self.config.shared_secret:
                payload["signature"] = self._sign_message(payload)

            for attempt in range(self.config.retry_count):
                try:
                    response = self._session.post(
                        f"{self.config.server_url}{endpoint}",
                        json=payload,
                        timeout=self.config.timeout,
                        verify=self.config.verify_ssl,
                    )

                    if response.status_code in (200, 201):
                        return {"success": True, **response.json()}
                    elif response.status_code == 401:
                        return {"success": False, "error": "Authentication failed"}
                    elif response.status_code >= 500:
                        if attempt < self.config.retry_count - 1:
                            time.sleep(self.config.retry_delay * (attempt + 1))
                            continue
                    return {"success": False, "error": f"HTTP {response.status_code}"}

                except requests.exceptions.Timeout:
                    if attempt < self.config.retry_count - 1:
                        time.sleep(self.config.retry_delay)
                        continue
                    return {"success": False, "error": "Request timeout"}

        except Exception as e:
            return {"success": False, "error": str(e)}

        return {"success": False, "error": "Max retries exceeded"}

    def receive(self, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Poll for messages (HTTP doesn't support push)."""
        return None  # HTTP uses polling via send()


class WebSocketTransport(Transport):
    """
    WebSocket-based transport.

    Provides real-time bidirectional communication.
    Preferred for low-latency task distribution.
    """

    def __init__(self, config: TransportConfig):
        super().__init__(config)
        self._ws = None
        self._loop = None
        self._message_handlers: Dict[str, Callable] = {}
        self._pending_responses: Dict[str, asyncio.Future] = {}

    def connect(self) -> bool:
        """Establish WebSocket connection."""
        if not WEBSOCKETS_AVAILABLE:
            self._last_error = "websockets library not installed"
            return False

        try:
            self._loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self._loop)

            # Convert HTTP URL to WebSocket URL
            ws_url = self.config.server_url.replace("http://", "ws://").replace("https://", "wss://")
            ws_url = f"{ws_url}/ws/agent"

            ssl_context = None
            if ws_url.startswith("wss://"):
                ssl_context = ssl.create_default_context()
                if not self.config.verify_ssl:
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE

            extra_headers = {}
            if self.config.api_key:
                extra_headers["Authorization"] = f"Bearer {self.config.api_key}"

            self._ws = self._loop.run_until_complete(
                websockets.connect(
                    ws_url,
                    ssl=ssl_context,
                    extra_headers=extra_headers,
                    ping_interval=30,
                    ping_timeout=10,
                )
            )

            self.is_connected = True
            return True

        except Exception as e:
            self._last_error = str(e)
            return False

    def disconnect(self) -> bool:
        """Close WebSocket connection."""
        if self._ws:
            try:
                self._loop.run_until_complete(self._ws.close())
            except Exception:
                pass
            self._ws = None

        if self._loop:
            self._loop.close()
            self._loop = None

        self.is_connected = False
        return True

    def send(self, message_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Send WebSocket message and wait for response."""
        if not self._ws or not self._loop:
            return {"success": False, "error": "Not connected"}

        try:
            import uuid
            message_id = str(uuid.uuid4())[:8]

            payload = {
                "id": message_id,
                "type": message_type,
                "timestamp": datetime.utcnow().isoformat(),
                "data": data,
            }
            if self.config.shared_secret:
                payload["signature"] = self._sign_message(payload)

            async def send_and_receive():
                await self._ws.send(json.dumps(payload))

                # Wait for response with matching ID
                while True:
                    response = await asyncio.wait_for(
                        self._ws.recv(),
                        timeout=self.config.timeout
                    )
                    response_data = json.loads(response)

                    if response_data.get("id") == message_id:
                        return response_data

            response = self._loop.run_until_complete(send_and_receive())
            return {"success": True, **response}

        except asyncio.TimeoutError:
            return {"success": False, "error": "Response timeout"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    def receive(self, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Receive a pushed message."""
        if not self._ws or not self._loop:
            return None

        try:
            async def receive_message():
                return await asyncio.wait_for(
                    self._ws.recv(),
                    timeout=timeout or self.config.timeout
                )

            message = self._loop.run_until_complete(receive_message())
            return json.loads(message)

        except asyncio.TimeoutError:
            return None
        except Exception as e:
            self._last_error = str(e)
            return None

    def register_handler(self, message_type: str, handler: Callable) -> None:
        """Register a handler for incoming message types."""
        self._message_handlers[message_type] = handler

    def start_listening(self) -> None:
        """Start listening for incoming messages (blocking)."""
        if not self._ws or not self._loop:
            return

        async def listen():
            try:
                async for message in self._ws:
                    data = json.loads(message)
                    msg_type = data.get("type")
                    if msg_type and msg_type in self._message_handlers:
                        self._message_handlers[msg_type](data)
            except Exception as e:
                logger.error(f"WebSocket listener error: {e}")

        self._loop.run_until_complete(listen())


class ProxyTransport(Transport):
    """
    Proxy-aware transport for tunneled networks.

    Wraps another transport and routes through SOCKS/HTTP proxy.
    """

    def __init__(self, config: TransportConfig, proxy_url: str, inner_transport: Transport):
        super().__init__(config)
        self.proxy_url = proxy_url
        self.inner = inner_transport

    def connect(self) -> bool:
        """Connect through proxy."""
        if not REQUESTS_AVAILABLE:
            self._last_error = "requests library not installed"
            return False

        # Configure proxy for inner transport
        if isinstance(self.inner, HTTPTransport):
            self.inner._session = requests.Session()
            self.inner._session.proxies = {
                "http": self.proxy_url,
                "https": self.proxy_url,
            }

        return self.inner.connect()

    def disconnect(self) -> bool:
        return self.inner.disconnect()

    def send(self, message_type: str, data: Dict[str, Any]) -> Dict[str, Any]:
        return self.inner.send(message_type, data)

    def receive(self, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        return self.inner.receive(timeout)


def create_transport(
    transport_type: str,
    config: TransportConfig,
    **kwargs,
) -> Transport:
    """
    Factory function to create transport instances.

    Args:
        transport_type: Type of transport (http, websocket, proxy)
        config: Transport configuration
        **kwargs: Additional arguments for specific transports

    Returns:
        Transport instance
    """
    if transport_type == "http":
        return HTTPTransport(config)
    elif transport_type == "websocket":
        return WebSocketTransport(config)
    elif transport_type == "proxy":
        proxy_url = kwargs.get("proxy_url", "")
        inner_type = kwargs.get("inner_type", "http")
        inner = create_transport(inner_type, config)
        return ProxyTransport(config, proxy_url, inner)
    else:
        raise ValueError(f"Unknown transport type: {transport_type}")
