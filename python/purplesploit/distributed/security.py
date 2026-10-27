"""Pre-provisioned agent message authentication and replay control."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
from threading import RLock
import time


class AgentMessageAuthenticator:
    """Authenticate signed envelopes independently from transport bearer auth."""

    def __init__(self, agents: dict[str, dict], *, max_skew_seconds=60, clock=time.time):
        self.agents = dict(agents)
        self.max_skew_seconds = max_skew_seconds
        self.clock = clock
        self._seen: dict[tuple[str, str], float] = {}
        self._lock = RLock()

    @staticmethod
    def signature(secret: str, envelope: dict) -> str:
        value = {key: item for key, item in envelope.items() if key != "signature"}
        encoded = json.dumps(value, sort_keys=True).encode()
        return hmac.new(secret.encode(), encoded, hashlib.sha256).hexdigest()

    def verify(self, envelope: dict, message_type: str) -> str:
        if not isinstance(envelope, dict) or not isinstance(envelope.get("data"), dict):
            raise PermissionError("Signed agent envelope is required")
        data = envelope["data"]
        agent_id = str(data.get("agent_id", ""))
        record = self.agents.get(agent_id)
        if not record:
            raise PermissionError("Agent identity is not provisioned")
        message_id = str(envelope.get("id", ""))
        if not message_id:
            raise PermissionError("Agent message id is required")
        try:
            timestamp = datetime.fromisoformat(str(envelope["timestamp"]).replace("Z", "+00:00"))
            if timestamp.tzinfo is None:
                timestamp = timestamp.replace(tzinfo=timezone.utc)
            event_time = timestamp.timestamp()
        except (KeyError, TypeError, ValueError) as exc:
            raise PermissionError("Agent timestamp is invalid") from exc
        now = self.clock()
        if abs(now - event_time) > self.max_skew_seconds:
            raise PermissionError("Agent message is outside the accepted time window")
        expected = self.signature(str(record["secret"]), envelope)
        if not hmac.compare_digest(str(envelope.get("signature", "")), expected):
            raise PermissionError("Agent message signature is invalid")
        with self._lock:
            self._seen = {key: expiry for key, expiry in self._seen.items() if expiry > now}
            replay_key = (agent_id, message_id)
            if replay_key in self._seen:
                raise PermissionError("Agent message replay detected")
            self._seen[replay_key] = now + self.max_skew_seconds * 2
        if message_type == "register":
            allowed = set(record.get("capabilities", []))
            requested = set(data.get("capabilities", []))
            if not requested.issubset(allowed):
                raise PermissionError("Agent requested an unprovisioned capability")
        return agent_id
