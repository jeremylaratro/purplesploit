"""Shared HTTP/WebSocket authentication, CSRF, rate, and audit controls."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
from threading import RLock
import time
from typing import Any

from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse

from purplesploit.core.secrets import SecretRedactor


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


@dataclass
class SecurityConfig:
    enabled: bool = True
    session_ttl_seconds: int = 900
    rotation_grace_seconds: int = 60
    rate_requests: int = 120
    rate_window_seconds: int = 60
    cookie_name: str = "purplesploit_session"
    secure_cookies: bool = True
    allowed_origins: tuple[str, ...] = (
        "http://localhost",
        "http://127.0.0.1",
    )

    def __post_init__(self):
        if (
            min(
                self.session_ttl_seconds,
                self.rotation_grace_seconds,
                self.rate_requests,
                self.rate_window_seconds,
            )
            <= 0
        ):
            raise ValueError("Security TTL and rate limits must be positive")


class SecurityAuditLog:
    def __init__(self, path: str | Path, redactor=None):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.redactor = redactor or SecretRedactor()
        self._lock = RLock()

    def record(self, event: str, **details) -> None:
        value = self.redactor.redact(
            {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event": event,
                **details,
            }
        )
        encoded = json.dumps(value, sort_keys=True, ensure_ascii=False) + "\n"
        with self._lock:
            descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
            with os.fdopen(descriptor, "a", encoding="utf-8") as stream:
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self.path.chmod(0o600)


class TokenAuthority:
    """Hash API tokens at rest and sign bounded browser/agent sessions."""

    def __init__(self, api_token: str, *, signing_key: bytes | None = None, clock=time.time):
        if not isinstance(api_token, str) or len(api_token) < 16:
            raise ValueError("API token must contain at least 16 characters")
        self.clock = clock
        self._tokens = {self._hash(api_token): None}
        self._signing_key = signing_key or secrets.token_bytes(32)
        self._lock = RLock()

    @staticmethod
    def _hash(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()

    def authenticate_api_token(self, token: str | None) -> bool:
        if not token:
            return False
        digest = self._hash(token)
        now = self.clock()
        with self._lock:
            expiry = self._tokens.get(digest, "missing")
            if expiry == "missing":
                return False
            if expiry is not None and expiry <= now:
                self._tokens.pop(digest, None)
                return False
            return True

    def rotate(self, current: str, new: str, *, grace_seconds: int) -> None:
        if not self.authenticate_api_token(current):
            raise PermissionError("Current token is invalid")
        if len(new) < 16:
            raise ValueError("New token must contain at least 16 characters")
        now = self.clock()
        with self._lock:
            for digest, expiry in list(self._tokens.items()):
                if expiry is None:
                    self._tokens[digest] = now + grace_seconds
            self._tokens[self._hash(new)] = None

    def issue_session(self, subject: str, ttl_seconds: int, *, kind="browser") -> dict[str, str]:
        now = int(self.clock())
        payload = {
            "sub": subject,
            "kind": kind,
            "iat": now,
            "exp": now + ttl_seconds,
            "jti": secrets.token_urlsafe(16),
            "csrf": secrets.token_urlsafe(24),
        }
        body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self._signing_key, body.encode(), hashlib.sha256).digest())
        return {
            "token": body + "." + signature,
            "csrf": payload["csrf"],
            "expires_at": str(payload["exp"]),
        }

    def verify_session(
        self, token: str | None, *, kind: str | None = None
    ) -> dict[str, Any] | None:
        if not token or token.count(".") != 1:
            return None
        body, signature = token.split(".", 1)
        expected = _b64(hmac.new(self._signing_key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(signature, expected):
            return None
        try:
            payload = json.loads(_unb64(body))
        except (ValueError, json.JSONDecodeError):
            return None
        if payload.get("exp", 0) <= self.clock() or (kind and payload.get("kind") != kind):
            return None
        return payload


class SlidingWindowRateLimiter:
    def __init__(self, count: int, window: int, *, clock=time.monotonic):
        self.count, self.window, self.clock = count, window, clock
        self._events: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = RLock()

    def allow(self, identity: str) -> bool:
        now = self.clock()
        with self._lock:
            values = self._events[identity]
            while values and values[0] <= now - self.window:
                values.popleft()
            if len(values) >= self.count:
                return False
            values.append(now)
            return True


class ApplicationSecurity:
    def __init__(
        self,
        config: SecurityConfig,
        authority: TokenAuthority,
        *,
        audit: SecurityAuditLog,
        limiter=None,
    ):
        self.config = config
        self.authority = authority
        self.audit = audit
        self.limiter = limiter or SlidingWindowRateLimiter(
            config.rate_requests, config.rate_window_seconds
        )

    @staticmethod
    def bearer(headers) -> str | None:
        value = headers.get("authorization", "")
        return value[7:].strip() if value.lower().startswith("bearer ") else None

    def identity(self, request: Request) -> tuple[str, dict[str, Any] | None, str]:
        token = self.bearer(request.headers)
        if self.authority.authenticate_api_token(token):
            return "api-token", None, "bearer"
        session = self.authority.verify_session(
            request.cookies.get(self.config.cookie_name), kind="browser"
        )
        if session:
            return str(session["sub"]), session, "cookie"
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})

    async def middleware(self, request: Request, call_next):
        if not self.config.enabled:
            return await call_next(request)
        public = request.url.path in {
            "/health",
            "/healthz",
            "/readyz",
            "/api/v1/health",
            "/api/v1/auth/session",
        }
        try:
            if public and request.url.path != "/api/v1/auth/session":
                identity, session, mode = "public", None, "public"
            else:
                identity, session, mode = self.identity(request)
            key = f"{identity}:{request.client.host if request.client else 'unknown'}"
            if not self.limiter.allow(key):
                raise HTTPException(429, "Rate limit exceeded")
            if mode == "cookie" and request.method not in {"GET", "HEAD", "OPTIONS"}:
                assert session is not None
                supplied = request.headers.get("x-csrf-token")
                if not supplied or not hmac.compare_digest(supplied, session["csrf"]):
                    raise HTTPException(403, "CSRF token is missing or invalid")
            origin = request.headers.get("origin")
            if origin and origin not in self.config.allowed_origins:
                raise HTTPException(403, "Origin is not allowed")
        except HTTPException as exc:
            self.audit.record(
                "http_rejected",
                path=request.url.path,
                method=request.method,
                status=exc.status_code,
                client=request.client.host if request.client else None,
            )
            return JSONResponse(
                {"detail": exc.detail},
                status_code=exc.status_code,
                headers=exc.headers,
            )
        response = await call_next(request)
        self.audit.record(
            "http_request",
            path=request.url.path,
            method=request.method,
            status=response.status_code,
            identity=identity,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    async def authenticate_websocket(
        self, websocket: WebSocket, *, kind="agent"
    ) -> dict[str, Any] | None:
        # Query-string credentials are intentionally rejected because URLs leak.
        if "token" in websocket.query_params:
            await websocket.close(code=1008, reason="Query-string tokens are not accepted")
            return None
        token = self.bearer(websocket.headers)
        if self.authority.authenticate_api_token(token):
            return {"sub": "api-token", "kind": kind}
        session = self.authority.verify_session(token, kind=kind)
        if session is None:
            await websocket.close(code=1008, reason="Authentication required")
            return None
        return session


def install_security_routes(app, security: ApplicationSecurity):
    @app.post("/api/v1/auth/session", include_in_schema=False)
    async def create_session(request: Request):
        token = security.bearer(request.headers)
        if not security.authority.authenticate_api_token(token):
            raise HTTPException(401, "Valid bearer token required")
        session = security.authority.issue_session(
            "local-operator", security.config.session_ttl_seconds
        )
        response = JSONResponse(
            {"csrf_token": session["csrf"], "expires_at": session["expires_at"]}
        )
        response.set_cookie(
            security.config.cookie_name,
            session["token"],
            httponly=True,
            secure=security.config.secure_cookies,
            samesite="strict",
            max_age=security.config.session_ttl_seconds,
        )
        return response

    @app.post("/api/v1/auth/rotate", include_in_schema=False)
    async def rotate_token(request: Request):
        current = security.bearer(request.headers)
        body = await request.json()
        try:
            security.authority.rotate(
                current or "",
                str(body.get("new_token", "")),
                grace_seconds=security.config.rotation_grace_seconds,
            )
        except PermissionError as exc:
            raise HTTPException(401, str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from exc
        security.audit.record("api_token_rotated")
        return {"success": True, "grace_seconds": security.config.rotation_grace_seconds}
