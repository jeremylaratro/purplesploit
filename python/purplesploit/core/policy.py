"""Engagement authorization, containment, and execution budget enforcement."""

from __future__ import annotations

from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
import fnmatch
import hashlib
import hmac
import ipaddress
from pathlib import Path
import re
from threading import RLock
import time
from typing import Any, Iterator
from urllib.parse import urlsplit
from uuid import uuid4

from .execution import ExecutionRequest


def _now() -> datetime:
    return datetime.now(timezone.utc)


class PolicyViolation(PermissionError):
    def __init__(self, code: str, message: str, *, details=None):
        super().__init__(message)
        self.code = code
        self.details = details or {}

    def to_dict(self):
        return {"allowed": False, "code": self.code, "message": str(self), "details": self.details}


class ActionRisk(str, Enum):
    PASSIVE = "passive"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


RISK_ORDER = {
    ActionRisk.PASSIVE: 0,
    ActionRisk.LOW: 1,
    ActionRisk.MEDIUM: 2,
    ActionRisk.HIGH: 3,
    ActionRisk.CRITICAL: 4,
}


@dataclass
class ScopeContract:
    include: list[str]
    exclude: list[str] = field(default_factory=list)
    allowed_ports: list[int] = field(default_factory=list)
    allow_redirects: bool = False
    allow_dns_rebinding: bool = False
    allow_proxies: bool = False
    max_redirects: int = 0
    max_child_targets: int = 4096

    def __post_init__(self):
        if not self.include:
            raise ValueError("Authorization scope requires at least one include rule")
        if self.max_redirects < 0 or self.max_child_targets <= 0:
            raise ValueError("Invalid containment limits")
        for port in self.allowed_ports:
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("allowed_ports must contain valid TCP/UDP ports")


@dataclass
class Approval:
    id: str
    risks: list[str]
    approved_by: str
    expires_at: str
    module_patterns: list[str] = field(default_factory=lambda: ["*"])
    target_patterns: list[str] = field(default_factory=lambda: ["*"])

    def valid_for(self, request: ExecutionRequest, risk: ActionRisk, targets: list[str]) -> bool:
        try:
            expiry = datetime.fromisoformat(self.expires_at)
        except ValueError:
            return False
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return (
            expiry > _now()
            and risk.value in self.risks
            and any(fnmatch.fnmatchcase(request.module_path, item) for item in self.module_patterns)
            and all(
                any(fnmatch.fnmatchcase(target, item) for item in self.target_patterns)
                for target in targets
            )
        )


@dataclass
class EngagementAuthorization:
    engagement_id: str
    authorized_by: str
    authorization_reference: str
    starts_at: str
    ends_at: str
    scope: ScopeContract
    allowed_risks: list[str] = field(default_factory=lambda: ["passive", "low"])
    approvals: list[Approval] = field(default_factory=list)
    rate_per_minute: int = 60
    max_concurrency: int = 4
    allowed_hours_utc: list[int] = field(default_factory=lambda: list(range(24)))
    emergency_contact: str = ""
    data_retention_days: int = 30
    require_lockout_discovery: bool = True

    @classmethod
    def from_dict(cls, value: dict[str, Any]):
        value = dict(value)
        value["scope"] = ScopeContract(**value["scope"])
        value["approvals"] = [Approval(**item) for item in value.get("approvals", [])]
        result = cls(**value)
        result.validate()
        return result

    def to_dict(self):
        return asdict(self)

    def validate(self):
        if not self.engagement_id or not self.authorized_by or not self.authorization_reference:
            raise ValueError("Authorization requires engagement, approver, and reference")
        start, end = datetime.fromisoformat(self.starts_at), datetime.fromisoformat(self.ends_at)
        if start.tzinfo is None or end.tzinfo is None or end <= start:
            raise ValueError("Authorization timestamps must be timezone-aware and ordered")
        if self.rate_per_minute <= 0 or self.max_concurrency <= 0:
            raise ValueError("Rate and concurrency budgets must be positive")
        if any(hour not in range(24) for hour in self.allowed_hours_utc):
            raise ValueError("allowed_hours_utc must contain UTC hours 0-23")
        for value in self.allowed_risks:
            ActionRisk(value)


def normalize_target(value: str) -> tuple[str, int | None, str]:
    """Return host, port, and path without DNS resolution or network access."""
    value = str(value).strip()
    if not value or any(character in value for character in "\r\n\0"):
        raise PolicyViolation("invalid_target", "Target is empty or contains control characters")
    if "/" in value and "://" not in value:
        try:
            return str(ipaddress.ip_network(value, strict=False)), None, ""
        except ValueError:
            pass
    parsed = urlsplit(value if "://" in value else "//" + value)
    host = parsed.hostname
    if host is None:
        # CIDR literals are not accepted by urlsplit with a scheme-relative prefix.
        try:
            ipaddress.ip_network(value, strict=False)
            return value, None, ""
        except ValueError as exc:
            raise PolicyViolation("invalid_target", f"Cannot parse target: {value}") from exc
    try:
        host = str(ipaddress.ip_address(host))
    except ValueError:
        host = host.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as exc:
        raise PolicyViolation("invalid_target", f"Invalid target port: {value}") from exc
    return host, port, parsed.path or "/"


def _rule_match(target: str, rule: str) -> bool:
    host, _, path = normalize_target(target)
    rule = rule.strip()
    try:
        network = ipaddress.ip_network(rule, strict=False)
        try:
            if "/" in host:
                target_network = ipaddress.ip_network(host, strict=False)
                return (
                    target_network.version == network.version
                    and int(target_network.network_address) >= int(network.network_address)
                    and int(target_network.broadcast_address) <= int(network.broadcast_address)
                )
            address = ipaddress.ip_address(host)
        except ValueError:
            return False
        return address in network
    except ValueError:
        pass
    if "://" in rule:
        rule_host, rule_port, rule_path = normalize_target(rule)
        target_host, target_port, target_path = normalize_target(target)
        return (
            fnmatch.fnmatchcase(target_host, rule_host)
            and (rule_port is None or rule_port == target_port)
            and target_path.startswith(rule_path)
        )
    return fnmatch.fnmatchcase(host, rule.lower().rstrip("."))


def classify_risk(request: ExecutionRequest) -> ActionRisk:
    if request.action_risk:
        return ActionRisk(request.action_risk)
    value = f"{request.module_path}/{request.operation_name or ''}".lower()
    if any(
        item in value
        for item in ("deploy/", "c2/", "psexec", "wmiexec", "secretsdump", "execute command")
    ):
        return ActionRisk.CRITICAL
    if any(item in value for item in ("spray", "sqlmap", "brute", "password", "exploit")):
        return ActionRisk.HIGH
    if any(item in value for item in ("nuclei", "wfuzz", "wpscan", "kerberoast", "asreproast")):
        return ActionRisk.MEDIUM
    if any(item in value for item in ("osint/", "import", "parse")):
        return ActionRisk.PASSIVE
    return ActionRisk.LOW


TARGET_KEYS = frozenset(
    {"RHOST", "RHOSTS", "TARGET", "TARGETS", "URL", "DOMAIN", "DC_IP", "HOST", "ENDPOINT"}
)


def request_targets(request: ExecutionRequest) -> list[str]:
    targets = list(request.targets)
    for key, value in request.options.items():
        if key.upper() not in TARGET_KEYS or value in (None, ""):
            continue
        values = value if isinstance(value, list) else re.split(r"[\s,]+", str(value))
        targets.extend(item for item in values if item)
    return list(dict.fromkeys(str(item) for item in targets))


class PolicyEngine:
    def __init__(self, *, enforce=True, clock=_now):
        self.enforce = enforce
        self.clock = clock
        self._contracts: dict[str, EngagementAuthorization] = {}
        self._active: defaultdict[str, int] = defaultdict(int)
        self._rates: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = RLock()

    @classmethod
    def disabled(cls):
        return cls(enforce=False)

    def register(self, contract: EngagementAuthorization | dict[str, Any]):
        if isinstance(contract, dict):
            resolved = EngagementAuthorization.from_dict(contract)
        else:
            resolved = contract
        resolved.validate()
        self._contracts[resolved.engagement_id] = resolved
        return resolved.to_dict()

    def get(self, engagement_id: str):
        try:
            return self._contracts[engagement_id]
        except KeyError as exc:
            raise PolicyViolation(
                "missing_authorization", "Engagement has no authorization contract"
            ) from exc

    def _target_allowed(self, contract: EngagementAuthorization, target: str) -> bool:
        host, port, _ = normalize_target(target)
        if (
            contract.scope.allowed_ports
            and port is not None
            and port not in contract.scope.allowed_ports
        ):
            return False
        if any(_rule_match(target, rule) for rule in contract.scope.exclude):
            return False
        return any(_rule_match(target, rule) for rule in contract.scope.include)

    def explain(
        self, request: ExecutionRequest | dict[str, Any], *, targets=None
    ) -> dict[str, Any]:
        if isinstance(request, dict):
            request = ExecutionRequest.from_dict(request)
        risk = classify_risk(request)
        targets = list(dict.fromkeys(targets or request_targets(request)))
        plan = {
            "request_id": request.request_id,
            "engagement_id": request.engagement_id,
            "module": request.module_path,
            "operation": request.operation_name,
            "risk": risk.value,
            "side_effects": list(request.side_effects),
            "targets": targets,
            "argv": list(request.argv),
            "allowed": not self.enforce,
            "decision": "policy_disabled" if not self.enforce else "pending",
        }
        if not self.enforce:
            return plan
        try:
            self.authorize(request, targets=targets, reserve=False)
        except PolicyViolation as exc:
            plan.update(exc.to_dict(), decision="rejected")
        else:
            plan.update(allowed=True, decision="authorized")
        return plan

    def authorize(
        self,
        request: ExecutionRequest | dict[str, Any],
        *,
        targets=None,
        reserve=True,
    ) -> dict[str, Any]:
        if isinstance(request, dict):
            request = ExecutionRequest.from_dict(request)
        if not self.enforce:
            return {"allowed": True, "decision": "policy_disabled", "reservation": None}
        if not request.engagement_id:
            raise PolicyViolation("missing_engagement", "Execution requires an engagement_id")
        contract = self.get(request.engagement_id)
        now = self.clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        start, end = (
            datetime.fromisoformat(contract.starts_at),
            datetime.fromisoformat(contract.ends_at),
        )
        if not start <= now <= end or now.hour not in contract.allowed_hours_utc:
            raise PolicyViolation(
                "outside_authorized_window", "Execution is outside the authorized time window"
            )
        targets = list(dict.fromkeys(targets or request_targets(request)))
        if not targets:
            raise PolicyViolation("missing_target", "Execution has no policy-visible target")
        if len(targets) > contract.scope.max_child_targets:
            raise PolicyViolation("target_budget", "Execution exceeds the child-target budget")
        rejected = [target for target in targets if not self._target_allowed(contract, target)]
        resolved = list(request.resolved_targets)
        rejected.extend(target for target in resolved if not self._target_allowed(contract, target))
        if rejected:
            raise PolicyViolation(
                "out_of_scope",
                "One or more targets are outside engagement scope",
                details={"targets": sorted(set(rejected))},
            )
        if request.proxy and not contract.scope.allow_proxies:
            raise PolicyViolation(
                "proxy_not_allowed", "Engagement does not authorize a proxy or pivot"
            )
        if request.redirect_chain:
            if not contract.scope.allow_redirects:
                raise PolicyViolation(
                    "redirect_not_allowed", "Redirect following is not authorized"
                )
            if len(request.redirect_chain) > contract.scope.max_redirects:
                raise PolicyViolation(
                    "redirect_budget", "Redirect chain exceeds the authorization budget"
                )
            redirected = [
                item for item in request.redirect_chain if not self._target_allowed(contract, item)
            ]
            if redirected:
                raise PolicyViolation(
                    "redirect_out_of_scope", "Redirect escaped the authorized scope"
                )
        risk = classify_risk(request)
        if risk.value not in contract.allowed_risks:
            approval = next(
                (
                    item
                    for item in contract.approvals
                    if item.id == request.approval_id and item.valid_for(request, risk, targets)
                ),
                None,
            )
            if approval is None:
                raise PolicyViolation(
                    "approval_required",
                    f"{risk.value} action requires a matching unexpired approval",
                )
        reservation = None
        if reserve:
            with self._lock:
                if self._active[contract.engagement_id] >= contract.max_concurrency:
                    raise PolicyViolation(
                        "concurrency_budget", "Engagement concurrency budget is exhausted"
                    )
                now_mono = time.monotonic()
                rate = self._rates[contract.engagement_id]
                while rate and rate[0] <= now_mono - 60:
                    rate.popleft()
                if len(rate) >= contract.rate_per_minute:
                    raise PolicyViolation("rate_budget", "Engagement dispatch rate is exhausted")
                rate.append(now_mono)
                self._active[contract.engagement_id] += 1
                reservation = str(uuid4())
        return {
            "allowed": True,
            "decision": "authorized",
            "risk": risk.value,
            "targets": targets,
            "reservation": reservation,
        }

    def release(self, engagement_id: str | None, reservation: str | None):
        if self.enforce and engagement_id and reservation:
            with self._lock:
                self._active[engagement_id] = max(0, self._active[engagement_id] - 1)

    @contextmanager
    def permit(self, request: ExecutionRequest, *, targets=None) -> Iterator[dict[str, Any]]:
        decision = self.authorize(request, targets=targets)
        try:
            yield decision
        finally:
            self.release(request.engagement_id, decision.get("reservation"))


@dataclass
class SprayBudget:
    per_principal: int = 2
    per_domain: int = 100
    per_run: int = 50
    window_minutes: int = 30

    def __post_init__(self):
        if min(self.per_principal, self.per_domain, self.per_run, self.window_minutes) <= 0:
            raise ValueError("Spray budgets must be positive")


class SprayBudgetLedger:
    """Transactional cross-run reservations; uncertainty always consumes budget."""

    def __init__(self, store, budget=None, clock=_now):
        self.store = store
        self.budget = budget or SprayBudget()
        self.clock = clock

    def reserve(
        self,
        *,
        engagement_id: str,
        domain: str,
        attempts: list[tuple[str, str]],
    ) -> list[str]:
        # attempt entries are (principal, target); passwords never enter the ledger.
        if len(attempts) > self.budget.per_run:
            raise PolicyViolation("spray_run_budget", "Spray exceeds the per-run attempt budget")
        now = self.clock()
        expires = now + timedelta(minutes=self.budget.window_minutes)
        cutoff = (now - timedelta(minutes=self.budget.window_minutes)).isoformat()
        reservations = []
        with self.store.transaction() as connection:
            domain_count = connection.execute(
                """SELECT COUNT(*) FROM spray_reservations
                   WHERE engagement_id=? AND domain_name=? AND reserved_at>=?""",
                (engagement_id, domain or "", cutoff),
            ).fetchone()[0]
            if domain_count + len(attempts) > self.budget.per_domain:
                raise PolicyViolation("spray_domain_budget", "Domain spray budget is exhausted")
            incoming: defaultdict[str, int] = defaultdict(int)
            for principal, _ in attempts:
                incoming[principal] += 1
            for principal, count in incoming.items():
                previous = connection.execute(
                    """SELECT COUNT(*) FROM spray_reservations
                       WHERE engagement_id=? AND domain_name=? AND principal=? AND reserved_at>=?""",
                    (engagement_id, domain or "", principal, cutoff),
                ).fetchone()[0]
                if previous + count > self.budget.per_principal:
                    raise PolicyViolation(
                        "spray_principal_budget", f"Principal budget exhausted: {principal}"
                    )
            for principal, target in attempts:
                reservation = str(uuid4())
                connection.execute(
                    """INSERT INTO spray_reservations
                       (reservation_id, engagement_id, domain_name, principal, target,
                        reserved_at, expires_at, status, outcome)
                       VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved', NULL)""",
                    (
                        reservation,
                        engagement_id,
                        domain or "",
                        principal,
                        target,
                        now.isoformat(),
                        expires.isoformat(),
                    ),
                )
                reservations.append(reservation)
        return reservations

    def record(self, reservation_id: str, outcome: str | None):
        status = (
            "uncertain" if not outcome or outcome in {"tool_error", "ambiguous"} else "completed"
        )
        with self.store.transaction() as connection:
            if (
                connection.execute(
                    "SELECT 1 FROM spray_reservations WHERE reservation_id=?", (reservation_id,)
                ).fetchone()
                is None
            ):
                raise KeyError(reservation_id)
            connection.execute(
                "UPDATE spray_reservations SET status=?, outcome=? WHERE reservation_id=?",
                (status, outcome, reservation_id),
            )

    def usage(self, engagement_id: str, domain: str = "") -> dict[str, Any]:
        cutoff = (self.clock() - timedelta(minutes=self.budget.window_minutes)).isoformat()
        rows = self.store._connection.execute(
            """SELECT principal, status, COUNT(*) AS count FROM spray_reservations
               WHERE engagement_id=? AND domain_name=? AND reserved_at>=?
               GROUP BY principal, status""",
            (engagement_id, domain, cutoff),
        ).fetchall()
        return {
            "engagement_id": engagement_id,
            "domain": domain,
            "total": sum(row["count"] for row in rows),
            "principals": {
                principal: sum(row["count"] for row in rows if row["principal"] == principal)
                for principal in {row["principal"] for row in rows}
            },
            "uncertain": sum(row["count"] for row in rows if row["status"] == "uncertain"),
        }
