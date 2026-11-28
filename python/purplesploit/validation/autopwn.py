"""Phase 4a: a fenced, non-secret, projective planner. No execution path.

Only the start identity is inspected. Alternatives are projections, never proof
of a credential or permission gain. Missing posture stays unknown. In particular
we do not run generic discovery/recon, load the credential store, read key files,
follow ADCS discovery, or call any executor lifecycle/preview/produce method.
"""
from __future__ import annotations

import ipaddress
import json
import math
import re
import signal
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, probes, states
from .executors import IMPLEMENTED, get_executor
from .executors.acl_common import dacledit_read_argv
from .executors.base import ExecutorContext, AuthorizedLabProvider, RunResult, SubprocessRunner
from .findings import NormalizedFinding
from .recommend import resolve_params


def host_name(value):
    """Lexical fence only: no DNS, aliases, suffix tricks, URLs or tool options."""
    if not isinstance(value, str):
        return None
    value = value.strip().rstrip('.').lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if len(value) > 253 or not value:
        return None
    if all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in value.split('.')):
        return value
    return None


def _items(values):
    if isinstance(values, str):
        values = [values]
    return [item.strip() for value in (values or []) for item in value.split(',') if item.strip()]


@dataclass
class ScopeFence:
    hosts: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    enumerated_hosts: set[str] = field(default_factory=set)
    enumeration_endpoints: set[str] = field(default_factory=set)

    @classmethod
    def parse(cls, hosts=(), domains=()):
        fence = cls()
        for values, dest in ((hosts, fence.hosts), (domains, fence.domains)):
            for value in _items(values):
                host = host_name(value)
                if not host or (dest is fence.domains and ('.' not in host or _is_ip(host))):
                    raise ValueError("invalid_scope")
                dest.add(host)
        return fence

    def contains(self, value):
        host = host_name(value)
        return bool(host and (host in self.hosts or host in self.enumerated_hosts or
                    host in self.enumeration_endpoints or
                    (not _is_ip(host) and any(host.endswith('.' + d) for d in self.domains))))

    def public(self):
        return {"hosts": sorted(self.hosts | self.enumerated_hosts | self.enumeration_endpoints),
                "domains": sorted(self.domains), "enumerated_hosts": sorted(self.enumerated_hosts),
                "enumeration_endpoints": sorted(self.enumeration_endpoints)}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


class PlanStopped(BaseException):
    def __init__(self, code):
        self.code = code


class Admission:
    def __init__(self, max_hops=1000, max_time=300, kill_file=None, clock=time.monotonic):
        if max_hops < 0 or not math.isfinite(max_time) or max_time < 0:
            raise ValueError("invalid_budget")
        self.max_hops, self.max_time = max_hops, max_time
        self.kill_file = Path(kill_file) if kill_file else None
        self.clock, self.started = clock, clock()
        self.expansions = 0
        self.interrupted = False

    def check(self, *, expansion=False):
        if self.interrupted:
            raise PlanStopped("interrupted")
        if self.kill_file and self.kill_file.exists():
            raise PlanStopped("kill_file")
        if self.clock() - self.started >= self.max_time:
            raise PlanStopped("max_time")
        if expansion and self.expansions >= self.max_hops:
            raise PlanStopped("max_hops")

    def expand(self):
        self.check(expansion=True)
        self.expansions += 1

    @contextmanager
    def signals(self):
        previous = signal.getsignal(signal.SIGINT)
        def stop(signum, frame):
            self.interrupted = True
        signal.signal(signal.SIGINT, stop)
        try:
            yield
        finally:
            signal.signal(signal.SIGINT, previous)


# Only these attributes can cross the tool boundary. No wildcard/credential
# attribute, read-file, module, script, ticket request, or execution option.
POSTURE_ATTRIBUTES = frozenset({
    "samaccountname", "useraccountcontrol", "msds-supportedencryptiontypes",
    "msds-allowedtodelegateto", "serviceprincipalname", "ms-ds-machineaccountquota",
    "msds-behavior-version", "dnshostname",
})


class PostureRunner:
    """Deny by default, including future probes with new command shapes.

    No argv, output, exception, or tool error is logged. Only fixed public
    events leave this boundary. Infrastructure is checked even for implicit
    authentication traffic; certipy/active coercion/listeners are never launched.
    """
    def __init__(self, cfg, runner, fence, admission, event):
        self.cfg, self.runner, self.fence = cfg, runner, fence
        self.admission, self.event = admission, event
        self.technique = None

    def run(self, argv, *, timeout=None, **kwargs):
        self.admission.check()
        cfg = self.cfg
        destinations = []
        permitted = False
        if len(argv) >= 3 and argv[:2] in (["nxc", "ldap"], ["nxc", "smb"]):
            host = argv[2]
            prefix = ["nxc", argv[1], host, *probes._nxc_auth(cfg)]
            tail = argv[len(prefix):]
            if argv[:len(prefix)] == prefix:
                permitted = not tail or (argv[1] == "smb" and tail == ["--shares"])
                if argv[1] == "ldap" and len(tail) == 3 and tail[0] == "--query":
                    attrs = tail[2].lower().split()
                    permitted = bool(attrs) and set(attrs) <= POSTURE_ATTRIBUTES
            destinations = [host]
        elif len(argv) >= 7 and argv[:4] == ["impacket-dacledit", "-action", "read", "-target"]:
            permitted = argv == dacledit_read_argv(cfg, argv[4], cfg.dc_ip)
            destinations = [cfg.dc_ip]
        # Conservatively fence DC/KDC/resolver for all authenticated tools: no
        # hidden domain-controller contact is authorized by a member-host fence.
        destinations += [cfg.dc_ip, cfg.kdc_host or cfg.dc_ip]
        if cfg.dns_server:
            destinations.append(cfg.dns_server)
        if not permitted or kwargs:
            raise ValueError("posture_command_denied")
        for host in destinations:
            if not self.fence.contains(host):
                self.event("skipped_out_of_scope", technique=self.technique,
                           target=host_name(host), in_scope=False)
                raise ValueError("out_of_scope")
        self.event("posture_read_requested", technique=self.technique,
                   target=host_name(destinations[0]), in_scope=True)
        self.admission.check()
        remaining = self.admission.max_time - (self.admission.clock() - self.admission.started)
        if remaining <= 0:
            raise PlanStopped("max_time")
        try:
            return self.runner.run(argv, timeout=min(timeout or 30, 30, remaining))
        except Exception:
            return RunResult(returncode=None, error="posture_read_failed")


# Free-form destination params not already tagged target_host/spn by executors.
DESTINATION_PARAMS = frozenset({"hosts", "coerce_victim", "external_listener", "callback",
                              "callback_host", "relay_target", "reauth_target", "dc", "kdc",
                              "dc_ip", "kdc_host", "dns_server", "ca_host"})
CALLBACK_TECHNIQUES = frozenset({"COERCION", "NTLM-RELAY", "ESC8", "ESC11", "UNCONSTRAINED-DELEG"})


def resolved_destinations(cfg, finding, specs, values):
    """Resolve even incomplete defaults BEFORE probing; unknown endpoints fail closed."""
    hosts = [finding.host, cfg.dc_ip, cfg.kdc_host or cfg.dc_ip]
    # These executors append configured extra targets EVEN when a hosts param
    # was supplied. Mirror that resolution instead of fencing the param alone.
    if finding.technique in ("SIGNING-RELAY", "SHARE-LOOT"):
        hosts.extend(cfg.extra_targets)
    if cfg.dns_server:
        hosts.append(cfg.dns_server)
    for spec in specs:
        value = values.get(spec.name)
        if spec.kind == "target_host" or spec.name in DESTINATION_PARAMS:
            hosts.extend(_items([value]) if isinstance(value, str) else ([value] if value else []))
        elif spec.kind == "spn" and value and '/' in value:
            hosts.append(value.split('/', 1)[1])
    # Empty callbacks mean a runtime-chosen local interface, not an authorized
    # endpoint. Never project a hop with an unresolved callback.
    if finding.technique in CALLBACK_TECHNIQUES and not any(values.get(k) for k in
            ("listener_host", "external_listener", "unconstrained_host")):
        hosts.append(None)
    return hosts


def plan(cfg, *, scope=(), scope_domain=(), scope_enumerate=(), goal=states.S_DA,
         max_hops=1000, max_time=300, kill_file=None, params=None, runner=None,
         clock=time.monotonic):
    """Return/write a PUBLIC-only audit. ``params`` is TECH -> public selectors.

    Enumeration needs an already fenced DC (scope/scope-domain). For standalone
    scope-enumerate, a DC FQDN under the requested domain is the explicit bootstrap
    endpoint; an IP cannot prove domain membership and requires --scope <DC-IP>.
    Enumeration endpoints are recorded in the fence, but become planning targets
    only if explicitly scoped or returned by enumeration (never an empty fallback).
    """
    fence = ScopeFence.parse(scope, scope_domain)
    enum_domains = ScopeFence.parse(domains=scope_enumerate).domains
    dc = host_name(cfg.dc_ip)
    if dc and any(dc.endswith('.' + domain) for domain in enum_domains):
        fence.enumeration_endpoints.add(dc)
    if goal == "DA":
        goal = states.S_DA
    if goal not in states.BASE_STATES:
        raise ValueError("unknown_goal")
    params = params or {}
    if set(params) - IMPLEMENTED:
        raise ValueError("unknown_technique")
    admission = Admission(max_hops, max_time, kill_file, clock)
    principal = cfg.username or ""
    events, path = [], []
    audit_stream = None
    header = None

    def write(record):
        audit_stream.write(json.dumps(record) + '\n')
        audit_stream.flush()

    def open_audit():
        nonlocal audit_stream, header
        header = {"schema": "autopwn.plan.v1", "mode": "dry_run", "principal": principal,
                  "projection": "start_identity_alternatives",
                  "goal": goal, "fence": fence.public()}
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
        audit = cfg.output_dir / ("autopwn-" + uuid.uuid4().hex + ".jsonl")
        audit_stream = audit.open('x', encoding='utf-8')
        write({"header": header})
        for pending in events:
            write(pending)
    # Event signature IS the public schema: no arbitrary dictionary copying.
    def event(outcome, *, technique=None, target=None, classification=None, in_scope=None):
        record = {"outcome": outcome, "technique": technique, "target": target,
                  "classification": classification, "principal": principal, "in_scope": in_scope}
        events.append(record)
        if audit_stream is not None:
            write(record)
    status = "empty_frontier"
    underlying = runner if runner is not None else SubprocessRunner()
    safe = PostureRunner(cfg, underlying, fence, admission, event)
    ctx = ExecutorContext(cfg, safe, AuthorizedLabProvider(False), cfg.output_dir)
    try:
        with admission.signals():
            admission.check(expansion=True)
            for domain in sorted(enum_domains):
                admission.check(expansion=True)
                res = probes._ldap_query(ctx, "(objectClass=computer)", ["dNSHostName"])
                admission.check()
                if res.returncode == 0 and not res.error and not res.timed_out:
                    # Parse only actual attribute rows, excluding auth/status
                    # banners. No raw text is copied into the public record.
                    for line in (res.stdout or "").splitlines():
                        if re.search(r"\[[-+*]\]", line):
                            continue
                        match = re.search(r"\bdNSHostName(?:\s*[:=]\s*|\s+)(\S+)\s*$", line, re.I)
                        host = host_name(match[1]) if match else None
                        if host and host.endswith('.' + domain):
                            fence.enumerated_hosts.add(host)
            # The complete fence is now resolved. Persist the header before the
            # first candidate expansion and append/flush public events as we go.
            open_audit()
            hosts = sorted({h for h in (fence.hosts | fence.enumerated_hosts |
                            set(cfg.extra_targets)) if fence.contains(h)})
            for host in cfg.extra_targets:
                if not fence.contains(host):
                    event("skipped_out_of_scope", target=host_name(host), in_scope=False)
            if not hosts:
                status = "empty_scope"
            for host in hosts:
                for technique in sorted(IMPLEMENTED):
                    admission.expand()
                    safe.technique = technique
                    ex = get_executor(technique)
                    finding = NormalizedFinding(source={}, finding_id="plan-" + technique,
                        host=host, technique=technique, technique_class=ex.technique_class,
                        entity={})
                    overrides = params.get(technique, {})
                    specs = ex.param_specs(ctx, finding)
                    vals = {s.name: overrides.get(s.name, s.recommended) for s in specs}
                    # Probe selectors must match the resolved executor defaults.
                    finding.entity = {k: v for k, v in vals.items() if isinstance(v, str)}
                    destinations = resolved_destinations(cfg, finding, specs, vals)
                    outside = [h for h in destinations if not fence.contains(h)]
                    if outside:
                        for dest in outside:
                            event("skipped_out_of_scope", technique=technique,
                                  target=host_name(dest), in_scope=False)
                        continue
                    try:
                        resolve_params(specs, overrides)
                    except Exception:
                        event("missing_parameters", technique=technique, target=host, in_scope=True)
                        continue
                    # Dedicated discovery excludes secret-bearing probes and
                    # never uses generic recon or candidate_findings([]).
                    result = discovery.discover_posture(ctx, finding)
                    admission.check()
                    # A delegation read can reveal additional SPN destinations.
                    # Fence these before accepting a projected hop; do not follow.
                    discovered = result.evidence.get("allowed_to_delegate_to")
                    if discovered:
                        endpoints = re.findall(r"[A-Za-z][A-Za-z0-9-]*/([^\s,;]+)", str(discovered))
                        if not endpoints or any(not fence.contains(h) for h in endpoints):
                            event("skipped_out_of_scope", technique=technique, target=host, in_scope=False)
                            continue
                    classification = ("unknown" if result.unknown else
                                      "eligible" if result.viable and ex.verified_recipe else "ineligible")
                    event("posture_checked", technique=technique, target=host,
                          classification=classification, in_scope=True)
                    if classification == "eligible":
                        reaches = goal in ex.eff
                        path.append({"technique": technique, "target": host, "principal": principal,
                                     "classification": "projected", "in_scope": True,
                                     "destinations": sorted({host_name(h) for h in destinations}),
                                     "would_gain_credential": bool(ex.recovers_credentials),
                                     "would_reach_goal": reaches})
                        event("projected_hop", technique=technique, target=host,
                              classification="projected", in_scope=True)
    except PlanStopped as stopped:
        status = stopped.code
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception:
        # Never retain exception messages, including in _private_errors.
        status = "planning_failed"
    if audit_stream is None:
        open_audit()
    event(status)
    report = {"header": header,
              "events": events, "projected_path": path, "status": status,
              "goal_status": "projected" if any(h["would_reach_goal"] for h in path) else "not_established",
              "goal_reached": False}
    try:
        write({"status": status, "goal_status": report["goal_status"],
               "goal_reached": False, "projected_path": path})
    finally:
        audit_stream.close()
    return report
