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
import sys
import time
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path

from . import discovery, probes, states
from .credential_store import CredentialStore
from .executors import IMPLEMENTED, get_executor
from .executors.acl_common import dacledit_read_argv
from .executors.base import (ExecutorContext, AuthorizedLabProvider, Credential,
                             RunResult, SubprocessRunner)
from .findings import NormalizedFinding
from .identity import credential_scope
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


# ========================================================================= 4b
# The autopwn EXECUTION loop (ADR-003 Phase 4b). Dry-run ``plan`` above is the
# unchanged default; NOTHING below runs unless the CLI gate (all of
# ``--execute --yes --allow-destructive --scope`` + a typed risk acceptance, or
# ``--dangerous`` for the acceptance only) has already passed. The loop auto-
# executes mutating AD techniques toward a goal state. Its safety model is the
# plan's and is NON-NEGOTIABLE:
#   * EVERY resolved destination of EVERY hop is fenced at dispatch; an out-of-
#     fence target is audited ``skipped_out_of_scope`` and NEVER dispatched.
#   * The loop advances ONLY on a verified rollback; a dirty / unverified /
#     interrupted mutation HALTS it (never advance against dirty state).
#   * Kill (SIGINT / ``--kill-file``) + budget (``--max-hops`` / ``--max-time``)
#     are admitted before every hop AND every tool launch; an in-flight mutation
#     finishes its hardened rollback first.
#   * The audit is a PUBLIC allowlist (identities, techniques, targets, outcome
#     codes, rollback status) -- never a secret value, raw result, teardown
#     obligation, or exception text.

# The exact phrase the operator must type to accept the residual risk.
ACCEPT_PHRASE = "EXECUTE"


def recognized_destinations(argv):
    """Best-effort host extraction from a tool argv for the defense-in-depth tool-
    boundary fence. Conservative by design: it recognizes ONLY the leading shapes
    that reliably carry a host (``nxc <proto> <host>``, an impacket
    ``domain/user[:pass]@host`` auth target, and a ``-dc-ip``/``-target-ip``
    value), so it never produces a false out-of-fence refusal on an unrelated
    token. The PRIMARY destination guarantee is the pre-dispatch
    :func:`resolved_destinations` fence; this is only a backstop."""
    if not isinstance(argv, (list, tuple)) or not argv:
        return []
    hosts = []
    if len(argv) >= 3 and argv[0] == "nxc":
        hosts.append(argv[2])
    if isinstance(argv[0], str) and argv[0].startswith("impacket-"):
        for token in argv:
            if isinstance(token, str) and "/" in token and "@" in token.split("/", 1)[1]:
                hosts.append(token.rsplit("@", 1)[1])
    for flag in ("-dc-ip", "-target-ip"):
        if flag in argv:
            i = argv.index(flag)
            if i + 1 < len(argv):
                hosts.append(argv[i + 1])
    return [h for h in (host_name(x) for x in hosts) if h]


class ExecuteRunner:
    """Wraps the real/injected command runner for the execute loop.

    Before every tool launch it admits the kill-switch + budget -- EXCEPT while a
    mutation's hardened rollback is in flight (``ctx._pending_teardown is not
    None``), so an in-flight rollback always finishes before the loop halts. It
    also fences every destination it can recognize (defense in depth); an out-of-
    fence recognized host is audited and refused, never dispatched."""

    def __init__(self, underlying, fence, admission, event, ctx_holder):
        self.underlying = underlying
        self.fence = fence
        self.admission = admission
        self.event = event
        self.ctx_holder = ctx_holder

    def run(self, argv, *, env=None, timeout=None, cwd=None):
        ctx = self.ctx_holder[0]
        tearing_down = ctx is not None and getattr(ctx, "_pending_teardown", None) is not None
        if not tearing_down:
            # Kill-switch + budget BEFORE every (non-rollback) tool launch.
            self.admission.check()
        for host in recognized_destinations(argv):
            if not self.fence.contains(host):
                self.event("skipped_out_of_scope", target=host_name(host), in_scope=False)
                return RunResult(returncode=None, error="out_of_scope")
        return self.underlying.run(argv, env=env, timeout=timeout, cwd=cwd)


@dataclass
class _Identity:
    """A frontier identity. ``selector`` is None for the operator start identity
    (the configured auth) and a ``principal@domain`` store selector for a gained
    one (re-scoped via the Phase-3 credential store)."""
    selector: object
    principal: str
    domain: str
    machine: bool = False

    @property
    def key(self):
        return (self.principal.casefold(), (self.domain or "").casefold())


def _execute_warning(fence, goal):
    """The LOUD, PUBLIC residual-risk warning. Names only the declared scope
    (hosts/domains the operator chose) -- never a secret."""
    pub = fence.public()
    declared = (sorted(fence.hosts) + ["domain:" + d for d in sorted(fence.domains)]
                + ["enumerated:" + h for h in sorted(fence.enumerated_hosts)])
    scope_desc = ", ".join(declared) or "(empty)"
    return ("autopwn EXECUTE mode auto-executes mutating AD techniques toward "
            f"{goal}. Rollback is NOT guaranteed if the run is interrupted "
            "(SIGINT / kill-file may leave AD mutated). The scope fence "
            f"[{scope_desc}] is the ONLY boundary.")


def execute(cfg, *, scope=(), scope_domain=(), scope_enumerate=(), goal=states.S_DA,
            max_hops=1000, max_time=300, kill_file=None, params=None, runner=None,
            dangerous=False, warn_fn=None, prompt_fn=None, clock=time.monotonic,
            discover=None):
    """Run the fenced, gated autopwn EXECUTION loop. Returns a PUBLIC-only report
    and writes a PUBLIC-only append-only audit (``autopwn.execute.v1``).

    ``params`` is TECH -> public selector overrides. ``runner`` is the injected
    command runner the real executors drive (default :class:`SubprocessRunner`);
    the loop wraps it in :class:`ExecuteRunner`. ``discover`` is the per-identity
    discovery callable ``(ctx, hosts) -> verdicts`` (default the full
    :func:`discovery.build_verdicts` with ``allow_destructive``); each verdict
    exposes ``technique`` / ``host`` / ``eligible_for_autoexploit``."""
    fence = ScopeFence.parse(scope, scope_domain)
    enum_domains = ScopeFence.parse(domains=scope_enumerate).domains
    base_dc = host_name(cfg.dc_ip)
    if base_dc and any(base_dc.endswith('.' + domain) for domain in enum_domains):
        fence.enumeration_endpoints.add(base_dc)
    if goal == "DA":
        goal = states.S_DA
    if goal not in states.BASE_STATES:
        raise ValueError("unknown_goal")
    params = params or {}
    if set(params) - IMPLEMENTED:
        raise ValueError("unknown_technique")
    admission = Admission(max_hops, max_time, kill_file, clock)
    warn_fn = warn_fn or (lambda s: print(s, file=sys.stderr))
    prompt_fn = prompt_fn if prompt_fn is not None else input
    if discover is None:
        def discover(ctx, hosts):
            return discovery.build_verdicts(ctx, hosts, allow_destructive=True)
    base_cfg = cfg
    start_principal = cfg.username or ""
    warning = _execute_warning(fence, goal)

    events, path = [], []
    audit_stream = None
    header = None
    accept_mode = None
    current = {"principal": start_principal}

    def write(record):
        audit_stream.write(json.dumps(record) + '\n')
        audit_stream.flush()

    def open_audit():
        nonlocal audit_stream, header
        header = {"schema": "autopwn.execute.v1", "mode": "execute",
                  "principal": start_principal, "goal": goal, "fence": fence.public(),
                  "warning": warning, "accept_mode": accept_mode}
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
        audit = cfg.output_dir / ("autopwn-" + uuid.uuid4().hex + ".jsonl")
        audit_stream = audit.open('x', encoding='utf-8')
        write({"header": header})
        for pending in events:
            write(pending)

    # Event signature IS the public schema: identities, techniques, targets,
    # outcome codes, and rollback status ONLY -- never a secret / raw result.
    def event(outcome, *, technique=None, target=None, in_scope=None, rollback=None,
              principal=None):
        record = {"outcome": outcome, "technique": technique, "target": target,
                  "principal": principal if principal is not None else current["principal"],
                  "in_scope": in_scope, "rollback": rollback}
        events.append(record)
        if audit_stream is not None:
            write(record)

    ctx_holder = [None]
    underlying = runner if runner is not None else SubprocessRunner()
    safe = ExecuteRunner(underlying, fence, admission, event, ctx_holder)
    store = CredentialStore.from_config(base_cfg)
    status = "empty_frontier"
    goal_reached = False

    def in_fence_hosts(active_cfg):
        return sorted({h for h in (fence.hosts | fence.enumerated_hosts |
                       set(active_cfg.extra_targets)) if fence.contains(h)})

    def make_ctx(active_cfg):
        return ExecutorContext(active_cfg, safe, AuthorizedLabProvider(active_cfg.authorized),
                               active_cfg.output_dir)

    try:
        with admission.signals():
            # Budget / existing kill-file gate BEFORE anything is read or accepted.
            admission.check(expansion=True)
            # Risk acceptance BEFORE any mutating hop (and before any read).
            warn_fn("\n*** autopwn EXECUTE -- DESTRUCTIVE, AUTONOMOUS ***")
            warn_fn(warning)
            if dangerous:
                accept_mode = "dangerous"
            else:
                try:
                    answer = prompt_fn(f"Type '{ACCEPT_PHRASE}' to proceed, anything else aborts: ")
                except (EOFError, KeyboardInterrupt):
                    answer = ""
                if (answer or "").strip() != ACCEPT_PHRASE:
                    status = "acceptance_declined"
                    open_audit()
                    event(status)
                    write({"status": status, "goal_status": "not_established",
                           "goal_reached": False, "executed_path": path})
                    audit_stream.close()
                    return {"header": header, "events": events, "executed_path": path,
                            "status": status, "goal_status": "not_established",
                            "goal_reached": False}
                accept_mode = "interactive"
            # Resolve --scope-enumerate against the (fenced) DC, then persist the
            # header so the exact scope + accept-mode are recorded before any hop.
            boot_ctx = make_ctx(base_cfg)
            ctx_holder[0] = boot_ctx
            _enumerate_into_fence(boot_ctx, admission, fence, enum_domains)
            open_audit()
            event("warning_accepted")

            visited = set()
            frontier = [_Identity(None, start_principal, base_cfg.domain,
                                  machine=start_principal.endswith("$"))]
            while frontier:
                admission.check()                      # kill/budget BETWEEN hops
                identity = _pop_frontier(frontier)
                if identity.key in visited:
                    continue
                visited.add(identity.key)
                current["principal"] = identity.principal
                scope_cm = (nullcontext((base_cfg, None)) if identity.selector is None
                            else credential_scope(base_cfg, identity.selector))
                try:
                    with scope_cm as (active_cfg, _cred):
                        ctx = make_ctx(active_cfg)
                        ctx.on_capabilities = None     # set per hop
                        ctx_holder[0] = ctx
                        # Infra must be explicitly in-fence to be touched.
                        infra = [active_cfg.dc_ip, active_cfg.kdc_host or active_cfg.dc_ip]
                        if active_cfg.dns_server:
                            infra.append(active_cfg.dns_server)
                        if any(not fence.contains(h) for h in infra):
                            for h in infra:
                                if not fence.contains(h):
                                    event("skipped_out_of_scope", target=host_name(h), in_scope=False)
                            continue
                        event("identity_entered", in_scope=True)
                        verdicts = discover(ctx, in_fence_hosts(active_cfg))
                        goal_reached = _run_identity_hops(
                            ctx, active_cfg, fence, admission, goal, params,
                            verdicts, store, frontier, visited, event, path)
                        if goal_reached:
                            status = "goal_reached"
                            break
                except _LoopHalt as halt:
                    status = halt.code
                    goal_reached = halt.code == "goal_reached"
                    break
                except Exception:
                    # Forgiving by default: a single unresolvable identity (bad
                    # re-scope / discovery error) is audited and SKIPPED -- it
                    # never aborts the whole engagement and never leaks a reason.
                    event("identity_skipped", in_scope=None)
                    continue
    except PlanStopped as stopped:
        status = stopped.code
    except KeyboardInterrupt:
        status = "interrupted"
    except Exception:
        # Never retain exception messages anywhere public.
        status = "execution_failed"
    if audit_stream is None:
        open_audit()
    event(status)
    goal_status = "established" if goal_reached else "not_established"
    report = {"header": header, "events": events, "executed_path": path,
              "status": status, "goal_status": goal_status, "goal_reached": goal_reached}
    try:
        write({"status": status, "goal_status": goal_status,
               "goal_reached": goal_reached, "executed_path": path})
    finally:
        audit_stream.close()
    return report


class _LoopHalt(BaseException):
    """Unwind BOTH loop levels on a terminal event (goal reached / rollback halt /
    kill / budget). Carries the PUBLIC status code only."""
    def __init__(self, code):
        self.code = code


def _pop_frontier(frontier):
    """DA-adjacent first (machine accounts), else FIFO -- cycle-safe via visited."""
    for i, identity in enumerate(frontier):
        if identity.machine:
            return frontier.pop(i)
    return frontier.pop(0)


def _enumerate_into_fence(ctx, admission, fence, enum_domains):
    """Materialize ``--scope-enumerate`` domains into the host fence via the fenced
    DC (same read + parse as the dry-run planner); fail-closed and secret-safe."""
    for domain in sorted(enum_domains):
        admission.check()
        res = probes._ldap_query(ctx, "(objectClass=computer)", ["dNSHostName"])
        admission.check()
        if res.returncode == 0 and not res.error and not res.timed_out:
            for line in (res.stdout or "").splitlines():
                if re.search(r"\[[-+*]\]", line):
                    continue
                match = re.search(r"\bdNSHostName(?:\s*[:=]\s*|\s+)(\S+)\s*$", line, re.I)
                host = host_name(match[1]) if match else None
                if host and host.endswith('.' + domain):
                    fence.enumerated_hosts.add(host)


def _rollback_status(ctx):
    """``(applied, verified)`` of the just-executed hop's mutation. The loop
    advances ONLY when a mutation that WAS applied is also ``rollback.verified``."""
    artifact = getattr(ctx, "_last_artifact", None) or {}
    mutation = artifact.get("mutation") or {}
    applied = bool(mutation.get("applied"))
    verified = (mutation.get("rollback") or {}).get("verified") is True
    return applied, verified


def _run_identity_hops(ctx, active_cfg, fence, admission, goal, params,
                       verdicts, store, frontier, visited, event, path):
    """Execute every eligible, goal-directed, fully-fenced hop for one identity.

    Returns True iff the goal was reached. Raises :class:`_LoopHalt` to stop the
    whole run on a dirty rollback, a kill/budget stop, or an interrupt mid-hop."""
    principal = active_cfg.username or ""
    for verdict in verdicts or []:
        admission.check()                              # kill/budget BEFORE each hop
        if not getattr(verdict, "eligible_for_autoexploit", False):
            continue
        technique = getattr(verdict, "technique", None)
        host = getattr(verdict, "host", None)
        executor = get_executor(technique)
        if executor is None:
            continue
        # Greedy toward the goal: a hop that GAINS a new identity or REACHES the goal.
        reaches_goal = goal in executor.eff
        if not (executor.recovers_credentials or reaches_goal):
            continue
        finding = NormalizedFinding(source={}, finding_id="autopwn-" + str(technique),
                                    host=host, technique=technique,
                                    technique_class=executor.technique_class, entity={})
        overrides = params.get(technique, {})
        specs = executor.param_specs(ctx, finding)
        vals = {s.name: overrides.get(s.name, s.recommended) for s in specs}
        # Fence EVERY resolved destination at dispatch; out-of-fence -> never run.
        destinations = resolved_destinations(active_cfg, finding, specs, vals)
        outside = [h for h in destinations if not fence.contains(h)]
        if outside:
            for dest in outside:
                event("skipped_out_of_scope", technique=technique,
                      target=host_name(dest), in_scope=False)
            continue
        admission.expand()                             # budget: count the hop
        event("executed_hop", technique=technique, target=host, in_scope=True)
        collected = []
        ctx.on_capabilities = lambda caps: collected.extend(c for c in caps if c is not None)
        try:
            receipt = executor.run(ctx, finding, overrides=overrides)
        except BaseException as exc:                   # noqa: BLE001 -- interrupt mid-hop
            # The hardened rollback already ran inside run(); inspect its result,
            # audit the rollback status, and HALT -- never advance on dirty state.
            applied, verified = _rollback_status(ctx)
            event("hop_interrupted", technique=technique, target=host,
                  rollback=("not_applicable" if not applied else
                            "verified" if verified else "dirty"))
            raise _LoopHalt(exc.code if isinstance(exc, PlanStopped) else "interrupted")
        applied, verified = _rollback_status(ctx)
        rollback = ("not_applicable" if not applied else "verified" if verified else "dirty")
        complete = bool(receipt.get("complete"))
        path.append({"technique": technique, "target": host, "principal": principal,
                     "mutating": bool(executor.mutating), "rollback": rollback,
                     "complete": complete, "reached_goal": reaches_goal and complete})
        event("hop_result", technique=technique, target=host, rollback=rollback,
              in_scope=True)
        # Advance ONLY on a verified rollback; a dirty mutation HALTS the loop.
        if applied and not verified:
            event("rollback_dirty_halt", technique=technique, target=host, rollback="dirty")
            raise _LoopHalt("rollback_halt")
        # Collect produced credentials (Phase 2 store) and extend the frontier.
        try:
            store.upsert(collected)
        except Exception:
            pass                                       # store errors stay private
        for cap in collected:
            if isinstance(cap, Credential) and cap.secret and cap.principal:
                domain = cap.domain or active_cfg.domain
                key = (cap.principal.casefold(), (domain or "").casefold())
                if key not in visited:
                    selector = f"{cap.principal}@{domain}" if domain else cap.principal
                    frontier.append(_Identity(selector, cap.principal, domain,
                                              machine=bool(cap.is_machine)))
        if reaches_goal and complete:
            event("goal_reached", technique=technique, target=host, in_scope=True)
            return True
    return False
