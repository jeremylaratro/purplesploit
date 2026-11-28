# ADR-003 — Universal credential producers → recursive autopwn-to-DA (27NOV2026)

**Status:** Proposed (north-star direction; owner-endorsed 27NOV2026)
**Extends:** ADR-002 (bulletproof hardening + DA-chaining). **Subsumes:** the `--show-flag` F2
capture work into a single contract (Phase 1 below).
**Owner directive (verbatim):** "I want everything we find to be a producer — whether that is
simply saving a new user:credential pair or a machine:hash pair, etc. It should all be usable
whether manually operator directed, or automated via scan/find/act. Eventually, I want it all to
be chainable — the north star we are working towards."

## Context — where we are

- **17 of 30 executors `produce()` a capability; 13 do not.** Even among producers, the chain
  engine threads only a few typed channels downstream (`ccache` / `nt_hash` / `aes_key` /
  `krbtgt` / `control`). **`CAP_PASSWORD` (cleartext/cracked creds) is NOT threaded** at all.
- **`discover` / `recon` are hardwired to `cfg.username`** — there is no way to re-scan "from a
  newly-gained identity's perspective."
- Consequence (verified): a cracked KERBEROAST account, a LAPS password, a looted `.env` secret
  are **chaining dead-ends** — recovered, used in-process for the proof, then dropped. You cannot
  pivot off them, manually or automatically.
- The chain engine itself is real and works for typed-artifact pivots (DCSYNC krbtgt → ticket
  forge; ESC8/CERTIFRIED DC-TGT → DCSYNC). The gap is **coverage + cleartext creds + identity
  re-scope + a driver**, not the core chaining idea.

## Decision — the Universal Credential-Producer Contract

**Every technique that recovers credential material emits it as one standardized `Credential`
capability, captured AT RECOVERY TIME** — before any ticket/key cleanup, on BOTH the standalone
and composed branches, and REGARDLESS of whether a downstream proof later succeeded. One capture,
three consumers. No technique that recovers a secret is a non-producer; pure write/detection
primitives produce nothing (correctly).

### The `Credential` artifact (standardized)

```
Credential {
  principal        # e.g. "svc_sql" or "CASTELBLACK$"
  domain           # realm the cred is valid in
  is_machine       # user vs machine account
  secret_type      # password | nthash | aeskey | ccache | pfx
  value            # the secret material (runtime-only; never serialized to a receipt)
  source_technique # which edge produced it
  provenance       # how it was obtained (for the audit trail)
  reach_hint       # optional: hosts/targets this identity is known to reach
}
```
It maps onto the existing `Capability` (extend the secret channels; add the cred metadata). Secret
handling is unchanged: the `value` is runtime-only, never in a receipt/proof_token/memory — the
same invariant `--show-flag` already enforces.

### Three consumers of the same capture

1. **Reveal** (`--show-flag`): prints the cred to the terminal-only sink (Phase 0).
2. **Manual credential store** (a vault): the operator lists gained creds and runs any technique
   **as** a selected identity — operator-directed multi-identity workflows.
3. **Automated chaining**: the engine threads the cred (incl. new `CAP_PASSWORD` routing) to
   re-scope the session identity for the next hop.

## The north star — recursive autopwn-to-DA

```
start identity = operator creds
frontier = { start identity }
until  S_DA reached  OR  no new progress  OR  budget exhausted:
    identity   = frontier.pop()               # breadth/priority order
    findings   = discover(AS identity)         # scan from THIS identity's perspective
    hop        = select_next(findings)         # toward DA (greedy, then BloodHound-optimal)
    result     = execute(hop, AS identity)     # gated, rollback-disciplined
    newcreds   = result.produced_credentials   # the universal contract
    frontier  += newcreds  (minus visited)     # cycle-safe
report the path foothold → DA
```

## Phased roadmap (each phase independently valuable)

- **Phase 0 — `--show-flag` reveal mechanism** *(in progress)*: terminal-only sink, `revealed_secrets()`
  hook, CLI flag, the invariant gate. The *reveal* consumer.
- **Phase 1 — Universal Credential-Producer Contract**: the standardized `Credential` capability;
  every secret-recovering technique produces it **at recovery time** (fixes the composed-only /
  post-cleanup bug Codex flagged; **subsumes `--show-flag` F2**). Deliverable: reveal-coverage for
  ALL techniques + a chainable cred artifact from each.
- **Phase 2 — Credential store + manual use**: a session credential vault (list / select); run any
  technique AS a stored identity. Unlocks operator-directed multi-identity work with no loop yet.
- **Phase 3 — Identity re-scope everywhere**: `discover` / `recon` / every executor accept a
  gained identity instead of only `cfg.username`; thread `CAP_PASSWORD` and new creds. The
  pervasive auth-resolution change (the biggest lift).
- **Phase 4 — The autopwn driver**: the greedy recursive loop + frontier / visited / termination /
  budget — **safety-fenced** (dry-run default, per-hop gate, `--yes --allow-destructive` to
  auto-execute, scope fence). The novel orchestration.
- **Phase 5 — Path optimization**: BloodHound-informed shortest-path-to-DA selection (optional
  polish over greedy).

**Rough sizing:** Phase 1 ≈ 1-2 sprints (reuses Phase 0), Phase 2 ≈ 1, Phase 3 ≈ 2-3 (the lift),
Phase 4 ≈ 2, Phase 5 ≈ 2-3. ≈ 6-9 sprints to a greedy autopwn-to-DA; +2-3 for BloodHound-optimal.

## Safety (non-negotiable for Phase 4)

Autonomous multi-hop execution of **mutating** techniques (RBCD writes, password resets, cert
issuance, GPO abuse) to reach DA is high-risk. Guardrails, all mandatory before any auto-execute:
- **Scope fence** — an explicit allow-list of targets/domains; nothing acts outside it.
- **Per-hop gate + authorizer** (reuse the existing gate model) and **verified rollback per
  mutating hop** (reuse proof.v1 — an unverified rollback scores the hop inconclusive and the loop
  halts).
- **Dry-run by default**; auto-execute only on explicit opt-in. **Hop + wall-clock budget.**
- **IOC/kill-switch** and a full path audit trail. Irreversible ops (password reset) flagged and
  confirmed.

## Risks / open questions

- **Identity re-scope breadth** (Phase 3) — pervasive; the single biggest technical risk.
- **Blast radius** of autonomous mutation — as much policy as code (see Safety).
- **Live-proof reliability compounds** across hops (single-hop lab flakiness already seen).
- **The credential vault holds live secrets** — must be access-controlled, memory-only or
  operator-encrypted, and NEVER in a receipt/report/claude-mem (same invariant as `--show-flag`).
- **Termination / cycles / path explosion** — frontier + visited discipline.

## Relationship to the queue

Phase 0 (`--show-flag`) finishes first (it is the capture foundation). Recommended: **Phase 1-2 of
this ADR before ligolo/dispersal** (ligolo/dispersal are the pivot-transport layer this loop will
eventually drive). ADCS T2 is independent and can interleave. Final sequencing is the owner's call.
