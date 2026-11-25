"""Emit ``adlab.plan003.proof.v1`` proof-observation receipts.

This module is purplesploit's side of the PLAN-003 proof contract. A
``ValidationExecutor`` proves one technique against a target and records a
*non-secret success predicate*; this module turns that into the strict
``adlab.plan003.proof.v1`` receipt that ad-lab-harness' ``adlab.score_proof``
grades against the reviewed ``adlab.plan003.proof-truth.v1`` facet
(proved / not-proved / inconclusive).

The shape produced here is deliberately identical to what the harness-side
adapter ``adlab.proof_adapters.from_chain_artifact`` emits, so a receipt written
by purplesploit is directly scoreable without a translation step. The harness
remains the independent judge: nothing here decides proved/not-proved, and a
missing terminal fact yields a receipt the scorer reads as not-proved /
inconclusive, never proved. ``exit 0 is never proof`` -- only the recorded
terminal predicate is.

Separation of duties: recovered credential / hash / key / cert material is
dropped (:func:`scrub`) so a proof receipt can never carry a secret. It holds
vulnerable-entity identities and non-secret success predicates only.

Python stdlib only; no LLM. Cross-refs: claude-mem #66146 (recipes),
#66119 / #66120 (proof-chain scope), ad-lab-harness ``adlab/score_proof.py`` +
``adlab/proof_adapters.py`` (the authoritative schema).
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Iterable, Mapping

# The receipt schema string the scorer keys on (must match score_proof.PROOF_SCHEMA).
PROOF_SCHEMA = "adlab.plan003.proof.v1"

# The controlled terminal-fact vocabulary a proof may assert (one per chain).
# Mirrors adlab.proof_adapters.TERMINAL_KINDS exactly.
TERMINAL_KINDS = frozenset({
    "authn_success", "secret_recovered", "rbcd_access",
    "cert_issued_and_used", "file_write_readback", "replication_dump",
})

# Classifier gate verdicts an executor may record for a gated op.
GATE_CLASSIFIERS = frozenset({"approved", "denied", "not_required"})

# Substrings marking a field as carrying recovered secret material. Any such
# field is dropped so a receipt holds identities + non-secret predicates only.
_SECRET_MARKERS = (
    "password", "passwd", "pwd", "secret", "hash", "ntlm", "nthash",
    "aeskey", "aes", "krbtgt", "plaintext", "cleartext", "pfx", "pem",
    "privkey", "private_key", "ccache", "laps_value", "laps_pw", "ticket",
)


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return True
    token = key.casefold()
    return any(marker in token for marker in _SECRET_MARKERS)


def scrub(mapping: Any) -> dict:
    """Return a copy of ``mapping`` with any secret-bearing key dropped."""
    if not isinstance(mapping, Mapping):
        return {}
    return {key: value for key, value in mapping.items() if not _is_secret_key(key)}


def proof_token(*parts: Any) -> str:
    """A deterministic, non-secret proof token from public predicate parts.

    Used as ``terminal_fact.proof_token`` -- the scorer requires a non-empty
    string token. It is a digest of public identifiers (technique, target,
    impersonated principal, a success marker), never of a recovered secret.
    """
    joined = "|".join("" if p is None else str(p) for p in parts)
    return hashlib.sha256(joined.encode("utf-8", "replace")).hexdigest()


def build_terminal_fact(kind: str, *, predicate: str | None = None,
                        proof_token: str | None = None,
                        impersonated: str | None = None,
                        ok: bool = True, extra: Mapping | None = None) -> dict | None:
    """Assemble one terminal fact. Unknown kind -> ``None``; never holds a secret.

    ``ok`` is the executor's recorded success predicate, passed through verbatim
    (a recorded failure stays ``ok=False`` so the scorer calls it a negative
    predicate, not a missing one). ``extra`` fields are scrubbed before merge.
    """
    if kind not in TERMINAL_KINDS:
        return None
    fact: dict[str, Any] = {"kind": kind, "ok": bool(ok), "redacted": True}
    if isinstance(predicate, str) and predicate.strip():
        fact["predicate"] = predicate
    if isinstance(proof_token, str) and proof_token.strip():
        fact["proof_token"] = proof_token
    if isinstance(impersonated, str) and impersonated.strip():
        fact["impersonated"] = impersonated
    for key, value in scrub(extra).items():
        fact.setdefault(key, value)
    fact["redacted"] = True
    return fact


def normalize_steps(raw: Iterable[Mapping] | None) -> list[dict]:
    """Keep only ``{name, ok}`` per step; ``ok`` is strict-``True`` only."""
    steps: list[dict] = []
    if not isinstance(raw, (list, tuple)):
        return steps
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        name = item.get("name")
        steps.append({"name": str(name) if name is not None else None,
                      "ok": item.get("ok") is True})
    return steps


def normalize_gate(raw: Mapping | None) -> dict:
    gate = {"classifier": "not_required", "op": None}
    if isinstance(raw, Mapping):
        classifier = raw.get("classifier")
        if classifier in GATE_CLASSIFIERS:
            gate["classifier"] = classifier
        op = raw.get("op")
        if isinstance(op, str):
            gate["op"] = op
    return gate


def normalize_mutation(raw: Mapping | None) -> dict:
    mutation = {"applied": False,
                "rollback": {"performed": False, "method": None, "verified": False}}
    if isinstance(raw, Mapping):
        mutation["applied"] = raw.get("applied") is True
        rollback = raw.get("rollback")
        if isinstance(rollback, Mapping):
            mutation["rollback"]["performed"] = rollback.get("performed") is True
            method = rollback.get("method")
            if isinstance(method, str):
                mutation["rollback"]["method"] = method
            mutation["rollback"]["verified"] = rollback.get("verified") is True
    return mutation


def empty_receipt(technique: str | None, cls: str | None, *, target: Mapping | None = None,
                  candidate: Mapping | None = None, executor: Mapping | None = None) -> dict:
    """A receipt with no steps, no terminal fact, marked incomplete."""
    return {
        "schema": PROOF_SCHEMA,
        "technique": str(technique) if technique is not None else None,
        "class": str(cls) if cls is not None else None,
        "target": dict(target) if isinstance(target, Mapping) else {},
        "candidate": scrub(candidate),
        "executor": scrub(executor),
        "steps": [],
        "terminal_fact": None,
        "mutation": {"applied": False,
                     "rollback": {"performed": False, "method": None, "verified": False}},
        "gate": {"classifier": "not_required", "op": None},
        "complete": False,
        "errors": [],
    }


def build_receipt(*, technique: str | None, cls: str | None, target: Mapping | None,
                  steps: Iterable[Mapping] | None = None, gate: Mapping | None = None,
                  mutation: Mapping | None = None, terminal_fact: Mapping | None = None,
                  complete: bool = False, candidate: Mapping | None = None,
                  executor: Mapping | None = None, errors: Iterable[str] | None = None) -> dict:
    """Assemble a strict ``proof.v1`` receipt from an executor's loose artifact.

    A terminal fact is written only when it names one of :data:`TERMINAL_KINDS`
    and carries a non-empty ``proof_token``; otherwise the receipt carries no
    terminal fact and records ``terminal_fact_absent`` -- a proof is never
    invented. Secret-bearing fields are dropped throughout.
    """
    receipt = empty_receipt(technique, cls, target=target,
                            candidate=candidate, executor=executor)
    receipt["steps"] = normalize_steps(steps)
    receipt["gate"] = normalize_gate(gate)
    receipt["mutation"] = normalize_mutation(mutation)
    receipt["errors"] = [str(e) for e in (errors or [])]
    if isinstance(terminal_fact, Mapping) and terminal_fact.get("kind") in TERMINAL_KINDS:
        reserved = ("kind", "predicate", "proof_token", "impersonated", "ok", "redacted")
        fact = build_terminal_fact(
            terminal_fact.get("kind"),
            predicate=terminal_fact.get("predicate"),
            proof_token=terminal_fact.get("proof_token"),
            impersonated=terminal_fact.get("impersonated"),
            ok=terminal_fact.get("ok", True),
            extra={k: v for k, v in terminal_fact.items() if k not in reserved},
        )
        receipt["terminal_fact"] = fact
        if not (fact and fact.get("proof_token")):
            receipt["errors"].append("terminal_fact_token_missing")
    else:
        receipt["errors"].append("terminal_fact_absent")
    receipt["complete"] = complete is True
    return receipt


def write_receipt(receipt: Mapping, path: str | os.PathLike) -> Path:
    """Write a receipt to ``path`` as pretty JSON (atomic replace)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(receipt, handle, indent=2, sort_keys=True, ensure_ascii=True)
            handle.write("\n")
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return path
