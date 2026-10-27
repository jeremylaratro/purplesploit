## TURN 8 — codex — 26OCT2026

### Q14 — CWP1 fold-in

The common contract now lives in the untracked CWP1 file `python/purplesploit/core/execution.py`: `ExecutionRequest` at lines 33–66, `Observation` at 76–104, and `ExecutionResult` at 107–148; the tracked package export was added at `python/purplesploit/core/__init__.py:10,20-23`. *(measured; recorded: `python/purplesploit/core/execution.py:33-148@c962994+CWP1`; `python/purplesploit/core/__init__.py:10,20-23@c962994+CWP1`)*

The provenance fold-in is incomplete: `Observation` has only the generic `attributes` bag at line 84, and the current Aranum importer places `source_tool`, `source_id`, `source_schema`, and `raw` inside that bag. `ExecutionResult` separately has `tool`, `tool_version`, and `raw_result`; `ExecutionRequest` has no provenance or authentication-context field. *(recorded: `python/purplesploit/core/execution.py:34-49,77-91,107-131@c962994+CWP1`; `python/purplesploit/interop/aranum.py:151-179@c962994+CWP1`)*

The exact CWP1 attachment should be:

| Record | Attachment |
|---|---|
| `ExecutionRequest` | Add `auth_context` immediately after `options/options_locked` at `core/execution.py:37-38`. It records the account context deliberately bound to that request. Do not add a parallel top-level account `scope`; it is `auth_context.scope`. *(inferred)* |
| `ExecutionResult` | Add `auth_context` beside `tool`/`tool_version` at `core/execution.py:125-131`, before `observations`/`raw_result`, and copy it from the request for every result outcome. Existing `tool`, `tool_version`, and `raw_result` remain the execution-level provenance carriers. *(inferred; recorded: `python/purplesploit/core/execution.py:125-131@c962994+CWP1`)* |
| `Observation` | Promote `source_tool`, `source_tool_version`, `source_schema`, `source_id`, and JSON-compatible `raw` from `attributes` into first-class fields immediately after `attributes` at `core/execution.py:84`; add first-class `auth_context` beside them, before `source_execution_id`. Keep `attributes` for producer-specific extensions. *(inferred; recorded: `python/purplesploit/core/execution.py:76-91@c962994+CWP1`; `python/purplesploit/interop/aranum.py:166-179@c962994+CWP1`)* |

The shared `auth_context` shape should be `{account_ref, scope, domain, local_host, auth_method}`, with `scope ∈ {local, domain, machine}` and `auth_method ∈ {password, hash, kerberos, null-session, anonymous}`; `domain` applies to domain/machine scope and `local_host` to local scope. Define it once immediately before `ExecutionRequest` around `core/execution.py:32`, then reuse that type in all three records. *(inferred)*

There must not be a standalone account `scope` on `Observation`: Aranum already has an unrelated observation scope—host/domain/run and posture subject scope—currently preserved through `attributes`/`raw` at `interop/aranum.py:218-229`. Nesting the account value as `auth_context.scope` prevents those two meanings from colliding. *(recorded: `python/purplesploit/interop/aranum.py:218-229@c962994+CWP1`; inferred)*

The carrying path is:

- `Framework._complete_module_results` must copy `request.auth_context` into the result where it already copies request/correlation/engagement identity at `core/framework.py:449-456`; the early error/rejection constructors at lines 395–409 must do the same. *(recorded: `python/purplesploit/core/framework.py:395-409,449-456@c962994+CWP1`; inferred)*

- `ExternalToolModule.execute_command` must copy it into the process result where the `ExecutionResult` is constructed at `core/module.py:590-594`. *(recorded: `python/purplesploit/core/module.py:583-594@c962994+CWP1`; inferred)*

- `normalize_observations` must preserve an explicitly emitted observation context and otherwise default it from `request.auth_context` alongside the existing request/module defaults at `core/execution.py:230-243`. It must not infer account scope or method from `DOMAIN`, username shape, or which credential option happens to be populated. *(recorded: `python/purplesploit/core/execution.py:230-243@c962994+CWP1`; inferred)*

- Existing `to_dict`/`from_dict` boundaries at `core/execution.py:59-66,99-104,138-148` must round-trip the context. That automatically carries it through distributed request/result serialization at `distributed/coordinator.py:81-90,152-166,186-200`, agent execution at `distributed/agent.py:77-99`, and assessment storage at `core/assessment.py:710-728`. *(recorded: cited files/lines@c962994+CWP1; inferred)*

The credential model is currently split across three representations rather than one authoritative class. All three must receive the carrying fields. *(measured)*

- The runtime credential is a dictionary managed by `CredentialManager` at `core/session.py:370-395`; `Framework.add_credential` constructs it at `core/framework.py:766-802`. Add top-level `account_ref`, `scope`, and `local_host` there; retain the existing top-level `domain`. `CredentialManager.modify` must admit them at `core/session.py:477-493`, while its existing export/import preserves dictionary fields at lines 533–548. *(recorded: cited files/lines@c962994+CWP1; inferred)*

- The legacy SQLite credential row is declared at `core/database.py:152-167`. Add explicit `account_ref`, `scope`, and `local_host` columns, corresponding migrations beside `core/database.py:301-319`, and parameters/INSERT columns at `core/database.py:560-588`. `metadata` should not be the authoritative carrier for these fields. *(recorded: `python/purplesploit/core/database.py:152-167,301-319,560-588@c962994+CWP1`; inferred)*

- The SQLAlchemy/API credential is `models/database.py:33-55`, with request/response schemas at lines 169–188. Add `account_ref`, `scope`, and `local_host` to the ORM model, `to_dict`, `CredentialCreate`, and `CredentialResponse`; pass them through framework startup synchronization at `core/framework.py:128-159`, persistence at lines 890–905, and API create/update/response paths at `api/server.py:390-400,433-481`. *(recorded: cited files/lines@c962994+CWP1; inferred)*

No stable cross-store account reference exists today: the legacy database has a local integer `id`, while the ORM uses mutable `name` as its primary key and the framework auto-generates that name at `core/framework.py:784-796`. Therefore `account_ref` should be an explicit stable credential-record field rather than overloading either existing identifier. *(recorded: `python/purplesploit/core/database.py:154-165`; `python/purplesploit/models/database.py:33-44`; `python/purplesploit/core/framework.py:784-796@c962994+CWP1`; inferred)*

The current duplicate/upsert identities—`username + domain` in `core/session.py:387-391` and `models/database.py:433-436`—would collapse same-named local accounts on different hosts. They should use `account_ref`, with `(username, scope, domain, local_host)` as the record’s account identity fields; this is storage fidelity, not CWP2 reuse/graph derivation. *(recorded: `python/purplesploit/core/session.py:387-391`; `python/purplesploit/models/database.py:429-446@c962994+CWP1`; inferred)*

`auth_method` belongs to each `auth_context`, not to the credential record, because it describes how that particular execution/result was obtained. *(inferred)*

For finding projection, use the existing `Finding.metadata` carrier at `core/findings.py:170,313-319`, following the existing `metadata["source_observation"]` precedent at `interop/importers.py:260-264`; the serialized source observation then carries the same `auth_context` without adding another finding-specific account model. The direct Aranum projection at `interop/aranum.py:202-208` should use that same source-observation metadata field. *(recorded: cited files/lines@c962994+CWP1; inferred)*

No reuse relationship, effective-on-host edge, or graph finding is part of this placement; only the credential fields, stable reference, and request/result/observation carrying context belong in this fold-in. *(inferred)*

No files were edited. *(measured)*