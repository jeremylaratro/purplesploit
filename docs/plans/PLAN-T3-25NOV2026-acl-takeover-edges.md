STATUS: DONE

# PLAN-T3 (25NOV2026) — ACL / object-takeover edges

**Status:** DRAFT → 1 independent review → build → probe → prove (on re-configurable GOAD, later).
**Scope of this document:** design only, no code. Touches only `docs/plans/` (this file). Every
file/function/marker named below lives under `python/purplesploit/validation/**` and is a
*proposal* for the next (execution) session to implement — nothing in the worktree is modified here.

## 0. What T3 is, and the GENERIC-ALL decision

T3 adds the ACL / object-takeover edges — the BloodHound-style edges the roadmap
(`docs/plans/PLAN-NEWTECH-25NOV2026-technique-expansion-roadmap.md`, T3 row) calls "the biggest
composition win" for the chaining engine. The brief lists 8 line items; I kept **7 distinct
executor classes** (not 8), because item 8 is a conditional instruction ("if you judge GENERIC-ALL
should be split by pivot, call out the extra executors"), not an 8th named technique — the brief's
own technique list only names 7 (GENERIC-ALL/GENERIC-WRITE, WRITE-DACL, WRITE-OWNER,
FORCE-CHANGE-PASSWORD, ADD-MEMBER/ADD-SELF, TARGETED-KERBEROAST, GPO-ABUSE).

**Decision: GENERIC-ALL stays ONE executor** with a `pivot` param (4 choices), not split into 4.
Justification: 3 of its 4 pivot actions are *mechanically identical* to techniques that already
exist or are separately specced in this same tranche — writing `msDS-KeyCredentialLink` (=
SHADOW-CREDS, already shipped T1b), writing `msDS-AllowedToActOnBehalfOfOtherIdentity` (= RBCD,
already shipped full), and writing a victim's SPN then roasting it (= TARGETED-KERBEROAST, item 6
below). Splitting GENERIC-ALL into 4 classes would mean 3 of them duplicate other items on this
same list almost line-for-line — that inflates the executor count without adding real technique
coverage, which is the opposite of what item 8's "keep total ~8" is guarding against. Instead,
GENERIC-ALL's own, *non-duplicated* value is the thing none of the other techniques do: a
**positive, non-destructive confirmation of the specific GenericAll/GenericWrite ACE** before
pivoting (closing the gap `RbcdProbe`/`ShadowCredsProbe` both explicitly leave as `unknown`/
"ASSUMED ... not readable without BloodHound" — T3 can close it because, unlike RBCD/SHADOW-CREDS,
a GENERIC-ALL finding *is itself* a reported ACL edge, so there is a concrete trustee+target to
re-confirm via `dacledit.py -action read`, the new tool this tranche is explicitly allowed). Its
4 pivot bodies are self-contained (not inter-executor delegation — see §1.1 rationale), reusing only
plain constants/regexes by import, exactly as `certifried.py` already imports `machine_account`/
`_short_name` from `coercion.py`.

Files read (STEP 2, confirmed against the actual tree): `executors/base.py`, `executors/shadow_creds.py`,
`executors/rbcd.py`, `executors/roast.py`, `executors/certifried.py`, `proof.py`, `states.py`,
`probes.py` (full registry + `RbcdProbe`/`KerberoastProbe`/`ShadowCredsProbe`/`ConstrainedDelegProbe`
in detail), `recommend.py`, `predicates.py`, `executors/__init__.py`, plus `orchestrator.py`,
`config.py`, `engine/chain_engine.py`, `engine/__init__.py` (not in the brief's read list, but needed
to design the destructive gate and pre/eff correctly — see §5 for what they already contain).

**Key pre-existing fact that changes the destructive-gate design:** `chain_engine.py`'s
`ChainEngine._edge_allowed` *already* reads `getattr(e, "destructive", False)` and
`getattr(e, "crack_dependent", False)` as hard filters (gated by `allow_destructive`/`allow_crack`
kwargs on `ChainEngine`/`da_in_minutes`) — but **no executor in the tree sets either flag today**.
T3 is the first tranche to actually set `destructive = True` / `crack_dependent = True`, so those
two dormant engine-level filters activate for the first time. This is a *second, static, engine-level*
gate, separate from the *per-call, runtime* warn-press-yes gate the brief's owner decision asks for
(§6) — the two compose (§6.3).

## 1. Technique table

| Technique | Executor class (file) | Tool(s) | terminal_kind | mutating | destructive | pre → eff |
|---|---|---|---|---|---|---|
| GENERIC-ALL / GENERIC-WRITE | `GenericAllExecutor` (`executors/generic_all.py`) | dacledit.py (confirm), bloodyAD, certipy-ad (shadow pivot), impacket-addcomputer/-rbcd/-getST (rbcd pivot), impacket-GetUserSPNs+hashcat (spn pivot), nxc | pivot-dependent: `authn_success` \| `authn_success` \| `secret_recovered` \| `rbcd_access` | yes | **yes** (conservative; only the `reset_password` pivot is actually irreversible — §6.3) | `{S0_USER_CREDS, S_ACL_CONTROL}` → `{S_ACL_CRED, S_IMPERSONATION_TGT}` |
| WRITE-DACL | `WriteDaclExecutor` (`executors/write_dacl.py`) | dacledit.py | `file_write_readback` | yes | no | `{S0_USER_CREDS}` → `{S_ACL_CONTROL}` |
| WRITE-OWNER | `WriteOwnerExecutor` (`executors/write_owner.py`) | owneredit.py, dacledit.py | `file_write_readback` | yes | no | `{S0_USER_CREDS}` → `{S_ACL_CONTROL}` |
| FORCE-CHANGE-PASSWORD | `ForceChangePasswordExecutor` (`executors/force_change_password.py`) | dacledit.py (confirm), bloodyAD, nxc | `authn_success` | yes | **yes** (fixed) | `{S0_USER_CREDS}` → `{S_ACL_CRED}` |
| ADD-MEMBER / ADD-SELF | `AddMemberExecutor` (`executors/add_member.py`) | dacledit.py (confirm), bloodyAD, nxc | `file_write_readback` | yes | no | `{S0_USER_CREDS}` → `{S_ACL_CONTROL}` |
| TARGETED-KERBEROAST | `TargetedKerberoastExecutor` (`executors/targeted_kerberoast.py`) | dacledit.py (confirm), bloodyAD, impacket-GetUserSPNs, hashcat, nxc | `authn_success` | yes | no (**`crack_dependent=True`**) | `{S0_USER_CREDS}` → `{S_ACL_CRED}` |
| GPO-ABUSE | `GpoAbuseExecutor` (`executors/gpo_abuse.py`) | dacledit.py (confirm), nxc (SMB get/put-file), bloodyAD (versionNumber) | `file_write_readback` | yes | **yes** (fixed — code-exec side effect) | `{S0_USER_CREDS}` → `{S_ACL_CONTROL}` |

All 7: `verified_recipe=False` (recipe-known, not lab-proven — same honesty flag as ESC8/ESC11/Certifried).
None implement `teardown()`/composed deferral (`ctx.composed`) — rollback is always immediate (§1.1).

### 1.1 Shared infrastructure (new module, used by all 7)

New module `executors/acl_common.py` (plain functions + regex constants only — no executor
classes, precedented by `process_manager.py` being shared infra, and by `certifried.py` importing
plain helpers from `coercion.py`). Holds the non-destructive ACE/owner read machinery every T3
executor's own precondition-confirm step needs, defined exactly once so parsing rules can't drift
across 7 files:

```python
# UNVERIFIED (pin in-lab): dacledit.py / owneredit.py (impacket) human-readable rights wording.
_RE_DACL_READ_OK      = re.compile(r"(ACCESS[- ]ALLOWED|ace type|ObjectType|Rights\s*:)", re.I)
_RE_ACE_GENERIC_ALL   = re.compile(r"(Generic[- ]?All|Full[- ]?Control)", re.I)
_RE_ACE_GENERIC_WRITE = re.compile(r"Generic[- ]?Write", re.I)
_RE_ACE_WRITE_DACL    = re.compile(r"Write[- ]?Dacl", re.I)
_RE_ACE_WRITE_OWNER   = re.compile(r"Write[- ]?Owner", re.I)
_RE_ACE_SELF_MEMBERSHIP = re.compile(r"Self[- ]?Membership", re.I)
_RE_FORCE_CHANGE_PW_RIGHT = re.compile(
    r"(User-?Force-?Change-?Password|00299570-246d-11d0-a768-00aa006e0529)", re.I)
_RE_OWNER_READ_OK  = re.compile(r"(current owner|owner\s*:|ownersid)", re.I)
_RE_OWNER_VALUE    = re.compile(r"(?:current owner|owner)\s*[:=]\s*(\S.*)", re.I)

def dacledit_read_argv(cfg, target: str, dc: str) -> list[str]: ...
def dacledit_write_argv(cfg, target: str, dc: str, trustee: str, rights: str = "FullControl") -> list[str]: ...
def dacledit_remove_argv(cfg, target: str, dc: str, trustee: str, rights: str = "FullControl") -> list[str]: ...
def owneredit_read_argv(cfg, target: str, dc: str) -> list[str]: ...
def owneredit_write_argv(cfg, target: str, dc: str, new_owner: str) -> list[str]: ...

def confirm_ace(read_res: RunResult, read_text: str, trustee: str,
                right_res: tuple[re.Pattern, ...]) -> Optional[bool]:
    """Tri-state, fail-safe like every probe in this codebase:
    True  -> the read POSITIVELY shows trustee holding >=1 of right_res (sufficient).
    False -> the read POSITIVELY shows trustee's own ACE line, but none of right_res
             match it (positively INSUFFICIENT -- the only state that should abort
             a mutation before it fires).
    None  -> unreadable / trustee's ACE line not located (unknown -- NEVER a false
             negative; callers proceed anyway with an 'advisory:*_unconfirmed' note,
             mirroring RbcdProbe/ShadowCredsProbe's existing fail-open philosophy).
    """
    if _tool_errored(read_res) or not _RE_DACL_READ_OK.search(read_text):
        return None
    trustee_lines = [ln for ln in read_text.splitlines() if trustee.lower() in ln.lower()]
    if not trustee_lines:
        return None
    joined = "\n".join(trustee_lines)
    return any(r.search(joined) for r in right_res)
```

(`_tool_errored` reused from `probes.py` by import, not redefined.) Each T3 executor's own
"confirm precondition" step calls `confirm_ace(...)`; `False` aborts the mutation
(`errors.append("<technique>_not_confirmed")`, `complete=False`); `None` proceeds with
`errors.append("advisory:<technique>_unconfirmed_attempting_anyway")`; `True` proceeds cleanly.
**This 3-way branch (not a 2-way "block unless confirmed") is deliberate** — it is the one place
in this plan where it would be easy to accidentally invert the codebase's house philosophy ("unknown
never skips, only a positive negative does") into a stricter, inconsistent per-executor gate. The
three-way tri-state keeps T3 consistent with every existing probe.

`predicates.py` gets one new helper (the "bind-ok AND absent" idiom already hand-rolled twice —
`rbcd.py`'s `cleared` and `certifried.py`'s `cleared` — and about to recur ~5 more times in T3):

```python
def positive_absence(bind_ok: bool, haystack: str, needle: str) -> bool:
    """bind_ok AND needle not present in haystack -- never vacuous (an errored/empty
    read is never 'absent'); callers supply their own bind-ok determination."""
    return bool(bind_ok) and needle.lower() not in (haystack or "").lower()
```

**Composability scope cut (stated explicitly, not a silent corner-cut):** none of the 7 T3
executors implement `produced()`'s full `Capability`-channel threading or `teardown()`'s composed
deferral. This mirrors the *current, real* state of the original 11 executors (RBCD, SHADOW-CREDS,
etc. — none of which have `pre`/`eff` *or* `produced()` yet either; per `states.py`'s own docstring,
"The existing 11 executors get their pre/eff in the C tranche, not here"). T3 declares `pre`/`eff`
(required by the brief) but, like `cred_for`/`local_admin_for` themselves, the parametrized binding
is for a *future* engine extension, not consumed by `chain_engine.py` today (see §5). Each T3
executor DOES implement a minimal `produced()` returning the *precise* principal-typed state via
`Capability(state=states.cred_for(target)|states.control_for(target), channel=CAP_NONE,
principal=target)` — zero threading logic, pure documentation-for-the-future, consistent with how
`cred_for`'s own docstring says "the engine binds the principal at search time." `teardown()` stays
the base no-op; rollback is **always immediate**, never deferred, for all 7.

## 2. Per-technique design

### 2.1 GENERIC-ALL (`GenericAllExecutor`)

**Params** (`param_specs`):
- `target` (`target_host`, required) — recommended `finding.entity.get("target") or finding.host or ""`. The user/computer the ACL edge is over.
- `pivot` (`free`, `choices=["reset_password","spn_kerberoast","shadow_creds","rbcd"]`, recommended `"shadow_creds"`) — rationale: shadow_creds is the only pivot that is both non-destructive and crack-free; operator overrides per engagement.
- `new_computer` (`computer_name`, recommended `delegation_computer(ctx.config.principal_base)`, used only by the `rbcd` pivot — reused from `recommend.py`).
- `impersonate` (`escalation_target`, recommended `"Administrator"`, `rbcd` pivot only).
- `spn` (`spn`, recommended `recommended_spn("http", target)`, `spn_kerberoast` pivot only).
- `wordlist` (`free`, recommended `roast.DEFAULT_WORDLIST` (imported), `spn_kerberoast` pivot only).

**`plan()` is overridden** (not just `steps_preview`) because `terminal_kind` is pivot-dependent and
the base `ValidationExecutor.plan()` reads the plain class attribute `self.terminal_kind` with no
params in scope at that point:
```python
_PIVOT_TERMINAL = {"reset_password": "authn_success", "spn_kerberoast": "authn_success",
                    "shadow_creds": "secret_recovered", "rbcd": "rbcd_access"}

def plan(self, ctx, finding, overrides=None) -> ValidationPlan:
    params = resolve_params(self.param_specs(ctx, finding), overrides)
    pivot = params["pivot"].value
    return ValidationPlan(technique=self.technique, technique_class=self.technique_class,
        target=self.target_identity(ctx, finding, params), mutating=self.mutating,
        terminal_kind=self._PIVOT_TERMINAL[pivot], params=params,
        steps_preview=self.steps_preview(ctx, finding, params),
        verified_recipe=self.verified_recipe, recipe_ref=self.recipe_ref,
        finding_summary=finding.summary())
```
`target_identity(ctx, finding, params)` is trivially pivot-aware already (base signature takes
`params`): returns `{"domain": domain, "principal": target}` for `reset_password`/`spn_kerberoast`,
`{"domain": domain, "account": target}` for `shadow_creds` (mirrors `ShadowCredsExecutor` exactly),
`ctx.config.resolve_target_identity(target)` for `rbcd` (mirrors `RBCDExecutor` exactly) — so a
GENERIC-ALL receipt scores against the SAME proof-truth facet the underlying mechanism would.

**Steps (ordered), all pivots share step 0:**
0. `confirm_ace` — `dacledit_read_argv(cfg, target, dc)`; `confirm_ace(res, out, trustee=cfg.username, right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))`.

**`reset_password` pivot** (steps 1–4):
1. **destructive-confirm gate** (§6): `ctx.destructive_confirmer.confirm("generic_all_reset_password", {"target": target})`; denied → `gate.classifier="denied"`, `errors.append("gate_denied:generic_all_reset_password")`, abort.
2. `bloodyAD -d <domain> -u <op> (-p|-H <secret>) --host <dc> set password '<target>' '<newpw>'` (`newpw = secrets.token_urlsafe(18)`, never stored). Marker: `_RE_BLOODYAD_SET_PW_OK = re.compile(r"(successfully set|password (has been )?changed|updated)", re.I)`.
3. `nxc smb <dc> -u <target> -p <newpw>` reauth. Markers: `_RE_NXC_PWNED`/`_RE_NXC_AUTH_OK` (same literals as `roast.py`).
4. **Exact positive success predicate:** `reauth_ok = bool(_RE_NXC_PWNED.search(out) or _RE_NXC_AUTH_OK.search(out))`. `terminal_fact`: kind `authn_success`, `ok=reauth_ok`, `impersonated=target`, `predicate="reset <target>'s password via a confirmed GenericAll/GenericWrite ACE and re-authenticated as them"`, `proof_token=proof.proof_token("GENERIC-ALL","reset_password",domain,target,"authn_success" if reauth_ok else "authn_failed")`.
**Rollback: deliberately NONE** (`mutation.rollback.performed=False, verified=False`); `errors.append(f"advisory:irreversible:original_password_not_recoverable:{target}@{domain}")` — identical honesty pattern to FORCE-CHANGE-PASSWORD (§2.4); this is why this pivot alone requires the destructive-confirm gate.

**`spn_kerberoast` pivot** (steps 1–7): write SPN → roast → crack (gated `offline_crack`, reusing the
existing authorizer op name from `roast.py` for policy continuity) → reauth → **rollback clears the SPN**.
1. `bloodyAD ... set object '<target>' servicePrincipalName -v '<spn>'`. Marker: `_RE_BLOODYAD_SET_OK = re.compile(r"(successfully (set|updated)|attribute.*(updated|set))", re.I)`.
2. `impacket-GetUserSPNs <auth> -dc-ip <dc> -request -request-user '<target>'` → hash via `re.compile(r"\$krb5tgs\$[^\s]+")` (literal, not imported, zero coupling).
3. gate `ctx.authorizer.authorize("offline_crack", {"technique": "GENERIC-ALL", "target": target})`.
4. `hashcat -m 13100 <hashfile> <wordlist> --potfile-path ... --quiet` + `--show --outfile-format 2` extraction (identical shape to `roast.py`).
5. `nxc smb <dc> -u <target> -p <plaintext>` reauth.
6. **Exact positive success predicate:** same reauth marker as above. `terminal_fact` kind `authn_success`.
7. **Rollback:** `bloodyAD ... set object '<target>' servicePrincipalName -v ''` + positive read-back `nxc ldap <dc> <auth> --query "(sAMAccountName=<target_short>)" servicePrincipalName`; `verified = predicates.positive_absence(bind_ok=_RE_ANCHOR-style account-read-ok, haystack=read_text, needle=<the written spn>)` — never vacuous (an errored read never counts as "cleared").

**`shadow_creds` pivot** (steps 1): reuses `ShadowCredsExecutor`'s own exact recipe and markers —
`certipy-ad shadow auto -account '<target>' <auth> -dc-ip <dc>`, importing `_RE_SHADOW_HASH`/
`_RE_SHADOW_RESTORE` directly from `shadow_creds.py` (deliberate cross-module reuse of those two
module-level regexes, so if certipy's wording is later pinned/corrected there, this pivot updates
automatically — no duplicate regex to drift). `terminal_fact` kind `secret_recovered`. **Rollback:**
certipy's own self-restore, `verified=restore_ok` exactly as `shadow_creds.py` already computes it —
nothing extra for GENERIC-ALL to add.

**`rbcd` pivot** (steps 1–4): mirrors `RBCDExecutor`'s own body with `target` playing the role of
`delegate_to`: `impacket-addcomputer` (new `<new_computer>$`) → `impacket-rbcd -action write` (with
the SAME bloodyAD D2 fallback `RBCDExecutor._bloodyad_rbcd_argv` already implements) →
`impacket-getST` S4U → `nxc smb <target> -k --use-kcache`. `terminal_fact` kind `rbcd_access`.
**Rollback:** `impacket-rbcd -action flush` + `-action read` positive-confirmation (`_RE_RBCD_READ_OK`
+ principal-absence, same as `rbcd.py`) + `impacket-addcomputer -delete` — i.e. `RBCDExecutor._rollback`'s
own three-step verified rollback, duplicated inline (modest, orchestration-glue duplication, not
novel logic — see §1.1's "no inter-executor delegation" rationale).

**Probe (`GenericAllProbe`, `probes.py`):** `dacledit_read_argv` read; `confirm_ace(..., right_res=
(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))`. `False` → `viable=False` ("the ACE does not grant
GenericAll/GenericWrite -> skip"). `None`/unreadable → `viable=True, unknown=True` ("ACE unconfirmed
-> attempting anyway", mirroring `RbcdProbe`). `True` → `viable=True`.

**Unit tests (`tests/unit/validation/test_t3_generic_all.py`):**
- GREEN per pivot: a scripted runner keyed on tool+subcommand (same `_key(argv)` pattern as
  `test_n1_certifried.py`'s `_CertipyRunner`) produces a proved-shape receipt for each of the 4 pivots.
- RED `confirm_ace` insufficient: dacledit read shows the operator's own line with only
  `"ReadProperty"` → `complete=False`, `errors` contains `"generic_all_not_confirmed"`, **no mutation
  argv is ever issued** (assert `runner.calls` has no `set password`/`set object`/`shadow`/`rbcd` call).
- GREEN `confirm_ace` unknown: dacledit read times out (`timed_out=True`) → pivot still attempts
  (mutation argv IS issued); `errors` contains `"advisory:generic_all_unconfirmed_attempting_anyway"`.
- RED destructive-confirm denied (`reset_password` only): a scripted `DestructiveConfirmationProvider`
  fake returning `False` → `gate.classifier="denied"`, `complete=False`, `errors` contains
  `"gate_denied:generic_all_reset_password"`; the `bloodyAD set password` argv is **never** issued.
- GREEN destructive-confirm approved: fake returns `True` → proceeds, `gate.classifier="approved"`.
- RED `offline_crack` denied (`spn_kerberoast` only): mirrors `roast.py`'s existing gate-denied test shape.
- RED rollback non-vacuous (`spn_kerberoast`): the post-write LDAP read-back errors (`returncode=None`)
  → `rollback.verified=False` even though the bloodyAD clear call itself reported success — proves
  the rollback cannot be satisfied by the clear step's exit code alone.
- RED/GREEN `rbcd` pivot rollback: mirror `rbcd.py`'s own 3 rollback tests (flush-fail, read-vacuous,
  delete-fail each independently flip `verified=False`).
- `target_identity` test per pivot asserting the facet-matching identity shape documented above.
- `produced()` test: for each pivot, the returned `Capability.state` equals `states.cred_for(target)`
  (reset_password/spn_kerberoast/shadow_creds) or `states.S_IMPERSONATION_TGT` (rbcd).

**Done-criteria:** all 4 pivots proved-shape GREEN; `confirm_ace` tri-state covered (2 RED/unknown +
1 insufficient-abort); destructive gate covered (approve+deny) for `reset_password` only; offline-crack
gate covered for `spn_kerberoast` only; every rollback test proves non-vacuity; `plan()`'s pivot-dependent
`terminal_kind` asserted via `executor.plan(ctx, finding).terminal_kind` for all 4 choices; registered
in `executors/__init__.py` (`REGISTRY["GENERIC-ALL"] = GenericAllExecutor`) and `probes.py`
(`PROBE_REGISTRY["GENERIC-ALL"] = GenericAllProbe`); a `findings.py` `SIGNALS` entry added (rule_id
e.g. `"promoted-acl-generic-all"` or category `"acl"` + an entity extractor populating `target`/`trustee`
— see §7).

---

### 2.2 WRITE-DACL (`WriteDaclExecutor`)

**Params:** `target` (`target_host`, required); `trustee` (`free`, recommended `cfg.username`,
"the principal the self-written ACE names; default = the operator's own account"); `rights` (`free`,
`choices=["FullControl","GenericAll"]`, recommended `"FullControl"`).

**Steps:**
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_DACL))` — the precondition is
   *already* holding WriteDacl/FullControl/GenericAll over `target` (this is what lets you write a
   NEW ACE at all). `False` aborts; `None` proceeds with an advisory.
2. gate `ctx.authorizer.authorize("write_dacl", {"target": target, "trustee": trustee})` (ordinary
   mutating-op gate, same shape as `shadow_creds.py`'s `"shadow_write"`).
3. `dacledit_write_argv(cfg, target, dc, trustee, rights)` → `dacledit.py -action write -ace-type
   grant -rights <rights> -principal '<trustee>' -target '<target>' -dc-ip <dc> <auth>`. Marker:
   `_RE_DACL_WRITE_OK = re.compile(r"(DACL (modified|written) successfully|ace.*(added|written))", re.I)`.
4. **Exact positive success predicate — the technique's own terminal, not a separate "abuse" step:**
   re-read via `dacledit_read_argv` again; `confirm_ace(..., right_res=matching(rights))` must be
   literally `True` (not merely "the write call reported success") for `ok=True`. This is
   `file_write_readback`'s shape exactly: a write, proved by a positive read-back, never by the
   write call's own exit code.
   `terminal_fact`: kind `file_write_readback`, `ok=(confirm_ace(...) is True)`,
   `predicate=f"granted {trustee} {rights} over {target} via a self-written DACL ACE, confirmed by
   a positive DACL read-back"`, `proof_token=proof.proof_token("WRITE-DACL",domain,target,trustee,
   rights,"ace_confirmed" if ok else "ace_unconfirmed")`.

**Verified rollback:** `dacledit_remove_argv(cfg, target, dc, trustee, rights)` → `dacledit.py
-action remove -ace-type grant -rights <rights> -principal '<trustee>' -target '<target>'`; then
re-read once more. **Positive, non-vacuous confirmation:** `verified = bind_ok and (confirm_ace(...,
right_res=matching(rights)) is not True)` — i.e. the post-rollback read must *positively run*
(bind-ok) AND must no longer show `trustee` holding `rights` (covers both "trustee line gone" and
"trustee line present but rights no longer listed", so a pre-existing, unrelated ACE for the same
trustee is never mistaken for "not rolled back"). An errored/empty re-read never counts as verified.

**Probe (`WriteDaclProbe`):** same `confirm_ace` call as step 1; `False`→`viable=False`
("WriteDacl/FullControl/GenericAll not confirmed over target -> skip"); `None`→`unknown=True`.

**Unit tests (`test_t3_write_dacl.py`):** GREEN proved shape; RED `confirm_ace` insufficient (abort,
no `dacledit -action write` ever issued); RED write-gate denied; RED terminal non-vacuous (write
reports success but the re-read shows `rights` absent → `complete=False`, NOT a fabricated proof);
RED rollback non-vacuous (post-remove re-read errors → `verified=False` even though the remove call
itself reported success); GREEN rollback (re-read positively shows `rights` gone for `trustee`).

**Done-criteria:** proved + all 4 RED cases above pass; registered in `REGISTRY`/`PROBE_REGISTRY`;
`findings.py` signal added (category `"acl"`, marker e.g. a line containing `WriteDacl`).

---

### 2.3 WRITE-OWNER (`WriteOwnerExecutor`)

**Params:** `target` (`target_host`, required); `trustee` (`free`, recommended `cfg.username`).

**Steps:**
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_OWNER))`.
2. **Baseline owner read** (captured *before* any mutation, so rollback has something honest to
   restore to): `owneredit_read_argv(cfg, target, dc)` → `owneredit.py -action read -target
   '<target>' -dc-ip <dc> <auth>`; `_RE_OWNER_READ_OK` confirms the read ran;
   `original_owner = _RE_OWNER_VALUE.search(text).group(1)` if matched, else `None` (unreadable
   baseline — recorded, not fatal; see rollback note below).
3. gate `ctx.authorizer.authorize("write_owner", {"target": target, "trustee": trustee})`.
4. `owneredit_write_argv(cfg, target, dc, trustee)` → `owneredit.py -action write -new-owner
   '<trustee>' -target '<target>' -dc-ip <dc> <auth>`. Marker: `_RE_OWNER_WRITE_OK = re.compile(
   r"(owner.*(modified|changed|set) successfully)", re.I)`.
5. **As new owner**, self-grant FullControl: the SAME `dacledit_write_argv(cfg, target, dc,
   trustee="FullControl")` call step 2.3 uses, inlined (modest duplication, same rationale as §1).
6. Re-read via `dacledit_read_argv`; `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL,))`.
**Exact positive success predicate:** `ok = owner_write_ok and (confirm_ace(step6) is True)`.
`terminal_fact`: kind `file_write_readback`, `predicate=f"took ownership of {target}, self-granted
FullControl via DACL write, confirmed by a positive ACE read-back"`, `proof_token=
proof.proof_token("WRITE-OWNER",domain,target,trustee,"owner_and_ace_confirmed" if ok else
"unconfirmed")`.

**Verified rollback — TWO sub-steps, BOTH required for `rollback.verified=True`:**
1. Remove the self-granted ACE (identical to WRITE-DACL's rollback, same non-vacuous predicate).
2. Restore the **original** owner: `owneredit_write_argv(cfg, target, dc, original_owner)` +
   `owneredit_read_argv` again; `verified_owner = bind_ok and (_RE_OWNER_VALUE match == original_owner)`
   — an exact string match against the captured baseline, never "no error" alone.
   **Honest limitation, stated explicitly in the receipt, not hidden:** if `original_owner` could
   not be captured at step 2 (unreadable baseline), the owner half of rollback **cannot** be
   verified by construction — `mutation.rollback.verified=False`,
   `errors.append("advisory:original_owner_unknown_rollback_unverifiable")`. This must never be
   silently reported as `verified=True`.

**Probe (`WriteOwnerProbe`):** same `confirm_ace` shape as step 1 above, `right_res=
(_RE_ACE_GENERIC_ALL, _RE_ACE_WRITE_OWNER)`.

**Unit tests (`test_t3_write_owner.py`):** GREEN proved shape with a captured baseline owner; RED
`confirm_ace` insufficient (abort before touching ownership); RED owner-write gate denied; RED
rollback non-vacuous on EACH of the two sub-steps independently (ACE-removal read errors →
`verified=False`; owner-restore read returns a *different* owner string → `verified=False`); RED
the "unreadable baseline" path specifically — assert the `advisory:original_owner_unknown...` error
string appears and `verified=False`, never `True`.

**Done-criteria:** proved + the 2-of-2 rollback-verification test + the unreadable-baseline honesty
test; registered; `findings.py` signal added (category `"acl"`, marker containing `WriteOwner`).

---

### 2.4 FORCE-CHANGE-PASSWORD (`ForceChangePasswordExecutor`)

**Params:** `victim` (`principal_name`? — note: `recommend.PARAM_KINDS` has no `principal_name`
entry; use kind `"free"` with `description` stating it is a principal name, required, recommended
`(finding.entity or {}).get("principal") or ""`).

This is the destructive reference case the brief's own wording anchors on: "original pw
unrecoverable — see warn gate."

**Steps:**
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_FORCE_CHANGE_PW_RIGHT))` — the
   User-Force-Change-Password extended right (GUID `00299570-246d-11d0-a768-00aa006e0529`) OR
   GenericAll.
2. **destructive-confirm gate** (§6): `ctx.destructive_confirmer.confirm("force_change_password",
   {"victim": victim, "domain": cfg.domain})`; denied → `gate.classifier="denied"`,
   `errors.append("gate_denied:force_change_password")`, **abort before any write**.
3. `bloodyAD -d <domain> -u <op> ... --host <dc> set password '<victim>' '<newpw>'`
   (`newpw = secrets.token_urlsafe(18)`, never stored, never logged). `_RE_BLOODYAD_SET_PW_OK`.
4. `nxc smb <dc> -u <victim> -p <newpw>` reauth. `_RE_NXC_PWNED`/`_RE_NXC_AUTH_OK`.
**Exact positive success predicate:** `reauth_ok = bool(_RE_NXC_PWNED.search(out) or
_RE_NXC_AUTH_OK.search(out))`. `terminal_fact`: kind `authn_success`, `impersonated=victim`,
`proof_token=proof.proof_token("FORCE-CHANGE-PASSWORD",domain,victim,"authn_success" if reauth_ok
else "authn_failed")`.

**Rollback: deliberately none, by design, not a gap.** `mutation.rollback.performed=False,
verified=False`; `errors.append(f"advisory:irreversible:original_password_not_recoverable:
{victim}@{domain}")`. This is honest and intentional: AD never exposes the prior password hash to
an attribute-write caller, so there is nothing to restore. A chain-cleanliness report that reads
this as "not clean" is *correct*, not a bug — exactly why this technique is `destructive=True` and
excluded from `ChainEngine`'s edge list unless `allow_destructive=True` (§5, §6.3).

**Probe (`ForceChangePasswordProbe`):** same `confirm_ace` shape; additionally checks `victim` is a
user, not a computer (`not victim.rstrip().endswith("$")`, mirroring `KerberoastProbe`'s own
computer/MSA exclusion reasoning) — a computer-account target is a positive `viable=False` ("force-
change-password targets a computer account; not a meaningful lateral proof -> skip").

**Unit tests (`test_t3_force_change_password.py`):** GREEN proved shape; RED `confirm_ace`
insufficient (abort, `bloodyAD set password` never issued); RED destructive-confirm denied (same
assertion shape as GENERIC-ALL's `reset_password` pivot test); GREEN destructive-confirm approved;
RED reauth fails (bloodyAD reports success, nxc reauth does not match either marker) →
`complete=False`, `terminal_fact.ok=False` — proves the reset call's own exit code/success marker is
never treated as proof by itself; explicit assertion that `mutation.rollback.performed is False` and
the `advisory:irreversible:...` string is present on **every** run that reaches step 3, success or not.

**Done-criteria:** proved + destructive-gate RED/GREEN + the "no rollback, ever, honestly recorded"
assertion; registered; `findings.py` signal added.

---

### 2.5 ADD-MEMBER / ADD-SELF (`AddMemberExecutor`)

One technique string `"ADD-MEMBER"` covers both — ADD-SELF is simply the default
(`member = cfg.username`); there is zero mechanical difference, so (same reasoning as the
GENERIC-ALL decision) a second class/string would duplicate, not add, coverage.

**Params:** `group` (`free`, required, recommended `(finding.entity or {}).get("group") or ""`);
`member` (`free`, recommended `cfg.username` — i.e. ADD-SELF by default; override to add a
different principal for ADD-MEMBER).

**Steps:**
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE,
   _RE_ACE_SELF_MEMBERSHIP))` — over the **group** object (Self-Membership is the narrowest,
   most-specific right BloodHound actually flags for this edge; GenericAll/GenericWrite also suffice).
2. gate `ctx.authorizer.authorize("add_member", {"group": group, "member": member})`.
3. `bloodyAD -d <domain> -u <op> ... --host <dc> add groupMember '<group>' '<member>'`. Marker:
   `_RE_BLOODYAD_ADD_MEMBER_OK = re.compile(r"(successfully added|added.*to.*group|is a member)", re.I)`.
4. **Exact positive success predicate:** re-read via `nxc ldap <dc> <auth> --query
   "(sAMAccountName=<member_short>)" memberOf`; `ok = _account_read_ok(res, text) and (group.lower()
   in text.lower())` — bind-ok AND the group is positively present in the member's `memberOf`, never
   inferred from the `add groupMember` call's own exit code.
   `terminal_fact`: kind `file_write_readback`, `predicate=f"added {member} to {group}, confirmed by
   a positive memberOf read-back"`, `proof_token=proof.proof_token("ADD-MEMBER",domain,group,member,
   "membership_confirmed" if ok else "membership_unconfirmed")`.

**Verified rollback:** `bloodyAD ... remove groupMember '<group>' '<member>'` + the same `nxc ldap
--query memberOf` read-back; `verified = predicates.positive_absence(bind_ok=_account_read_ok(...),
haystack=text, needle=group)`.

**Probe (`AddMemberProbe`):** `confirm_ace` as above over `group`; additionally a cheap, fail-safe
pre-check: read `member`'s current `memberOf` — if `group` already appears, `viable=False`
("<member> is already a member of <group> -> nothing to add, skip") — avoids offering a vacuous
no-op mutation. Unreadable → `unknown=True` as usual.

**Unit tests (`test_t3_add_member.py`):** GREEN proved shape (ADD-SELF default AND an ADD-MEMBER
override with a different `member`); RED `confirm_ace` insufficient over the group (abort); RED
add-gate denied; RED terminal non-vacuous (the `add groupMember` call reports success but the
`memberOf` re-read omits the group → `complete=False`); RED rollback non-vacuous (post-remove
`memberOf` read errors → `verified=False`); probe test for the "already a member" skip.

**Done-criteria:** proved (both default and override) + all RED cases; registered; `findings.py`
signal added (category `"acl"`, marker containing `AddMember`/`Self-Membership`).

---

### 2.6 TARGETED-KERBEROAST (`TargetedKerberoastExecutor`)

**Params:** `victim` (`free`, required, recommended `(finding.entity or {}).get("principal") or ""`);
`spn` (`spn`, recommended `recommended_spn("http", victim)`, imported from `recommend.py`);
`wordlist` (`free`, recommended `roast.DEFAULT_WORDLIST`, imported); `reauth_target` (`target_host`,
recommended `ctx.config.dc_ip`).

**Steps** (write-SPN → roast → crack → reauth → remove-SPN, i.e. KERBEROAST's own shape plus a
write-the-precondition-myself front and a remove-it-after back):
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))`.
2. gate `ctx.authorizer.authorize("targeted_kerberoast_write_spn", {"victim": victim, "spn": spn})`.
3. `bloodyAD ... set object '<victim>' servicePrincipalName -v '<spn>'`. `_RE_BLOODYAD_SET_OK`.
4. `impacket-GetUserSPNs <auth> -dc-ip <dc> -request -request-user '<victim>'` → hash via
   `re.compile(r"\$krb5tgs\$[^\s]+")` (literal, matching `roast.py`'s `KerberoastExecutor.hash_re`
   but not imported — zero cross-module coupling for a one-line literal).
5. gate `ctx.authorizer.authorize("offline_crack", {"technique": "TARGETED-KERBEROAST",
   "victim": victim})` — reuses the existing `"offline_crack"` op name from `roast.py` so operator
   policy covers both uniformly.
6. `hashcat -m 13100 <hashfile> <wordlist> --potfile-path ... --quiet` + `--show --outfile-format 2`.
7. `nxc smb <reauth_target> -u <victim> -p <plaintext>` reauth.
**Exact positive success predicate:** `reauth_ok = bool(_RE_NXC_PWNED.search(out) or
_RE_NXC_AUTH_OK.search(out))`. `terminal_fact`: kind `authn_success`,
`predicate=f"GenericWrite-wrote an SPN on {victim}, Kerberoasted + cracked it, and re-authenticated
as them"`, `proof_token=proof.proof_token("TARGETED-KERBEROAST",domain,victim,"authn_success" if
reauth_ok else "authn_failed")`.

**Verified rollback:** `bloodyAD ... set object '<victim>' servicePrincipalName -v ''` + `nxc ldap
<dc> <auth> --query "(sAMAccountName=<victim_short>)" servicePrincipalName`;
`verified = predicates.positive_absence(bind_ok=_account_read_ok(...), haystack=text, needle=spn)`.

`crack_dependent = True` (class attribute) — this is the **first** executor in the tree to set it,
activating `ChainEngine`'s dormant `allow_crack` hard filter for the first time (mirrors KERBEROAST's
own `offline_crack` *authorizer* gate, which is a per-call runtime check — `crack_dependent` is the
separate, static, engine-eligibility flag; both apply, independently, same two-layer pattern as
`destructive` in §6.3).

**Probe (`TargetedKerberoastProbe`):** mirrors `KerberoastProbe` closely — `victim` must be a user,
not computer/MSA (`not victim.rstrip().endswith("$")`, positive `viable=False` if it is — 120-char
machine passwords are uncrackable, identical reasoning); PLUS `confirm_ace` over `victim` with
`right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE)`.

**Unit tests (`test_t3_targeted_kerberoast.py`):** GREEN proved shape; RED `confirm_ace` insufficient
(abort before the SPN write); RED write-SPN gate denied; RED `offline_crack` gate denied (mirrors
`roast.py`'s existing gate-denied test); RED crack fails (no plaintext from `--show`) →
`complete=False`; RED rollback non-vacuous (post-clear LDAP read errors → `verified=False`); probe
test for the computer/MSA exclusion.

**Done-criteria:** proved + both gates' RED cases + rollback non-vacuity; registered; `findings.py`
signal added.

---

### 2.7 GPO-ABUSE (`GpoAbuseExecutor`)

The most UNVERIFIED of the 7 (GPO internals — `versionNumber` bump semantics, the Scheduled Tasks
Preference XML shape — are genuinely intricate; flagged loudly, not glossed over, consistent with how
`certifried.py`/`esc8.py` already mark `verified_recipe=False` for similarly intricate recipes).

**Params:** `gpo_guid` (`free`, required, recommended `(finding.entity or {}).get("gpo_guid") or
""`); `dc_host` (`target_host`, recommended `ctx.config.dc_ip`-resolvable FQDN, for the SYSVOL UNC
path); `linked_host` (`target_host`, NOT required, recommended `(finding.entity or {}).get(
"linked_host") or ""` — "one machine linked to the GPO, used only to best-effort VERIFY the task
landed; the technique still fires without it, with a narrower proof — see step 6").

**Steps:**
1. `confirm_ace(..., right_res=(_RE_ACE_GENERIC_ALL, _RE_ACE_GENERIC_WRITE))` over the GPO's AD
   object (`CN={gpo_guid},CN=Policies,CN=System,<domain-DN>`).
2. **destructive-confirm gate** (§6): `ctx.destructive_confirmer.confirm("gpo_abuse_immediate_task",
   {"gpo": gpo_guid, "linked_host": linked_host})`; denied → abort before any SYSVOL write.
3. **Baseline snapshot** (read before any mutation — mirrors WRITE-OWNER's baseline-owner capture):
   `nxc smb <dc_host> <auth> --get-file 'SYSVOL\<domain>\Policies\{<gpo_guid>}\Machine\Preferences\
   ScheduledTasks\ScheduledTasks.xml' <out_dir>/baseline_tasks.xml`. Record whether the GET succeeded
   (file existed — capture its bytes) or not (none existed — baseline is explicitly "absent").
4. Write the malicious `ScheduledTasks.xml` — an **immediate task running as SYSTEM**, payload a
   harmless, uniquely-marked proof command (e.g. `cmd.exe /c whoami > C:\Windows\Temp\
   t3_gpo_abuse_<random marker>.txt`), never a real payload — via `nxc smb <dc_host> <auth>
   --put-file <out_dir>/malicious_tasks.xml 'SYSVOL\...\ScheduledTasks.xml'` (same UNC path).
5. Bump `versionNumber` on the GPO's AD object so clients re-pull: `bloodyAD -d <domain> -u <op> ...
   --host <dc> set object 'CN={<gpo_guid>},CN=Policies,CN=System,<domain-dn>' versionNumber -v
   '<old+N>'` (UNVERIFIED exact machine/user-version split — pin in-lab).
6. **Best-effort exercise, never over-claimed:** if `linked_host` was supplied, poll (bounded by
   `ctx.config.tool_timeout_s`, a plain bounded retry loop — NOT `ProcessManager`, that chassis is
   for long-running listeners, not a short poll) for the marker file via `nxc smb <linked_host>
   <auth> --get-file 'C:\Windows\Temp\t3_gpo_abuse_<marker>.txt'`;
   `exercise_ok = predicates.file_present_nonempty(<fetched path>)`. If `linked_host` was NOT
   supplied, `exercise_ok` stays `False` and `errors.append("advisory:no_linked_host_exercise_not_
   confirmed")` — **the terminal fact is never marked `ok=True` on the strength of the write alone
   when no execution was actually observed.**
**Exact positive success predicate:** `ok = exercise_ok` when `linked_host` given; else `ok = (task
write confirmed AND versionNumber bump confirmed)` with the advisory above always attached so the
weaker proof is never silently indistinguishable from a confirmed one.
`terminal_fact`: kind `file_write_readback`, `predicate=f"deployed an immediate SYSTEM-context
scheduled task via a writable GPO ({gpo_guid})" + (f" linked to {linked_host}, execution confirmed"
if exercise_ok else " -- execution not independently confirmed")`, `proof_token=
proof.proof_token("GPO-ABUSE",domain,gpo_guid,linked_host or "","task_confirmed" if exercise_ok
else "task_deployed_unconfirmed")`.

**Verified rollback — the strongest possible confirmation, byte-identical read-back:**
`nxc smb <dc_host> <auth> --put-file` the **baseline** bytes back to the same UNC path (or, if none
existed originally, a minimal valid empty skeleton `<ScheduledTasks clsid="{CC63F200-7309-4ba0-B154-
A71CD118DBCC}"></ScheduledTasks>`), then `--get-file` once more and **byte-compare** against the
baseline (or confirm the malicious marker string is absent from the restored bytes when no baseline
existed). `verified = (restored_bytes == baseline_bytes) or (marker not in restored_bytes)`.
`versionNumber` is bumped forward **again** (never decremented — AD GPO versioning is monotonic;
stated as an explicit, honest limitation): `errors.append("advisory:gpo_version_number_not_reverted_
monotonic_versioning")`.

**Probe (`GpoAbuseProbe`):** `confirm_ace` over the GPO AD object as step 1. Unreadable/ambiguous →
`unknown=True` (attempt anyway, per contract) — there is no cheap, safe, non-destructive way to
confirm the GPO is actually linked to any computer OU without trusting the aranum/BloodHound finding's
own `entity` (which is exactly how `RbcdProbe`/`ShadowCredsProbe` already handle an unreadable
upstream fact: pass it through, flagged, never silently dropped).

**Unit tests (`test_t3_gpo_abuse.py`):** GREEN proved shape with `linked_host` given (exercise
confirmed); GREEN proved-but-narrower shape with `linked_host` omitted (advisory present, `ok` still
derived honestly); RED `confirm_ace` insufficient (abort before any SYSVOL write); RED destructive-
confirm denied (no `--put-file` ever issued); RED exercise times out / marker file never appears with
`linked_host` given → `complete=False`, never a fabricated `ok=True`; RED rollback non-vacuous
(post-restore `--get-file` returns bytes that still contain the marker → `verified=False`); GREEN
rollback with no baseline (restores to the empty skeleton, verified via marker-absence).

**Done-criteria:** both exercise-confirmed and exercise-unconfirmed shapes proved; destructive-gate
RED/GREEN; byte-identical rollback RED/GREEN; registered; `findings.py` signal added (category
`"gpo"` or `"acl"`, marker containing `WriteGPO`/`GPLink`).

## 3. `states.py` additions

Two new base states (the coarse *shape* used for engine eligibility and abstract reachability —
see §1.1's composability-scope-cut rationale) plus one new parametrized factory, mirroring the exact
docstring convention `cred_for`/`local_admin_for` already use:

```python
# ---- T3 additions ----------------------------------------------------------
# A principal-typed CONTROL state (an ACE/ownership/group-membership/GPO-link the
# operator now holds over SOME principal, not yet typed to a specific one -- the
# coarse SHAPE used for engine eligibility; the precise binding is control_for().
S_ACL_CONTROL = "S_acl_control"

# A principal-typed CREDENTIAL/control-enabling-impersonation state established
# via a T3 ACL pivot (reset-password / targeted-kerberoast / shadow-creds) --
# coarse SHAPE; the precise binding REUSES the EXISTING cred_for(principal)
# (same semantics: "SHADOW-CREDS recovers a victim principal's NT hash ... only
# when the bound principal is a DA/DC equivalent does cred_for(principal) satisfy
# a DCSync/S_DA pre" -- T3's ACL-pivot-recovered credentials are the identical
# case, so no new factory is needed for this half).
S_ACL_CRED = "S_acl_cred"

_CONTROL_PREFIX = "control:"

def control_for(principal: str) -> str:
    """A per-PRINCIPAL CONTROL state (``control:<principal>``) -- mirrors cred_for.

    WRITE-DACL's self-granted ACE, WRITE-OWNER's new ownership, ADD-MEMBER's new
    group membership, and GPO-ABUSE's code-exec-as-SYSTEM on GPO-linked machines
    each bind this to a SPECIFIC principal (a user/computer, a group, or a set of
    GPO-linked hosts). PRINCIPAL-TYPED exactly like cred_for: control_for(X) feeds
    a downstream edge's pre ONLY for that specific X; reaching S_DA requires X
    itself to be DA-equivalent, decided by the consuming edge/engine, NEVER
    assumed here. The engine binds the principal at search time (not yet built --
    see is_state() note below, same forward-looking status as cred_for today).
    """
    return f"{_CONTROL_PREFIX}{principal or ''}"
```

`BASE_STATES` gains `S_ACL_CONTROL, S_ACL_CRED`. `is_state()` gains a third prefix check
(`_is_prefixed(value, _CONTROL_PREFIX)`), `__all__` gains `"S_ACL_CONTROL", "S_ACL_CRED",
"control_for"`.

**Explicitly noted limitation (not a defect to fix in T3):** exactly like `cred_for`/`local_admin_for`
today, `control_for`/the parametrized half of `cred_for`'s T3 use is **not yet consumed by
`chain_engine.py`** — the engine's current `_applicable`/`_thread_caps` match on literal, static,
class-level `pre`/`eff` frozensets, which cannot embed a per-finding principal at class-definition
time. T3 therefore declares `pre`/`eff` using the coarse `S_ACL_CONTROL`/`S_ACL_CRED` shapes (so the
engine's eligibility filter and abstract `search()` work unmodified today, giving WRITE-DACL/
WRITE-OWNER/ADD-MEMBER/GPO-ABUSE → GENERIC-ALL a real, searchable path), and additionally exposes
the *precise* principal-typed binding via each executor's `produced()` (§1.1) so a future engine
extension that binds parametrized states per-finding has the exact value ready to consume without
touching any T3 executor again. This is the same, consistent status `cred_for`/`local_admin_for`
have had since N1 — T3 does not regress it, and does not need to fix it to ship.

## 4. Destructive warn-press-yes confirmation gate

**Owner decision (`PLAN-NEWTECH-25NOV2026...md`, GREENLIT): every destructive op prints a warning
and requires the operator to press `yes` — not a silent `--allow-destructive`.** The T3 brief adds
the precise wrinkle: non-interactive runs can't block on stdin forever, so they need an *explicit*
allow flag. These reconcile as: the interactive press-yes prompt is always attempted first; only when
there is genuinely no interactive input available does an explicit, visible, user-set flag stand in
for it — never a silent default-on bypass.

### 4.1 Mechanism (`base.py` additions)

```python
class DestructiveConfirmationProvider(ABC):
    """Decides whether a destructive (irreversible / code-exec) op may proceed."""
    @abstractmethod
    def confirm(self, op: str, detail: dict[str, Any]) -> bool: ...

class InteractiveDestructiveConfirmer(DestructiveConfirmationProvider):
    """Prints a loud warning; blocks on an EXACT 'yes' typed by the operator.
    Fail-closed on EOF (no input available) -- never silently proceeds."""
    def __init__(self, prompt_fn: Callable[[str], str] = input,
                 warn_fn: Optional[Callable[[str], None]] = None):
        self.prompt_fn = prompt_fn
        self.warn_fn = warn_fn or (lambda s: print(s, file=sys.stderr))

    def confirm(self, op: str, detail: dict[str, Any]) -> bool:
        self.warn_fn(f"\n*** DESTRUCTIVE OPERATION ***\nop: {op}\ndetail: {detail}\n"
                      "This is IRREVERSIBLE and/or executes code on a live host.\n")
        try:
            answer = self.prompt_fn("Type 'yes' to proceed, anything else to abort: ")
        except EOFError:
            self.warn_fn(f"[DESTRUCTIVE] {op}: no input available (EOF) -- refusing (fail closed)")
            return False
        return answer.strip() == "yes"

class NonInteractiveDestructiveConfirmer(DestructiveConfirmationProvider):
    """For headless/automated runs ONLY. Fail-closed: proceeds iff explicitly
    pre-authorized via config.allow_destructive -- never prompts, never silently
    defaults to True. Always prints the warning (visible in logs/output either way)."""
    def __init__(self, allowed: bool, warn_fn: Optional[Callable[[str], None]] = None):
        self.allowed = allowed
        self.warn_fn = warn_fn or (lambda s: print(s, file=sys.stderr))

    def confirm(self, op: str, detail: dict[str, Any]) -> bool:
        self.warn_fn(
            f"[DESTRUCTIVE] {op}: {detail} -- non-interactive run; "
            + ("allow_destructive is set, proceeding" if self.allowed
               else "allow_destructive NOT set, refusing"))
        return self.allowed is True
```

`ExecutorContext` gains a new field + a new `__post_init__` (it has none today):
```python
destructive_confirmer: Optional["DestructiveConfirmationProvider"] = None

def __post_init__(self) -> None:
    if self.destructive_confirmer is None:
        self.destructive_confirmer = NonInteractiveDestructiveConfirmer(
            allowed=getattr(self.config, "allow_destructive", False))
```
Fail-closed by construction: an `ExecutorContext` built with nothing injected (e.g. a bare unit test)
never prompts and never silently allows.

`ValidationExecutor` gains the declared default `destructive: bool = False` (alongside the existing
`mutating`) — promoting the engine's `getattr(e, "destructive", False)` defensive read (§0) to a real,
documented attribute every executor can see and override, same footing as `mutating`.

### 4.2 Wiring (`config.py`, `orchestrator.py`, `cli.py`)

`config.py`: one new field, `allow_destructive: bool = False` (same naming as `ChainEngine`'s
existing `allow_destructive` kwarg — deliberately the same name/meaning everywhere in the codebase,
so there is exactly one flag, not two things called similar names that mean different things).

`orchestrator.py`: `ValidationOrchestrator.__init__` gains `destructive_confirmer:
Optional[DestructiveConfirmationProvider] = None`, defaulted **exactly mirroring the existing
`confirmer` default logic** (`self.confirmer = confirmer or (AutoConfirm() if config.auto_confirm
else DeclineAll())`):
```python
self.destructive_confirmer = destructive_confirmer or (
    NonInteractiveDestructiveConfirmer(allowed=config.allow_destructive) if config.auto_confirm
    else InteractiveDestructiveConfirmer())
```
i.e. an **interactive** run (`not config.auto_confirm`, the human-in-the-loop default) always gets
the press-yes prompt; a **non-interactive** run (`config.auto_confirm=True`, e.g. CI/automation) gets
the fail-closed, explicit-flag-only path — never a prompt that would hang forever. `ExecutorContext`
construction passes `destructive_confirmer=self.destructive_confirmer`.

`cli.py`: one new flag, `--allow-destructive` (`action="store_true"`), help text states plainly that
it only has any effect on non-interactive (`--yes`) runs and that it still prints a loud warning —
never a silent bypass. `args.allow_destructive` → `config.allow_destructive`.

### 4.3 Two layers, by design (ties back to §0)

This is a **per-call runtime gate** (above) layered *on top of* the **static engine-eligibility
gate** `chain_engine.py` already has (`getattr(e, "destructive", False)` + `ChainEngine`'s
`allow_destructive` kwarg, dormant until T3). They answer different questions and both apply:

- **Static/engine-level** (`ChainEngine._edge_allowed`): "may this executor CLASS even be considered
  by an automated, composed search at all?" FORCE-CHANGE-PASSWORD and GPO-ABUSE are
  unconditionally `destructive=True` (every call is irreversible/code-exec). GENERIC-ALL is **also**
  declared `destructive=True` at the class level — **conservatively**, even though only its
  `reset_password` pivot is actually irreversible — because the engine builds its edge list
  (`default_edges()`) from one instance per technique *before* any `pivot` param is resolved, so it
  cannot know in advance which pivot a composed run would pick. The same reasoning sets
  `crack_dependent=True` on both GENERIC-ALL and TARGETED-KERBEROAST.
- **Runtime/per-call** (`ctx.destructive_confirmer.confirm(...)`): "does *this specific, already-
  resolved* invocation need the operator's explicit yes?" Only fires inside the branches that are
  actually irreversible — GENERIC-ALL's `reset_password` pivot body, FORCE-CHANGE-PASSWORD, and
  GPO-ABUSE's SYSVOL write. GENERIC-ALL's other 3 pivots, run standalone (not through the chain
  engine), never hit this call at all.

A standalone orchestrator run (`orchestrator.run()`, the normal operator path — §2.1's non-
`reset_password` pivots, WRITE-DACL, WRITE-OWNER, ADD-MEMBER, TARGETED-KERBEROAST) never touches the
static engine filter at all; it only ever sees the runtime gate, and only when it actually matters.

## 5. Registry / probe / findings wiring (so nothing is unreachable)

Not explicitly itemized in the brief's DELIVER list, but required for any of the above to be
reachable — stated here briefly so the implementer doesn't have to rediscover the wiring points:

- `executors/__init__.py`: import the 7 new classes; add each to `_FULL`; `REGISTRY`/`IMPLEMENTED`
  pick them up automatically (no other change needed, per the existing pattern).
- `probes.py`: import + add the 7 new probe classes to the `_PROBES` tuple; `PROBE_REGISTRY` picks
  them up automatically.
- `findings.py`: one `MappingSignal`/`SIGNALS` entry per technique (mirrors the existing table's
  `rule_ids`/`categories`/`line_regex` shape), each with an `entity` extractor populating the fields
  the executor's `param_specs` reads as recommended defaults (`target`/`trustee`/`group`/`member`/
  `victim`/`gpo_guid`/`linked_host`/`ca`-equivalents). Exact `rule_id` strings depend on what
  aranum's AD CS/ACL promoters actually emit — out of scope to invent here; flagged as the one place
  the implementer must look at real aranum output (or BloodHound-derived promoted findings) before
  finalizing the regex/rule_id match, same caveat the brief already accepts for tool-output markers
  (`verified_recipe=False`, UNVERIFIED, pin in-lab).

## 6. Implementation order

1. **`acl_common.py` + `predicates.positive_absence`** (§1.1) — everything else depends on these;
   zero behavior change to existing files, pure addition.
2. **`states.py` additions** (§3) — zero behavior change, pure addition; unblocks every executor's
   `pre`/`eff`/`produced()`.
3. **`base.py` destructive-gate additions** (§4.1) — `DestructiveConfirmationProvider` +
   the two concrete providers + `ExecutorContext.destructive_confirmer`/`__post_init__` +
   `ValidationExecutor.destructive: bool = False`. Zero behavior change for every existing executor
   (none read `ctx.destructive_confirmer`, none set `destructive=True` yet).
4. **`config.py` / `orchestrator.py` / `cli.py` wiring** (§4.2) — one field, one constructor default,
   one flag; zero behavior change until a `destructive=True` executor actually calls the new hook.
5. **Non-destructive, non-crack-dependent executors first** (lowest risk, prove the `confirm_ace`
   pattern once, reuse it everywhere else): **WRITE-DACL → WRITE-OWNER → ADD-MEMBER**.
6. **Crack-dependent, non-destructive: TARGETED-KERBEROAST** (reuses the proven `offline_crack`
   gate pattern from `roast.py` verbatim).
7. **Destructive: FORCE-CHANGE-PASSWORD** (simplest destructive case — exercises the new gate
   end-to-end before GENERIC-ALL's conditional variant).
8. **GENERIC-ALL** last among the "clean" techniques — its 4 pivots each reuse a pattern already
   proven by steps 5–7 (plus the existing `shadow_creds.py`/`rbcd.py`), so building it last means
   every sub-pattern it needs has already been unit-tested once in isolation.
9. **GPO-ABUSE** last overall — the most UNVERIFIED recipe (§2.7), and its destructive-gate +
   byte-identical-rollback shape is the most intricate; building it after the gate mechanism and the
   simpler destructive case (FORCE-CHANGE-PASSWORD) are both proven reduces the number of new things
   to debug at once.
10. **Probe registrations + `findings.py` signals** — can trail each executor by one small commit,
    or batch at the end; either way, each executor is testable standalone before its probe/finding
    wiring lands (exactly as the existing test files already demonstrate, e.g. `test_n1_certifried.py`
    constructs `ExecutorContext`/`map_finding` directly, independent of the orchestrator's `plan()`).

## 7. Test command

```
cd /srv/share/dev/purplesploit/.claude/worktrees/validation-automation/python
PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -q -p no:cacheprovider tests/unit/validation
```
(`cd python` first — `pytest.ini`'s `testpaths = tests` is anchored at `python/`, and the tests
actually live at `python/tests/unit/validation`, not a bare `tests/unit/validation` off the worktree
root; the brief's command is correct run from that directory.) Add the 7 new `test_t3_*.py` files
(§2.1–2.7) plus a `test_t3_destructive_gate.py` covering `InteractiveDestructiveConfirmer`/
`NonInteractiveDestructiveConfirmer` in isolation (EOF→False; `allowed=True`→True; `allowed=False`→
False; a scripted `prompt_fn` returning `"yes"`/`"no"`/`"YES"` — case-sensitive exact match only
`"yes"` passes) and a `test_t3_states.py` covering `control_for`/`is_state`/the new `BASE_STATES`
membership and each of the 7 executors' `pre`/`eff` frozensets against `states.all_states(...)`.
Keep the existing suite green throughout (the brief's "produced() returns [] for everything except
the one Capability per technique" change and the `ExecutorContext.__post_init__` addition are the only
two touches to already-shipped files' *behavior surface*, and both are additive/backward-compatible —
no existing test constructs `ExecutorContext` with a `destructive_confirmer` already set, so the new
`__post_init__` branch always fires harmlessly to its fail-closed default in every pre-existing test).
