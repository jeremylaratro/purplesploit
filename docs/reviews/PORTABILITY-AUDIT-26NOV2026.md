# Portability audit — validation toolchain on a never-before-seen system (26NOV2026)

**Goal (owner directive):** ensure all PLAN-003 validation work executes correctly on a
never-before-seen AD environment — no hard-coded credentials, no hard-coded IPs / domains /
hostnames / accounts, no GOAD-only quirks baked into product logic. Scope: the purplesploit
`validation/` product (executors, engine, CLI, config, probes, recommend) and the
ad-lab-harness **scorer** (`adlab/score_proof.py`). Exempt (legitimately lab-specific): the
harness **truth facets** (`GOAD-proof.json`, `GOAD.json`) and **unit-test fixtures** (fake
runners, never hit a real system).

## Result: PASS — the product is environment-parameterized

- **No hard-coded credentials** anywhere in product code (no passwords, hashes, or `vagrant`).
- **No hard-coded target IPs / domains / hostnames / accounts in logic.** Every GOAD string
  found is in a **comment, docstring, or `recipe_ref` provenance note** (cosmetic, not executed)
  — e.g. `verified_recipe = True  # lab-proven … (robb.stark)`, `recipe_ref = "… (PROVED
  jon.snow)"`.
- `ValidationConfig`: **`domain` and `dc_ip` are required** (raise if empty) — no GOAD default.
  Credentials, targets, CA, wordlist, DC host are all runtime params / finding-entity fields.
- Helpers are generic: `_domain_dn()` = `domain.split(".") → DC=…`; `recommended_spn(svc,host)`
  = `svc/host`; `delegation_computer(base)`; `principal_base(user)`. ADCS CA is
  `entity.get("ca_host") or finding.host` (not a hard-coded ESSOS-CA).
- The only "target-specific" literal found in logic is the **standard AD extended-right GUID**
  `00299570-…` (User-Force-Change-Password) in `acl_common.py` — identical on every AD system.
- Harness **scorer** (`score_proof.py`) is lab-agnostic (truth is a file argument). The
  `vagrant`/Vagrantfile references live only in the harness's GOAD build/observe layer
  (`clean_host.py`, `goad_profile.py`, `goad_readiness.py`) — whose *purpose* is GOAD.

## Fixed in this audit

- **DCSYNC multi-domain robustness.** `-just-dc-user krbtgt` (bare) is ambiguous in a
  multi-domain forest — DRSUAPI name translation raises `ERROR_DS_NAME_ERROR_NOT_UNIQUE` via the
  GC (common in real engagements; it is what blocked the live front→DCSYNC). Now
  **NetBIOS-domain-qualified** (`<NETBIOS>/krbtgt`), which impacket itself recommends and which
  works in single- **and** multi-domain. NetBIOS defaults to the FQDN's first label uppercased,
  with a `ValidationConfig.netbios_domain` override for the rare domain whose NetBIOS name
  differs. Verified live on GOAD (now `complete + terminal ok`, secret-clean) — also completes
  BLOCKER-4's live-GREEN proof.

## Noted — acceptable (carrier-side / cosmetic), not blockers

- `DEFAULT_WORDLIST = /usr/share/wordlists/rockyou.txt` — the **operator's Kali carrier**, not
  the target; overridable per technique via the `wordlist` param. Reasonable default.
- Tool names (`impacket-*`, `bloodyAD`, `certipy-ad`, `nxc`, `hashcat`) assume the operator's
  pentest carrier has them on `PATH` (some have D2 fallbacks). Carrier assumption, not a
  target-portability issue.
- `recipe_ref` / docstring provenance strings name GOAD accounts/hosts where each recipe was
  proven. **Display only**, never used in logic — they do not affect execution on a new system.

## Standing

Run this audit at the end of every tranche (T3…T8). Policy recorded in claude-mem #66220.
