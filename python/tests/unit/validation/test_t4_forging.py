"""T4 Kerberos ticket forging (Golden / Silver / Diamond / Sapphire).

Driven end-to-end with a scripted fake runner (no lab). These tests are written
to be NON-VACUOUS (review H9): the positive proof is wired so that a no-op forge
*cannot* pass it, authentication is conditional on the exact forged ccache, and
a generic SMB ``[+]`` is NOT accepted as the terminal. Each gate the executors
own (missing / placeholder signing key, missing requester, Sapphire's two-key
requirement, service scope) is shown able to go RED, and the secret rule is
asserted directly: the krbtgt / service key and the requester credential never
appear anywhere in the receipt.

The forge->reauth contract under test (``forge_common.forge_and_reauth``):
forge with ``KRB5CCNAME`` unset -> require the ccache file to exist ->
re-authenticate THROUGH that ccache (``--use-kcache``) -> accept ONLY the precise
cache-backed login line -> shred the ccache on every path.
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
    Capability, Credential, CAP_AES_KEY, CAP_NT_HASH, CAP_PRINCIPAL,
)
from purplesploit.validation import proof, states


HOST = "winterfell.north.sevenkingdoms.local"
DC_IP = "10.0.0.11"
SID = "S-1-5-21-111111111-222222222-333333333"

# Distinctive secret sentinels -- valid hex of the right width so they pass
# ``valid_key``, yet recognizable if they ever leak into a receipt.
AES_KEY = "deadbeef" * 8          # 64 hex = AES256, a well-formed krbtgt AES key
NT_KEY = "feedface" * 4           # 32 hex = an NT hash
REQ_PW = "REQ-PW-SENTINEL-9f3a7c"  # the requester's live low-priv password


class _ForgeFake(CommandRunner):
    """Scripted ticketer + nxc fake modelling the forge->reauth flow.

    - ``impacket-lookupsid`` -> the domain SID line (only hit when no override).
    - ``impacket-ticketer``  -> when ``make_ccache`` is True, CREATES
      ``<argv[-1]>.ccache`` in ``cwd`` and emits the real "Saving ticket in ..."
      line; otherwise emits a success banner but writes NO file (the no-op forge
      control -- the positive must fail on this).
    - ``nxc`` -> ``reauth_mode`` chooses stdout:
        ``'precise'`` : the exact cache-backed login line, but ONLY when
                        ``KRB5CCNAME`` names an existing file (auth conditional on
                        the forge having produced the exact ccache);
        ``'generic'`` : a plain SMB ``[+]`` WITHOUT "from ccache" (must NOT pass);
        ``'fail'``    : a ``[-]`` line.
    """

    def __init__(self, *, make_ccache=True, reauth_mode="precise", domain_sid=SID,
                 forge_rc=0, login_principal="Administrator", report_abs_path=None):
        self.make_ccache = make_ccache
        self.reauth_mode = reauth_mode
        self.domain_sid = domain_sid
        self.forge_rc = forge_rc
        self.login_principal = login_principal
        self.report_abs_path = report_abs_path
        self.calls: list[list[str]] = []
        self.reauth_env: dict = {}

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        tool = Path(argv[0]).name
        if tool == "impacket-lookupsid":
            return RunResult(0, stdout=f"[*] Domain SID is: {self.domain_sid}\n")
        if tool == "impacket-ticketer":
            user = argv[-1]
            if self.report_abs_path:    # reports an ABSOLUTE path, writes nothing to the scratch dir
                return RunResult(self.forge_rc, stdout=f"[*] Saving ticket in {self.report_abs_path}\n")
            if self.make_ccache and cwd:
                p = Path(cwd) / f"{user}.ccache"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(b"FORGED-CCACHE-BYTES")
                return RunResult(self.forge_rc, stdout=f"[*] Saving ticket in {user}.ccache\n")
            return RunResult(self.forge_rc, stdout="[*] Creating basic skeleton ticket...\n")
        if tool == "nxc":
            self.reauth_env = dict(env or {})
            cc = (env or {}).get("KRB5CCNAME")
            has_cache = bool(cc) and Path(cc).exists()
            if self.reauth_mode == "precise" and has_cache:
                return RunResult(0, stdout="SMB  winterfell  445  WS  "
                                 f"[+] NORTH\\{self.login_principal} from ccache (Pwn3d!)\n")
            if self.reauth_mode == "generic":
                # a plausible but WRONG success: a generic [+] with no ccache clause
                return RunResult(0, stdout="SMB  winterfell  445  WS  [+] NORTH\\guest \n")
            return RunResult(0, stdout="SMB  winterfell  445  WS  "
                             "[-] NORTH\\x KRB_AP_ERR_MODIFIED\n")
        return RunResult(0, stdout="")

    def ticketer_argv(self):
        for c in self.calls:
            if Path(c[0]).name == "impacket-ticketer":
                return c
        return None

    def called(self, name):
        return any(Path(c[0]).name == name for c in self.calls)


def _cfg(**kw) -> ValidationConfig:
    base = dict(domain="north.sevenkingdoms.local", dc_ip=DC_IP)
    base.update(kw)
    return ValidationConfig(**base)


def _finding(host=HOST):
    return map_finding({"finding_id": "KB-1", "host": host, "category": "kerberos",
                        "severity": "high", "line": f"krbtgt key material exposed on {host}"})


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


def _dump(receipt) -> str:
    return json.dumps(receipt, default=str)


def _no_cache_left(tmp_path) -> bool:
    return not any(p.is_file() for p in Path(tmp_path).iterdir())


# =====================================================================  GOLDEN

def test_all_four_t4_implemented():
    for t in ("GOLDEN-TICKET", "SILVER-TICKET", "DIAMOND-TICKET", "SAPPHIRE-TICKET"):
        assert is_implemented(t), t


def test_golden_positive_proves_through_the_forged_ccache(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "GOLDEN-TICKET" and receipt["class"] == "kerberos_forge"
    assert receipt["complete"] is True
    assert receipt["executor"]["verified_recipe"] is True   # recipe is now lab-proven
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "authn_success" and tf["ok"] is True and tf["proof_token"]
    assert receipt["mutation"]["applied"] is False
    # auth went THROUGH the exact forged ccache (KRB5CCNAME named it), not operator creds
    assert runner.reauth_env.get("KRB5CCNAME", "").endswith("Administrator.ccache")
    # the forged ccache was shredded on the way out
    assert _no_cache_left(tmp_path)


def test_golden_noop_forge_cannot_pass_the_positive(tmp_path):
    # H9 core: if the forge produces NO ccache, the proof must fail and reauth
    # must never even be attempted.
    runner = _ForgeFake(make_ccache=False)
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "forge_failed" in receipt["errors"]
    assert receipt["terminal_fact"]["ok"] is False
    assert not runner.called("nxc")          # reauth was never reached
    assert _no_cache_left(tmp_path)


def test_golden_generic_plus_is_not_accepted_as_proof(tmp_path):
    # A generic SMB [+] (no "from ccache (Pwn3d!)") must NOT be read as the proof.
    runner = _ForgeFake(reauth_mode="generic")
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "reauth_failed" in receipt["errors"]
    assert receipt["terminal_fact"]["ok"] is False


def test_golden_missing_signing_key_fails_closed(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg()                              # no forge_key, no threaded cap
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "no_signing_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")   # never forged without a key


def test_golden_placeholder_key_rejected(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key="x" * 64, forge_key_kind="aes")   # right width, NOT hex
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "no_signing_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_golden_secret_key_never_in_receipt(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is True
    assert AES_KEY not in _dump(receipt)      # the krbtgt key is masked everywhere


def test_golden_domain_sid_auto_resolves_via_lookupsid(tmp_path):
    # With no domain_sid override, the SID is resolved from the DC (lookupsid),
    # never fabricated -- and the proof still completes.
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes", username="jon.snow", password="pw")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(), overrides={"reauth_target": HOST})
    assert runner.called("impacket-lookupsid")
    assert receipt["complete"] is True


def test_golden_unresolved_domain_sid_aborts(tmp_path):
    # lookupsid returns nothing usable -> UNKNOWN SID -> abort, never fabricate.
    runner = _ForgeFake(domain_sid="")
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes", username="jon.snow", password="pw")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(), overrides={"reauth_target": HOST})
    assert receipt["complete"] is False
    assert "domain_sid_unresolved" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_golden_produced_capability_only_on_complete(tmp_path):
    ex = get_executor("GOLDEN-TICKET")
    # complete -> one S_PERSISTENCE principal capability (public marker only)
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    res = ex.run_composable(_ctx(cfg, runner, tmp_path), _finding(),
                            overrides={"reauth_target": HOST, "domain_sid": SID})
    assert res.complete is True
    assert [c.state for c in res.capabilities if not isinstance(c, Credential)] == [states.S_PERSISTENCE]
    assert any(isinstance(c, Credential) and c.secret_type == "ccache" for c in res.capabilities)
    cap = res.capabilities[0]
    assert cap.channel == CAP_PRINCIPAL and cap.value == "Administrator"
    # incomplete -> no capability leaks downstream
    runner2 = _ForgeFake(make_ccache=False)
    res2 = ex.run_composable(_ctx(cfg, runner2, tmp_path), _finding(),
                             overrides={"reauth_target": HOST, "domain_sid": SID})
    assert res2.complete is False and res2.capabilities == []


def test_golden_composition_hooks(tmp_path):
    ex = get_executor("GOLDEN-TICKET")
    f = _finding()
    ctx = _ctx(_cfg(), _ForgeFake(), tmp_path)
    assert ex.chain_pre(ctx, f) == frozenset({states.KRBTGT})
    assert ex.chain_eff(ctx, f) == frozenset({states.S_PERSISTENCE})
    # accepts a well-formed krbtgt AES/NT key, rejects a malformed one
    assert ex.accepts_key(ctx, f, Capability(states.KRBTGT, CAP_AES_KEY, AES_KEY))
    assert ex.accepts_key(ctx, f, Capability(states.KRBTGT, CAP_NT_HASH, NT_KEY))
    assert not ex.accepts_key(ctx, f, Capability(states.KRBTGT, CAP_AES_KEY, "nothex"))
    assert not ex.accepts_key(ctx, f, Capability(states.KRBTGT, CAP_PRINCIPAL, "dc01$"))


# =====================================================================  SILVER

def test_silver_positive_is_service_scoped(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=NT_KEY, forge_key_kind="nt")   # service-account key
    res = get_executor("SILVER-TICKET").run_composable(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"service_host": HOST, "domain_sid": SID})
    assert res.complete is True
    tf = res.receipt["terminal_fact"]
    assert tf["kind"] == "authn_success" and tf["ok"] is True
    # effect is admin of THAT host's service, not domain persistence (H8)
    assert [c.state for c in res.capabilities if not isinstance(c, Credential)] == [states.local_admin_for(HOST)]
    assert any(isinstance(c, Credential) and c.secret_type == "ccache" for c in res.capabilities)
    argv = runner.ticketer_argv()
    assert "-spn" in argv and f"cifs/{HOST}" in argv
    assert "-nthash" in argv            # NT service key rides -nthash (masked)
    assert NT_KEY not in _dump(res.receipt)


def test_silver_noop_forge_fails(tmp_path):
    runner = _ForgeFake(make_ccache=False)
    cfg = _cfg(forge_key=NT_KEY, forge_key_kind="nt")
    receipt = get_executor("SILVER-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"service_host": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]
    assert not runner.called("nxc")


def test_silver_missing_service_key_fails_closed(tmp_path):
    runner = _ForgeFake()
    receipt = get_executor("SILVER-TICKET").run(
        _ctx(_cfg(), runner, tmp_path), _finding(),
        overrides={"service_host": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "no_service_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


# ====================================================================  DIAMOND

def test_diamond_positive_requests_then_resigns(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes",
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("DIAMOND-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"forged_user": "Administrator", "reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is True
    argv = runner.ticketer_argv()
    assert "-request" in argv and "-user" in argv       # a REAL TGT is requested
    blob = _dump(receipt)
    assert AES_KEY not in blob and REQ_PW not in blob    # key AND requester pw masked


def test_diamond_missing_requester_credential_fails_closed(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")   # key present, NO requester
    receipt = get_executor("DIAMOND-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "no_requester_credential" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_diamond_missing_signing_key_fails_closed(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(username="jon.snow", password=REQ_PW)      # requester present, NO key
    receipt = get_executor("DIAMOND-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "no_signing_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_diamond_noop_forge_fails(tmp_path):
    runner = _ForgeFake(make_ccache=False)
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes",
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("DIAMOND-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]


# ===================================================================  SAPPHIRE

def test_sapphire_positive_needs_both_keys_and_a_requester(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes", forge_key_nt=NT_KEY,
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("SAPPHIRE-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"impersonate": "Administrator", "reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is True
    argv = runner.ticketer_argv()
    assert "-request" in argv and "-impersonate" in argv
    assert "-aesKey" in argv and "-nthash" in argv       # BOTH krbtgt keys
    blob = _dump(receipt)
    assert AES_KEY not in blob and NT_KEY not in blob and REQ_PW not in blob


def test_sapphire_missing_nt_key_fails_closed(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes",   # AES only, NO forge_key_nt
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("SAPPHIRE-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "no_nt_signing_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_sapphire_nt_only_signing_key_fails_closed(tmp_path):
    # Sapphire must sign with the AES key; an NT-kind signing key is not enough.
    runner = _ForgeFake()
    cfg = _cfg(forge_key=NT_KEY, forge_key_kind="nt", forge_key_nt=NT_KEY,
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("SAPPHIRE-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "no_aes_signing_key" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_sapphire_missing_requester_fails_closed(tmp_path):
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes", forge_key_nt=NT_KEY)  # no requester
    receipt = get_executor("SAPPHIRE-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False
    assert "no_requester_credential" in receipt["errors"]
    assert not runner.called("impacket-ticketer")


def test_sapphire_noop_forge_fails(tmp_path):
    runner = _ForgeFake(make_ccache=False)
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes", forge_key_nt=NT_KEY,
               username="jon.snow", password=REQ_PW)
    receipt = get_executor("SAPPHIRE-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]


# =============================================== robustness (cross-review r1 fixes)

def test_nonzero_forge_returncode_is_not_a_forge(tmp_path):
    # The tool wrote a file but FAILED (returncode!=0) -> not a forge (no fabricated
    # success from a half-written cache).
    runner = _ForgeFake(forge_rc=1)
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]
    assert not runner.called("nxc")


def test_stale_ccache_cannot_mask_a_failed_forge(tmp_path):
    # A cache left by a PRIOR run must not let a no-op forge pass: the scratch dir
    # is cleared first, so a stale cache is gone before the forge runs.
    stale = Path(tmp_path) / ".forge-Administrator" / "Administrator.ccache"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_bytes(b"STALE-VALID-TICKET-FROM-A-PRIOR-RUN")
    runner = _ForgeFake(make_ccache=False)              # this run forges nothing
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]
    assert not runner.called("nxc")                     # the stale cache was not reused


def test_cleanup_is_confined_to_the_forge_scratch_dir(tmp_path):
    # Standalone out_dir is the operator's output root: a sibling report/key file
    # there MUST survive the forge's shred (only the .forge-* scratch dir is wiped).
    sibling = Path(tmp_path) / "report.json"
    sibling.write_text('{"keep":"me"}')
    keyfile = Path(tmp_path) / "krbtgt.aes.key"
    keyfile.write_text(AES_KEY)
    runner = _ForgeFake()
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is True
    assert sibling.exists() and sibling.read_text() == '{"keep":"me"}'   # NOT shredded
    assert keyfile.exists() and keyfile.read_text() == AES_KEY           # NOT shredded
    assert not (Path(tmp_path) / ".forge-Administrator").exists()        # scratch removed


def test_login_as_a_different_principal_is_rejected(tmp_path):
    # A cache-backed [+] (Pwn3d!) for a DIFFERENT principal than the one we forged
    # must NOT satisfy the proof (identity binding).
    runner = _ForgeFake(login_principal="guest")        # forged Administrator, logged in as guest
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"forged_user": "Administrator", "reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "reauth_failed" in receipt["errors"]


def test_lookalike_principal_login_is_rejected(tmp_path):
    # Identity is matched EXACTLY, not by substring: forging "Administrator" but
    # logging in as "Administrator2" must be rejected (review r2 HIGH).
    runner = _ForgeFake(login_principal="Administrator2")
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"forged_user": "Administrator", "reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "reauth_failed" in receipt["errors"]


def test_absolute_cache_path_outside_scratch_is_not_a_forge(tmp_path):
    # A tool that reports an ABSOLUTE path to a pre-existing cache OUTSIDE the
    # scratch dir, while writing nothing into the (cleared) scratch dir, must NOT
    # count as a forge -- freshness is resolved only inside the scratch dir (r2).
    stale = Path(tmp_path) / "outside" / "Administrator.ccache"
    stale.parent.mkdir(parents=True, exist_ok=True)
    stale.write_bytes(b"STALE-OUTSIDE-TICKET")
    runner = _ForgeFake(report_abs_path=str(stale))
    cfg = _cfg(forge_key=AES_KEY, forge_key_kind="aes")
    receipt = get_executor("GOLDEN-TICKET").run(
        _ctx(cfg, runner, tmp_path), _finding(),
        overrides={"forged_user": "Administrator", "reauth_target": HOST, "domain_sid": SID})
    assert receipt["complete"] is False and "forge_failed" in receipt["errors"]
    assert not runner.called("nxc")
    assert stale.exists()                               # the outside cache was never touched
