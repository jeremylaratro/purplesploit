"""T1c executor: ADCS-ESC1 (adcs_esc1.py).

The technique is driven end-to-end with a scripted fake runner (no lab) and the
emitted receipt is asserted to be a well-formed ``adlab.plan003.proof.v1`` with
the shape the harness scorer reads as *proved*: correct schema/technique/class,
the scoring identity the facet keys on (ADCS-ESC1 {host_id, domain}), all steps
ok, a verified rollback (the issued key material destroyed -- certipy has no
revoke, #66157), a non-negated terminal fact ``cert_issued_and_used`` with a
token, and -- critically -- no issued pfx / recovered NT hash / operator password
anywhere in the receipt.

Failure / gate / unverified-rollback paths assert the honest *non*-proved shape:
a failed req, a failed PKINIT auth, an undeletable key artifact or a denied gate
yields an incomplete receipt (no positive proof), never a fabricated one.

The ADCS fake runner dispatches on the certipy subcommand (req / auth) so the
real serial/pfx/ccache parsing and the PKINIT + ticket-backed chain are exercised
distinctly (the shared keyed fake used by the other suites keys on tool name
only, which cannot tell the certipy calls apart).
"""
from __future__ import annotations

import json
from pathlib import Path

from purplesploit.validation.config import ValidationConfig
from purplesploit.validation.findings import map_finding
from purplesploit.validation.executors import get_executor, is_implemented
from purplesploit.validation.executors.base import (
    ExecutorContext, CommandRunner, RunResult, AuthorizedLabProvider,
)
from purplesploit.validation import proof


# ----------------------------------------------------------------- certipy fake runner
class _FakeCertipyRunner(CommandRunner):
    """Scripted stdout keyed on the certipy subcommand (req/auth) and nxc.

    ``certipy-ad`` is invoked twice (req, auth); keying on the second argv token
    distinguishes them. Everything else keys on the tool name.
    """

    def __init__(self, script):
        self.script = script
        self.calls: list[list[str]] = []

    def run(self, argv, *, env=None, timeout=None, cwd=None) -> RunResult:
        self.calls.append(list(argv))
        return self.script.get(self._key(argv), RunResult(returncode=0, stdout=""))

    @staticmethod
    def _key(argv) -> str:
        tool = Path(argv[0]).name
        if tool == "certipy-ad":
            return argv[1] if len(argv) > 1 else "certipy-ad"
        if tool == "nxc":
            return "nxc"
        return tool


def _ctx(cfg, runner, tmp_path, authorizer=None):
    return ExecutorContext(cfg, runner=runner,
                           authorizer=authorizer or AuthorizedLabProvider(True),
                           output_dir=tmp_path)


class _Deny(AuthorizedLabProvider):
    """Deny exactly one gated op; everything else is not_required."""

    def __init__(self, op):
        super().__init__(True)
        self._op = op

    def authorize(self, op, detail):
        return "denied" if op == self._op else "not_required"


# ----------------------------------------------------------------- fixtures
def _essos_config(**kw) -> ValidationConfig:
    base = dict(domain="essos.local", dc_ip="10.0.1.10",
                username="daenerys.targaryen", password="BlackDr4g0n!",
                host_aliases={"braavos.essos.local": {"host_id": "srv03"}})
    base.update(kw)
    return ValidationConfig(**base)


def _adcs_finding(host="braavos.essos.local"):
    # aranum promoted AD CS finding; _extract_adcs parses esc/template/ca and ca_host=host.
    return map_finding({
        "finding_id": "AR-c1", "host": host, "category": "adcs", "severity": "critical",
        "rule_id": "promoted-adcs-ca",
        "line": (f"AD CS CA ESSOS-CA AD CS template ESC1-UserCert (ESC1) "
                 f"enrollable by domain users on {host}"),
    })


# A recovered NT hash appears in the certipy auth transcript -- it must NEVER
# reach the receipt (the executor records presence only, never the value).
_FAKE_NT_HASH = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
_SERIAL = "1A0000001122334455667788AABBCCDDEEFF0011"


def _req_stdout():
    return ("[*] Requesting certificate via RPC\n"
            "[*] Successfully requested certificate\n"
            "[*] Request ID is 24\n"
            "[*] Got certificate with UPN 'Administrator@essos.local'\n"
            f"[*] Certificate serial number: {_SERIAL}\n"
            "[*] Saved certificate and private key to 'administrator.pfx'\n")


def _auth_stdout():
    return ("[*] Using principal: administrator@essos.local\n"
            "[*] Trying to get TGT...\n"
            "[*] Got TGT\n"
            "[*] Saved credential cache to 'administrator.ccache'\n"
            f"[*] Got hash for 'administrator@essos.local': {_FAKE_NT_HASH}\n")


def _nxc_stdout():
    return "SMB  braavos.essos.local  445  BRAAVOS  [+] essos.local\\Administrator (Pwn3d!)"


def _proved_script():
    return {
        "req": RunResult(0, stdout=_req_stdout()),
        "auth": RunResult(0, stdout=_auth_stdout()),
        "nxc": RunResult(0, stdout=_nxc_stdout()),
    }


# ================================================================= mapping + defaults
def test_adcs_maps_and_defaults(tmp_path):
    f = _adcs_finding()
    assert f.technique == "ADCS-ESC1" and f.technique_class == "adcs"
    assert f.entity.get("esc") == "ESC1"
    assert f.entity.get("template") == "ESC1-UserCert"
    assert f.entity.get("ca") == "ESSOS-CA"
    assert f.entity.get("ca_host") == "braavos.essos.local"
    assert is_implemented("ADCS-ESC1")
    cfg = _essos_config()
    specs = {s.name: s for s in get_executor("ADCS-ESC1").param_specs(
        _ctx(cfg, _FakeCertipyRunner({}), tmp_path), f)}
    assert specs["template"].recommended == "ESC1-UserCert"   # from finding.entity.template
    assert specs["ca"].recommended == "ESSOS-CA"              # from finding.entity.ca
    assert specs["ca_host"].recommended == "braavos.essos.local"
    assert specs["impersonate"].recommended == "Administrator"  # high-value SAN/UPN
    assert specs["target_host"].recommended == "braavos.essos.local"  # ca_host by default
    assert specs["ldap_scheme"].recommended == ""            # auto/off by default
    assert specs["ldap_scheme"].required is False


def test_adcs_template_default_falls_back_to_esc1(tmp_path):
    # A promoted-adcs-tpl finding whose line carries no explicit "AD CS template"
    # token -> template default falls back to the ESC1 convention name.
    f = map_finding({
        "finding_id": "AR-c2", "host": "braavos.essos.local", "category": "adcs",
        "rule_id": "promoted-adcs-tpl",
        "line": "AD CS CA ESSOS-CA vulnerable (ESC1) on braavos.essos.local",
    })
    assert f.technique == "ADCS-ESC1" and f.entity.get("template") is None
    cfg = _essos_config()
    specs = {s.name: s for s in get_executor("ADCS-ESC1").param_specs(
        _ctx(cfg, _FakeCertipyRunner({}), tmp_path), f)}
    assert specs["template"].recommended == "ESC1"


# ================================================================= proved-shaped receipt
def test_adcs_emits_proved_shaped_receipt(tmp_path):
    cfg = _essos_config()
    # Simulate certipy having written the issued key material, so the rollback's
    # destruction step is genuinely exercised (and asserted gone afterward).
    (tmp_path / "administrator.pfx").write_bytes(b"PFX")
    (tmp_path / "administrator.ccache").write_bytes(b"CCACHE")
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert receipt["schema"] == proof.PROOF_SCHEMA
    assert receipt["technique"] == "ADCS-ESC1" and receipt["class"] == "adcs"
    # Facet keys on {host_id, domain}; host_id resolved via host_aliases.
    assert receipt["target"].get("host_id") == "srv03"
    assert receipt["target"].get("domain") == "essos.local"
    assert receipt["complete"] is True
    assert receipt["steps"] and all(s["ok"] for s in receipt["steps"])
    # The full chain ran: req, auth, nxc, then the key-material-destruction rollback.
    assert [s["name"] for s in receipt["steps"]] == [
        "cert_request", "cert_auth", "nxc_access", "destroy_key_material"]
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True
    assert receipt["mutation"]["rollback"]["method"] == "destroy issued-cert key material (.pfx + .ccache)"
    assert "rollback_unverified" not in receipt["errors"]
    # The rollback actually destroyed the issued key material.
    assert not (tmp_path / "administrator.pfx").exists()
    assert not (tmp_path / "administrator.ccache").exists()
    tf = receipt["terminal_fact"]
    assert tf and tf["kind"] == "cert_issued_and_used" and tf["ok"] is True and tf["proof_token"]
    assert tf["impersonated"] == "Administrator"
    # certipy was invoked only as req + auth (no revoke -- certipy has none); nxc used the ticket.
    subs = [c[1] for c in runner.calls if Path(c[0]).name == "certipy-ad"]
    assert subs == ["req", "auth"]
    assert any(Path(c[0]).name == "nxc" and "-k" in c for c in runner.calls)


def test_adcs_operator_override_changes_impersonation(tmp_path):
    cfg = _essos_config()
    runner = _FakeCertipyRunner(_proved_script())
    get_executor("ADCS-ESC1").run(
        _ctx(cfg, runner, tmp_path), _adcs_finding(),
        overrides={"impersonate": "enterprise_admin"})
    req = next(c for c in runner.calls if Path(c[0]).name == "certipy-ad" and c[1] == "req")
    # The SAN/UPN now impersonates the overridden principal.
    assert req[req.index("-upn") + 1] == "enterprise_admin@essos.local"


def test_adcs_ldap_scheme_override_adds_flag(tmp_path):
    # The #66146 Win2016-CA gotcha: operator forces plain LDAP.
    cfg = _essos_config()
    runner = _FakeCertipyRunner(_proved_script())
    get_executor("ADCS-ESC1").run(
        _ctx(cfg, runner, tmp_path), _adcs_finding(), overrides={"ldap_scheme": "ldap"})
    req = next(c for c in runner.calls if Path(c[0]).name == "certipy-ad" and c[1] == "req")
    assert "-ldap-scheme" in req and req[req.index("-ldap-scheme") + 1] == "ldap"
    # Default (no override) omits the flag entirely.
    runner2 = _FakeCertipyRunner(_proved_script())
    get_executor("ADCS-ESC1").run(_ctx(cfg, runner2, tmp_path), _adcs_finding())
    req2 = next(c for c in runner2.calls if Path(c[0]).name == "certipy-ad" and c[1] == "req")
    assert "-ldap-scheme" not in req2


# ================================================================= no secret leak
def test_adcs_no_secret_in_receipt(tmp_path):
    cfg = _essos_config(password="BlackDr4g0n!")
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    blob = json.dumps(receipt)
    assert "BlackDr4g0n!" not in blob                    # operator password never stored
    assert _FAKE_NT_HASH not in blob                     # recovered NT hash never stored
    assert "31d6cfe0d16ae931b73c59d7e0c089c0" not in blob
    assert "administrator.pfx" not in blob               # issued pfx path never stored
    assert "administrator.ccache" not in blob            # credential cache path never stored


def test_adcs_hash_with_hashes_auth_not_leaked(tmp_path):
    # Operator authenticates by NT hash; the -hashes value must not leak either.
    op_hash = "aad3b435b51404eeaad3b435b51404ee:0123456789abcdef0123456789abcdef"
    cfg = _essos_config(password=None, nt_hash=op_hash)
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert op_hash not in json.dumps(receipt)
    # ... but the chain still proved (hash auth is a valid operator credential).
    assert receipt["complete"] is True and receipt["terminal_fact"]["ok"] is True


# ================================================================= honest non-proved shapes
def test_adcs_req_fails_is_not_proved(tmp_path):
    script = _proved_script()
    script["req"] = RunResult(1, stdout="[-] Certificate request failed: access denied")
    cfg = _essos_config()
    runner = _FakeCertipyRunner(script)
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert receipt["complete"] is False
    assert receipt["terminal_fact"] is None               # never issued -> no proof
    assert receipt["mutation"]["applied"] is False         # nothing to roll back
    assert "cert_request_failed" in receipt["errors"]
    assert any(s["name"] == "cert_request" and s["ok"] is False for s in receipt["steps"])
    # auth / nxc / revoke never ran.
    assert [c[1] for c in runner.calls if Path(c[0]).name == "certipy-ad"] == ["req"]


def test_adcs_auth_fails_is_not_proved(tmp_path):
    script = _proved_script()
    script["auth"] = RunResult(1, stdout="[-] Got error while trying to authenticate: KDC_ERR")
    cfg = _essos_config()
    # req issued the cert (wrote the .pfx) before auth failed, so the rollback has
    # a real artifact to destroy -> verified (non-vacuous).
    (tmp_path / "administrator.pfx").write_bytes(b"PFX")
    runner = _FakeCertipyRunner(script)
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    # Cert issued (mutating) but PKINIT failed -> negated terminal, not fabricated.
    assert receipt["mutation"]["applied"] is True
    assert receipt["terminal_fact"]["ok"] is False
    assert "cert_auth_failed" in receipt["errors"]
    assert any(s["name"] == "cert_auth" and s["ok"] is False for s in receipt["steps"])
    # nxc is skipped when auth fails; rollback still destroys the issued key material.
    assert not any(Path(c[0]).name == "nxc" for c in runner.calls)
    assert receipt["mutation"]["rollback"]["verified"] is True


def test_adcs_unverified_rollback_is_inconclusive(tmp_path):
    # Full chain proved, but a key-material artifact cannot be destroyed (here the
    # .pfx path is occupied by a directory, so unlink fails) -> rollback unverified.
    (tmp_path / "administrator.pfx").mkdir()
    cfg = _essos_config()
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
    assert any(s["name"] == "destroy_key_material" and s["ok"] is False
               for s in receipt["steps"])
    # The terminal predicate itself is still a (positive) record; the scorer's
    # rollback guard is what turns this into inconclusive.
    assert receipt["terminal_fact"]["ok"] is True


def test_adcs_unparsed_serial_does_not_block_rollback(tmp_path):
    # No serial/request-id in the output: irrelevant to the functional rollback
    # (key-material destruction needs no serial) -> still verified; only the
    # serial-based CA-DB follow-up advisory is skipped.
    script = _proved_script()
    script["req"] = RunResult(0, stdout=(
        "[*] Successfully requested certificate\n"
        "[*] Saved certificate and private key to 'administrator.pfx'\n"))
    cfg = _essos_config()
    # req + auth wrote the key material; destruction has real artifacts to remove.
    (tmp_path / "administrator.pfx").write_bytes(b"PFX")
    (tmp_path / "administrator.ccache").write_bytes(b"CCACHE")
    runner = _FakeCertipyRunner(script)
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["performed"] is True
    assert receipt["mutation"]["rollback"]["verified"] is True   # destruction needs no serial
    assert "rollback_unverified" not in receipt["errors"]
    assert not any(e.startswith("advisory:ca_db_revocation_followup")
                   for e in receipt["errors"])
    assert any(e.startswith("advisory:rotate_credentials") for e in receipt["errors"])
    assert [c[1] for c in runner.calls if Path(c[0]).name == "certipy-ad"] == ["req", "auth"]


def test_adcs_request_gate_denied_inconclusive(tmp_path):
    cfg = _essos_config()
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(
        _ctx(cfg, runner, tmp_path, _Deny("adcs_cert_request")), _adcs_finding())
    assert receipt["gate"]["classifier"] == "denied"
    assert receipt["complete"] is False and receipt["terminal_fact"] is None
    assert receipt["mutation"]["applied"] is False         # never issued -> nothing to roll back
    assert runner.calls == []                               # certipy never run


def test_adcs_target_not_vulnerable_is_not_proved(tmp_path):
    # A CA host not in the vulnerable set (no host_id alias) -> proved-shaped
    # receipt, but the scorer's fabrication guard rejects the target.
    cfg = _essos_config(host_aliases={})   # braavos no longer resolves to srv03
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert "host_id" not in receipt["target"]
    assert receipt["target"].get("domain") == "essos.local"
    # Locally the chain is complete + proved-shaped; truth-matching is the scorer's job.
    assert receipt["complete"] is True and receipt["terminal_fact"]["ok"] is True


def test_adcs_vacuous_destruction_is_unverified(tmp_path):
    # REGRESSION: if the issued .pfx was written to a path we did not parse (so the
    # guessed path never existed), file-absence is VACUOUS -> rollback must report
    # unverified, never a false clean. No key-material files are created here, so
    # destroy removes nothing.
    cfg = _essos_config()
    runner = _FakeCertipyRunner(_proved_script())
    receipt = get_executor("ADCS-ESC1").run(_ctx(cfg, runner, tmp_path), _adcs_finding())
    assert receipt["mutation"]["applied"] is True
    assert receipt["mutation"]["rollback"]["verified"] is False
    assert "rollback_unverified" in receipt["errors"]
    assert any(s["name"] == "destroy_key_material" and s["ok"] is False
               for s in receipt["steps"])
