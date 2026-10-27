# Version 7 release checklist

- Confirm `_version.py`, wheel metadata, documentation, and tag agree.
- Confirm repository and package license are CC-BY-NC-SA-4.0 and both wheel/sdist contain LICENSE.
- Run all tests on CPython 3.10–3.13.
- Enforce selected Ruff correctness rules, scoped formatting, type checks, and Bandit policy.
- Run `pip-audit --strict` and repository secret scanning.
- Run `python scripts/certify_release.py --source-tree ..`.
- Run `python scripts/recovery_rehearsal.py`.
- Build twice with the same `SOURCE_DATE_EPOCH`, normalize sdist metadata with
  `scripts/normalize_release_artifacts.py`, and byte-compare wheel and sdist.
- Generate CycloneDX SBOM and provenance/checksum manifest.
- Inspect wheel/sdist with `twine check` and the release certification script.
- On a release tag, keyless-sign every artifact and retain transparency-log evidence.
- Run the synthetic full-assessment suite and validate chosen external tools in an owned lab.
- Review `/healthz`, `/readyz`, redacted support bundle, migration, and rollback procedures.
- Record unresolved limitations from the support matrix in release notes.

CI encodes the automatable items. Publishing remains a deliberate maintainer action.
