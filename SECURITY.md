# Security policy

PurpleSploit is intended only for systems where the operator has explicit authorization.
Version 7’s supported service is `purplesploit-api`; it fails closed unless
`PURPLESPLOIT_API_TOKEN` is set, enforces engagement authorization for execution,
and rejects unprovisioned remote agents. The `purplesploit-legacy-api` command is a
local compatibility surface, not a supported remote deployment.

Report suspected vulnerabilities privately to the maintainers. Do not include real
credentials, client evidence, target data, or exploit payloads. Include the version,
affected component, minimal synthetic reproduction, and impact. Until a dedicated
security contact is published, use a private GitHub security advisory on the project.

Supported security controls and limitations are documented in
[Deployment](docs/DEPLOYMENT.md) and [Support matrix](docs/SUPPORT_MATRIX.md).
Third-party plugins in strict mode require an Ed25519 publisher signature, declared
permissions, and execute through a separate process with a minimal environment. This
is a process and trust boundary, not an operating-system sandbox; deploy untrusted code
inside an additional container/VM boundary.

The repository and Python package use CC-BY-NC-SA-4.0. Commercial use requires
separate permission. This policy does not replace the license or legal authorization.
