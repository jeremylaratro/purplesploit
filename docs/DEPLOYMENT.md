# Supported deployment

PurpleSploit 7 supports a single-user, local or operator-controlled service deployment.
The canonical SQLite store, encrypted secret vault, evidence blobs, audit log, and
plugin state live below `PURPLESPLOIT_DATA_DIR` (default `.data`). Protect and back up
that directory as sensitive assessment material.

## Start the supported API

```bash
cd python
python -m pip install .
export PURPLESPLOIT_API_TOKEN='replace-with-at-least-16-random-characters'
export PURPLESPLOIT_DATA_DIR='/secure/path/purplesploit'
purplesploit-api
```

The listener defaults to `127.0.0.1:5000`. Set `PURPLESPLOIT_HOST` and
`PURPLESPLOIT_PORT` only behind an authenticated TLS reverse proxy. Configure browser
origins with comma-separated `PURPLESPLOIT_ALLOWED_ORIGINS`. `/healthz` is liveness;
`/readyz` verifies the canonical store and reports whether policy and agent auth are on.

Every non-health request needs `Authorization: Bearer <token>`. Browser sessions use an
HttpOnly, Secure, SameSite=Strict cookie and a CSRF header. Agent WebSockets accept
credentials only in the Authorization header. Agent messages additionally require
timestamped HMAC envelopes. Provision agents in a mode-0600 JSON file and set
`PURPLESPLOIT_AGENT_CONFIG`; each entry contains a `secret` and allowed `capabilities`.

AI provider context is disabled until the caller supplies `consent: true` or the
operator explicitly sets `PURPLESPLOIT_AI_PROVIDER_CONSENT=true`. Provider output is
always a draft and never execution authorization.

Strict plugins require public Ed25519 keys in `PURPLESPLOIT_PLUGIN_TRUST_DIR`, named
`<key-id>.pem`. Packages must declare permissions and carry a matching signature.
Plugin Python runs in a separate process with no host secrets or framework database.
Use a container/VM when OS-level filesystem or network isolation is required.

Do not expose `purplesploit-legacy-api` remotely. It exists only for transition from
the v6 browser/API surface.
