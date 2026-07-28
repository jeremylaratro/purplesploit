#!/usr/bin/env bash
#
# End-to-end verification of a built bundle, in containers with --network none.
#
# The in-container checks during the build prove the wheelhouse resolves and the
# binary runs on the build machine. This proves the shipped artifact installs and
# runs on a clean target with no network at all — which is the actual claim.
#
# Two scenarios:
#   A. bare Kali, NO python installed  -> ./install.sh --binary-only
#   B. Kali + python3/venv only        -> ./install.sh (full venv + source)
#
# Usage: ./packaging/offline/verify-bundle.sh [path/to/bundle-dir]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUNDLE="${1:-$(ls -d "$REPO_ROOT"/build/offline/purplesploit-offline-* 2>/dev/null | grep -v '\.tar' | head -1)}"
CONTAINER=${CONTAINER:-$(command -v docker >/dev/null && echo docker || echo podman)}
TESTIMG=purplesploit-offline-target:kali

log()  { printf '\n\033[1;35m==>\033[0m %s\n' "$*"; }
pass() { printf '\033[1;32m  PASS\033[0m %s\n' "$*"; }
die()  { printf '\n\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

[[ -d "$BUNDLE" ]] || die "bundle dir not found: $BUNDLE"
log "Verifying $(basename "$BUNDLE")"

# A clean target: Kali plus only what a real box would have. Deliberately does
# NOT include pip, a compiler, or any of the build venv.
log "Building clean target image"
"$CONTAINER" build -q -t "$TESTIMG" - <<'EOF' >/dev/null
FROM kalilinux/kali-rolling:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv rsync ca-certificates \
    && rm -rf /var/lib/apt/lists/*
EOF

run_isolated() {   # run_isolated <image> <script>
    "$CONTAINER" run --rm \
        --network none \
        --user "$(id -u):$(id -g)" \
        -e HOME=/tmp/home \
        -v "$BUNDLE:/bundle:ro" \
        "$1" bash -euc "mkdir -p /tmp/home; $2"
}

# ---------------------------------------------- A. binary-only, no python
log "Scenario A: bare Kali, no Python interpreter, --binary-only"
OUT_A=$(run_isolated kalilinux/kali-rolling:latest '
    command -v python3 && { echo "python3 unexpectedly present"; exit 1; }
    cp -r /bundle /tmp/b && chmod -R u+w /tmp/b && cd /tmp/b
    ./install.sh --binary-only
    export PATH="$HOME/.local/bin:$PATH"
    purplesploit --version
    printf "exit\n" | purplesploit 2>&1 | grep -oE "[0-9]+ modules loaded"
' 2>&1) || { echo "$OUT_A"; die "scenario A failed"; }

grep -q "PurpleSploit" <<<"$OUT_A" || { echo "$OUT_A"; die "A: no version output"; }
MODS_A=$(grep -oE '[0-9]+ modules loaded' <<<"$OUT_A" | grep -oE '[0-9]+' | head -1)
[[ "${MODS_A:-0}" -gt 0 ]] || { echo "$OUT_A"; die "A: binary loaded 0 modules"; }
pass "binary runs with no Python and no network — $MODS_A modules loaded"

# ------------------------------------------ B. full install from wheelhouse
log "Scenario B: Kali + python3, full offline install from wheelhouse"
OUT_B=$(run_isolated "$TESTIMG" '
    command -v pip >/dev/null && { echo "pip unexpectedly present on target"; exit 1; }
    cp -r /bundle /tmp/b && chmod -R u+w /tmp/b && cd /tmp/b
    ./install.sh
    export PATH="$HOME/.local/bin:$PATH"
    printf "exit\n" | purplesploit-src 2>&1 | grep -oE "[0-9]+ modules loaded"
' 2>&1) || { echo "$OUT_B"; die "scenario B failed"; }

grep -q "all files match" <<<"$OUT_B" || { echo "$OUT_B"; die "B: checksum verification did not run"; }
pass "SHA256SUMS verified by installer"
grep -q "imports OK" <<<"$OUT_B" || { echo "$OUT_B"; die "B: import smoke test missing"; }
pass "venv built from vendored wheels with --no-index, imports OK"
MODS_B=$(grep -oE '[0-9]+ modules loaded' <<<"$OUT_B" | grep -oE '[0-9]+' | head -1)
[[ "${MODS_B:-0}" -gt 0 ]] || { echo "$OUT_B"; die "B: source install loaded 0 modules"; }
pass "source install runs — $MODS_B modules loaded"

[[ "$MODS_A" == "$MODS_B" ]] \
    || die "binary loaded $MODS_A modules but source install loaded $MODS_B — they should agree"
pass "binary and source install agree ($MODS_A modules)"

log "All offline verification checks passed"
