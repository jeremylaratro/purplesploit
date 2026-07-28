#!/usr/bin/env bash
#
# PurpleSploit offline installer.
#
# Runs with NO network access. Everything it needs is in this bundle:
#   wheels/  vendored wheels for every dependency (incl. pip/setuptools/wheel)
#   src/     the framework source
#   bin/     a prebuilt onefile binary, if you'd rather not use a venv at all
#
# Usage:
#   ./install.sh                       install to ~/.local/opt/purplesploit
#   ./install.sh --prefix /opt/ps      install somewhere else
#   ./install.sh --binary-only         just drop the onefile binary on PATH
#   ./install.sh --check               verify bundle integrity, install nothing
set -euo pipefail

BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PREFIX="${HOME}/.local/opt/purplesploit"
BINDIR="${HOME}/.local/bin"
MODE=full

log()  { printf '\n\033[1;35m==>\033[0m %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }
die()  { printf '\n\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)      PREFIX="$2"; shift 2 ;;
        --bindir)      BINDIR="$2"; shift 2 ;;
        --binary-only) MODE=binary; shift ;;
        --check)       MODE=check; shift ;;
        -h|--help)     sed -n '2,16p' "$0"; exit 0 ;;
        *)             die "unknown option: $1" ;;
    esac
done

# ------------------------------------------------------------------- integrity
log "Verifying bundle integrity"
if [[ -f "$BUNDLE_DIR/SHA256SUMS" ]]; then
    ( cd "$BUNDLE_DIR" && sha256sum --quiet -c SHA256SUMS ) \
        && info "SHA256SUMS: all files match" \
        || die "checksum mismatch — bundle is corrupt or was modified"
else
    info "SHA256SUMS absent, skipping"
fi

[[ "$MODE" == "check" ]] && { log "Check-only, nothing installed"; exit 0; }

# --------------------------------------------------------------------- binary
install_binary() {
    [[ -x "$BUNDLE_DIR/bin/purplesploit" ]] || die "bin/purplesploit missing"
    mkdir -p "$BINDIR"
    install -m 0755 "$BUNDLE_DIR/bin/purplesploit" "$BINDIR/purplesploit"
    info "installed $BINDIR/purplesploit"
}

if [[ "$MODE" == "binary" ]]; then
    log "Installing onefile binary"
    install_binary
    log "Done"
    info "Run: purplesploit    (ensure $BINDIR is on your PATH)"
    exit 0
fi

# ----------------------------------------------------------------------- venv
log "Checking interpreter"
PY="${PYTHON:-python3}"
command -v "$PY" >/dev/null || die "no python3 found — use ./install.sh --binary-only"

PYVER="$("$PY" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
info "found $PY ($("$PY" -V 2>&1))"

# The wheelhouse was built for one interpreter version. Mismatched ABI tags
# will fail loudly below, but warn early so the cause is obvious.
BUILT_FOR="$(ls "$BUNDLE_DIR"/wheels/*.whl 2>/dev/null \
    | grep -oP 'cp3[0-9]+' | sort -u | tr '\n' ' ' || true)"
if [[ -n "$BUILT_FOR" ]]; then
    TAG="cp${PYVER/./}"
    grep -q "$TAG" <<<"$BUILT_FOR" \
        || info "WARNING: wheelhouse has C-extension wheels for [$BUILT_FOR] but this is $TAG — pure-Python deps will install, compiled ones may not."
fi

log "Creating venv at $PREFIX/venv"
mkdir -p "$PREFIX"
"$PY" -m venv "$PREFIX/venv" \
    || die "venv creation failed — on Debian/Kali: apt install python3-venv"

log "Installing dependencies from vendored wheels (no network)"
"$PREFIX/venv/bin/pip" install --no-index --find-links "$BUNDLE_DIR/wheels" \
    --upgrade pip setuptools wheel
"$PREFIX/venv/bin/pip" install --no-index --find-links "$BUNDLE_DIR/wheels" \
    -r "$BUNDLE_DIR/requirements-offline.txt"

log "Installing source tree"
rsync -a --delete \
    --exclude 'venv/' \
    "$BUNDLE_DIR/src"/ "$PREFIX/app"/ 2>/dev/null \
    || cp -a "$BUNDLE_DIR/src"/. "$PREFIX/app"/

# ------------------------------------------------------------------- launcher
log "Writing launcher"
mkdir -p "$BINDIR"
cat > "$BINDIR/purplesploit-src" <<EOF
#!/usr/bin/env bash
# PurpleSploit launcher (venv + source install)
export PYTHONPATH="$PREFIX/app/python\${PYTHONPATH:+:\$PYTHONPATH}"
export PURPLESPLOIT_DB="\${PURPLESPLOIT_DB:-\$HOME/.local/share/purplesploit/purplesploit.db}"
mkdir -p "\$(dirname "\$PURPLESPLOIT_DB")"
exec "$PREFIX/venv/bin/python" -m purplesploit.main "\$@"
EOF
chmod +x "$BINDIR/purplesploit-src"
info "installed $BINDIR/purplesploit-src"

log "Installing onefile binary alongside"
install_binary || info "binary install skipped"

# ---------------------------------------------------------------- smoke test
log "Smoke test"
PYTHONPATH="$PREFIX/app/python" "$PREFIX/venv/bin/python" -c \
    "import purplesploit.main; from purplesploit.core.framework import Framework; print('    imports OK')"

log "Done"
cat <<EOF

    purplesploit       onefile binary (self-contained)
    purplesploit-src   venv + editable source at $PREFIX/app

    Source:   $PREFIX/app
    Venv:     $PREFIX/venv
    Database: \$HOME/.local/share/purplesploit/purplesploit.db

    Make sure $BINDIR is on your PATH.
    Optional PDF reporting needs system libs — see INSTALL.md.
EOF
