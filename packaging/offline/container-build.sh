#!/usr/bin/env bash
#
# Runs INSIDE the kali-rolling builder container (see Dockerfile.builder).
# Not meant to be run on the host — use build-offline-bundle.sh.
#
# Mounts expected:
#   /work  -> repo root (read-only is fine)
#   /out   -> build output directory (writable)
set -euo pipefail

REPO=/work
OUT=/out
PKG_DIR="$REPO/packaging/offline"
WHEELS="$OUT/wheels"

log() { printf '\n\033[1;35m[build]\033[0m %s\n' "$*"; }

log "interpreter: $(python3 -V), pip $(pip --version | awk '{print $2}')"
log "glibc: $(ldd --version | head -1)"

# ---------------------------------------------------------------- wheelhouse
log "Building wheelhouse -> $WHEELS"
mkdir -p "$WHEELS"

# Bootstrap tooling first: install.sh on the air-gapped box needs these before
# it can install anything else with --no-index.
pip download --dest "$WHEELS" pip setuptools wheel

# pip wheel (not pip download) so any sdist-only dependency is compiled to a
# wheel HERE, where a compiler exists. The target box may not have one.
pip wheel --wheel-dir "$WHEELS" -r "$PKG_DIR/requirements-offline.in"

log "wheelhouse: $(ls -1 "$WHEELS" | wc -l) files, $(du -sh "$WHEELS" | cut -f1)"

# ------------------------------------------------- verify + pin (offline test)
# Install from the wheelhouse with the network cut off. This is the real proof
# that the bundle is self-sufficient, and it produces the exact pin list.
log "Verifying wheelhouse installs with --no-index (offline simulation)"
rm -rf /tmp/verifyenv
python3 -m venv /tmp/verifyenv
/tmp/verifyenv/bin/pip install --no-index --find-links "$WHEELS" \
    --upgrade pip setuptools wheel
/tmp/verifyenv/bin/pip install --no-index --find-links "$WHEELS" \
    -r "$PKG_DIR/requirements-offline.in"

/tmp/verifyenv/bin/pip freeze --all > "$OUT/requirements-offline.txt"
log "pinned $(wc -l < "$OUT/requirements-offline.txt") packages -> requirements-offline.txt"

# Import smoke test against the offline-installed deps.
log "Import smoke test (offline venv)"
PYTHONPATH="$REPO/python" /tmp/verifyenv/bin/python -c "
import purplesploit.main
from purplesploit.core.framework import Framework
print('  purplesploit.main + Framework import OK')
"

# --------------------------------------------------------------- onefile bin
log "Building PyInstaller onefile binary"
pip install --no-index --find-links "$WHEELS" \
    -r "$PKG_DIR/requirements-offline.in"

BUILD_TMP=/tmp/pyi
rm -rf "$BUILD_TMP"
mkdir -p "$BUILD_TMP"
cp "$PKG_DIR/entry_frozen.py" "$PKG_DIR/purplesploit.spec" "$BUILD_TMP/"

cd "$BUILD_TMP"
SRC_ROOT="$REPO/python" pyinstaller \
    --noconfirm \
    --clean \
    --distpath "$BUILD_TMP/dist" \
    --workpath "$BUILD_TMP/work" \
    purplesploit.spec

mkdir -p "$OUT/bin"
cp "$BUILD_TMP/dist/purplesploit" "$OUT/bin/purplesploit"
chmod +x "$OUT/bin/purplesploit"
log "binary: $(du -h "$OUT/bin/purplesploit" | cut -f1)  $(file -b "$OUT/bin/purplesploit" | cut -d, -f1-2)"

# ------------------------------------------------------------ binary smoke test
log "Binary smoke test (--version, --help)"
"$OUT/bin/purplesploit" --version
"$OUT/bin/purplesploit" --help > /dev/null && echo "  --help OK"

# Prove module discovery works from the frozen data dir — this is the part most
# likely to silently break, since modules are loaded from .py files on disk and
# PyInstaller cannot see them. Compare against the source tree so a partial
# discovery (some modules failing to import) fails the build too.
log "Binary smoke test (module discovery)"
EXPECTED=$(PYTHONPATH="$REPO/python" /tmp/verifyenv/bin/python -c "
from purplesploit.core.framework import Framework
import tempfile, os
f = Framework(db_path=os.path.join(tempfile.mkdtemp(), 'x.db'))
f.discover_modules()
print(len(f.modules))
")
DISCOVERY_OUT=$(printf 'exit\n' | timeout 120 "$OUT/bin/purplesploit" 2>&1 || true)
FOUND=$(grep -oiE '[0-9]+ modules loaded' <<<"$DISCOVERY_OUT" | head -1 | grep -oE '[0-9]+' || echo 0)

info_ctx() { echo "$DISCOVERY_OUT" | tail -30; }
[[ "$FOUND" -gt 0 ]] \
    || { info_ctx; echo "!! frozen binary loaded 0 modules — modules/ data dir is not reaching \$_MEIPASS"; exit 1; }
[[ "$FOUND" == "$EXPECTED" ]] \
    || { info_ctx; echo "!! frozen binary loaded $FOUND modules, source tree has $EXPECTED — check hiddenimports in purplesploit.spec"; exit 1; }
echo "  module discovery OK: $FOUND/$EXPECTED modules"

log "container build complete"
