#!/usr/bin/env bash
#
# Build a fully self-contained PurpleSploit bundle for an air-gapped Kali box.
#
# Produces, in build/offline/:
#   purplesploit-offline-<version>-<date>/          the bundle
#   purplesploit-offline-<version>-<date>.tar.zst   the shippable archive
#   ...sha256                                       checksum of the archive
#
# The bundle contains BOTH delivery forms:
#   bin/purplesploit  — PyInstaller onefile, no Python needed on target
#   wheels/ + src/    — vendored wheels + source, installed by install.sh into a
#                       venv, for when you need to read or edit the code
#
# Everything is built inside a kali-rolling container so the wheel tags and the
# glibc the binary links against match the target, not this Fedora host.
#
# Usage:  ./packaging/offline/build-offline-bundle.sh [--no-binary] [--no-wheels]
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG_DIR="$REPO_ROOT/packaging/offline"
BUILD_DIR="$REPO_ROOT/build/offline"
IMAGE=purplesploit-offline-builder:kali

VERSION="$(grep -oP 'version="\K[0-9.]+' "$REPO_ROOT/python/setup.py" | head -1)"
STAMP="$(date +%d%b%Y | tr '[:lower:]' '[:upper:]')"
BUNDLE_NAME="purplesploit-offline-${VERSION}-${STAMP}"
BUNDLE="$BUILD_DIR/$BUNDLE_NAME"
STAGE="$BUILD_DIR/.stage"

CONTAINER=${CONTAINER:-$(command -v docker >/dev/null && echo docker || echo podman)}

log() { printf '\n\033[1;35m==>\033[0m %s\n' "$*"; }
die() { printf '\n\033[1;31m!!\033[0m %s\n' "$*" >&2; exit 1; }

command -v "$CONTAINER" >/dev/null || die "need docker or podman"
command -v rsync >/dev/null || die "need rsync"

log "PurpleSploit $VERSION -> $BUNDLE_NAME"
rm -rf "$BUNDLE" "$STAGE"
mkdir -p "$BUNDLE" "$STAGE"

# ------------------------------------------------------------------ 1. image
log "Building builder image ($IMAGE)"
"$CONTAINER" build -f "$PKG_DIR/Dockerfile.builder" -t "$IMAGE" "$PKG_DIR"

# ------------------------------------------ 2. wheelhouse + binary (in Kali)
log "Running container build (wheelhouse + onefile binary)"
# Run as the invoking uid so the wheelhouse and binary aren't root-owned.
"$CONTAINER" run --rm \
    --user "$(id -u):$(id -g)" \
    -e HOME=/tmp \
    -v "$REPO_ROOT:/work:ro" \
    -v "$STAGE:/out:z" \
    "$IMAGE" \
    bash /work/packaging/offline/container-build.sh

[[ -d "$STAGE/wheels" ]] || die "wheelhouse missing from container output"
[[ -f "$STAGE/bin/purplesploit" ]] || die "binary missing from container output"

mv "$STAGE/wheels" "$BUNDLE/wheels"
mv "$STAGE/bin" "$BUNDLE/bin"
mv "$STAGE/requirements-offline.txt" "$BUNDLE/requirements-offline.txt"

# ------------------------------------------------------------------ 3. source
log "Staging source tree"
mkdir -p "$BUNDLE/src"
rsync -a \
    --exclude '.git/' \
    --exclude 'build/' \
    --exclude 'training/' \
    --exclude 'htmlcov/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    --exclude '.mypy_cache/' \
    --exclude 'node_modules/' \
    --exclude '*.pyc' \
    --exclude '.coverage' \
    --exclude '.data/' \
    --exclude 'enum_output/' \
    --exclude '*.db' \
    "$REPO_ROOT"/ "$BUNDLE/src"/

# ----------------------------------------------------------------- 4. wrapper
log "Adding installer and docs"
cp "$PKG_DIR/bundle/install.sh" "$BUNDLE/install.sh"
cp "$PKG_DIR/bundle/INSTALL.md" "$BUNDLE/INSTALL.md"
chmod +x "$BUNDLE/install.sh"

cat > "$BUNDLE/VERSION" <<EOF
purplesploit  $VERSION
bundled       $(date -u +%Y-%m-%dT%H:%M:%SZ)
git_commit    $(git -C "$REPO_ROOT" rev-parse HEAD)
git_branch    $(git -C "$REPO_ROOT" rev-parse --abbrev-ref HEAD)
built_on      kalilinux/kali-rolling ($("$CONTAINER" run --rm "$IMAGE" bash -c 'grep VERSION_ID /etc/os-release'))
target        linux x86_64, glibc >= $("$CONTAINER" run --rm "$IMAGE" bash -c 'ldd --version | head -1 | grep -oP "[0-9]+\.[0-9]+$"')
EOF

# --------------------------------------------------------------- 5. checksums
log "Generating SHA256SUMS"
( cd "$BUNDLE" && find . -type f ! -name SHA256SUMS -print0 \
    | sort -z | xargs -0 sha256sum > SHA256SUMS )

# ----------------------------------------------------------------- 6. archive
log "Creating archive"
ARCHIVE="$BUILD_DIR/${BUNDLE_NAME}.tar.zst"
if command -v zstd >/dev/null; then
    tar -C "$BUILD_DIR" -cf - "$BUNDLE_NAME" | zstd -19 -T0 -o "$ARCHIVE" -f
else
    ARCHIVE="$BUILD_DIR/${BUNDLE_NAME}.tar.gz"
    tar -C "$BUILD_DIR" -czf "$ARCHIVE" "$BUNDLE_NAME"
fi
sha256sum "$ARCHIVE" > "$ARCHIVE.sha256"

rm -rf "$STAGE"

log "Done"
printf '  bundle   %s (%s)\n' "$BUNDLE" "$(du -sh "$BUNDLE" | cut -f1)"
printf '  archive  %s (%s)\n' "$ARCHIVE" "$(du -h "$ARCHIVE" | cut -f1)"
printf '  sha256   %s\n' "$(cut -d' ' -f1 < "$ARCHIVE.sha256")"
