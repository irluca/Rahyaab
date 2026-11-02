#!/usr/bin/env bash
# Build a verified Rahyaab release: a tarball plus its SHA256SUMS.
#
# Usage: bash scripts/build-release.sh [VERSION] [SRC_DIR] [OUT_DIR]
#   VERSION defaults to the VERSION in install.sh; SRC_DIR defaults to
#   the repository root; OUT_DIR defaults to <repo>/dist.
# Publish the two files as assets of a GitHub release, e.g.:
#   gh release create v1.7.0 dist/rahyaab-v1.7.0.tar.gz dist/SHA256SUMS
# Installers then fetch them with: bash install.sh --release v1.7.0
# and refuse to install anything when a hash does not match.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="${1:-$(grep -m1 '^VERSION=' "$ROOT/install.sh" | cut -d'"' -f2)}"
SRC="${2:-$ROOT}"
OUT="${3:-$ROOT/dist}"
mkdir -p "$OUT"
TARBALL="$OUT/rahyaab-$VERSION.tar.gz"
(cd "$SRC" && tar --exclude=.git --exclude=dist --exclude=__pycache__ \
    --exclude='*.pyc' --exclude='*.bak-*' -czf "$TARBALL" .)
(cd "$OUT" && sha256sum "rahyaab-$VERSION.tar.gz" > SHA256SUMS)
echo "Built $TARBALL"
cat "$OUT/SHA256SUMS"
