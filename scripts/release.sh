#!/usr/bin/env bash
# Cross-compile as2inspect release binaries + checksums into dist/.
# Usage: ./scripts/release.sh v0.1.0
set -euo pipefail

VER="${1:?usage: release.sh vX.Y.Z}"
cd "$(dirname "$0")/.."
rm -rf dist && mkdir -p dist

targets=("darwin/arm64" "darwin/amd64" "linux/amd64" "linux/arm64" "windows/amd64")
for t in "${targets[@]}"; do
  os="${t%/*}"; arch="${t#*/}"; ext=""
  [ "$os" = "windows" ] && ext=".exe"
  out="dist/as2inspect_${os}_${arch}${ext}"
  GOOS="$os" GOARCH="$arch" go build -ldflags "-X main.version=${VER} -s -w" -o "$out" ./cmd/as2inspect
  echo "built $out"
done

( cd dist && shasum -a 256 as2inspect_* > checksums.txt )
echo "checksums:"; cat dist/checksums.txt
