#!/bin/sh
# Build static sb binaries for all target arches into ./dist/<os>_<arch>/sb
#
# xx cross-compiles at the compiler stage, so this runs on a single native
# buildx builder with no QEMU. Override the arch set with SB_PLATFORMS.
set -eu
cd "$(dirname "$0")"
PLATFORMS="${SB_PLATFORMS:-linux/amd64,linux/arm64}"
exec docker buildx build --platform "$PLATFORMS" \
  --target dist --output type=local,dest=dist .
