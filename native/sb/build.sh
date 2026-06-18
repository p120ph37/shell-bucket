#!/bin/sh
# Build static sb binaries for all target arches into ./dist/<os>_<arch>/sb
#
# xx cross-compiles at the compiler stage, so this runs on a single native
# buildx builder with no QEMU. Override the arch set with SB_PLATFORMS.
#
# Production by default — no test scaffolding (every byte ships over the wire).
# Set SB_TEST=1 to build the INSTRUMENTED binary (the `__xxx` self-test hooks
# compiled in) into ./dist-test instead; check.sh uses that for the V suite.
set -eu
cd "$(dirname "$0")"
PLATFORMS="${SB_PLATFORMS:-linux/amd64,linux/arm64}"
if [ -n "${SB_TEST:-}" ]; then
  exec docker buildx build --platform "$PLATFORMS" --build-arg SB_TEST=1 \
    --target dist --output type=local,dest=dist-test .
fi
exec docker buildx build --platform "$PLATFORMS" \
  --target dist --output type=local,dest=dist .
