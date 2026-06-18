#!/bin/sh
# Build the INSTRUMENTED sb binary (SB_TEST=1 → the `__xxx` self-test hooks
# compiled in), THEN run the V self-test suite against the freshly-built
# linux_arm64 binary — gated end to end. `set -e` + build.sh's own
# non-zero-on-failure exit (it's `exec docker buildx … --output local`, which on a
# failed RUN step fails the build and does not write dist-test/) means a broken
# build aborts here before any test runs, so we never test a stale binary. Exits
# non-zero on a build failure OR any self-test FAIL.
#
# The self-tests need the hooks, so they run against the dist-test/ binary —
# NOT the production dist/ one (which omits them by design). Ship dist/; test
# dist-test/.
set -eu
cd "$(dirname "$0")"

SB_TEST=1 ./build.sh

echo "── self-tests (against freshly-built dist-test/linux_arm64/sb) ──"
docker run --rm \
  -v "$PWD/dist-test/linux_arm64/sb:/b/sb:ro" \
  -v "$PWD:/p:ro" \
  -v "$PWD/test:/t:ro" \
  alpine:3.19 sh -c '
    apk add --no-cache bash >/dev/null 2>&1
    fail=0
    for s in /t/*.sh; do
      out=$(sh "$s" 2>&1)
      printf "%s\n" "$out"
      printf "%s\n" "$out" | grep -q "FAIL" && fail=1
    done
    [ "$fail" = 0 ] && echo "── all self-tests passed ──" || echo "── SELF-TEST FAILURES ──"
    exit "$fail"
  '
