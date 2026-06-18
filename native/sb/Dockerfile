# syntax=docker/dockerfile:1
# Cross-compile sb to static musl binaries: V → C → xx-clang.
#
# The build stage runs on the NATIVE build platform; xx-clang cross-compiles the
# generated C to each TARGETPLATFORM, so no QEMU/emulation is needed for codegen.
# The final `scratch` stage only COPYs the finished binary (no execution), so a
# single native builder produces all target arches.
#
# Build (from this dir):
#   docker buildx build --platform linux/amd64,linux/arm64 \
#     --target dist --output type=local,dest=dist .
# → dist/linux_amd64/sb, dist/linux_arm64/sb

FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.9.0 AS xx

FROM --platform=$BUILDPLATFORM thevlang/vlang:alpine AS build
COPY --from=xx / /
RUN apk add --no-cache clang lld git
ARG TARGETPLATFORM
RUN xx-apk add --no-cache musl-dev gcc
WORKDIR /work
COPY v.mod ./
COPY csrc/ ./csrc/
# AES-GCM crypto object: clone BearSSL at a pinned release (in-container only —
# never vendored into the workspace) and cross-compile the five objects an
# AES-CT-GCM AEAD needs plus our shim into one relocatable object the V link
# pulls in via `#flag`. xx-clang targets TARGETPLATFORM, matching the V build.
ARG BEARSSL_TAG=v0.6
RUN git clone --depth=1 --branch ${BEARSSL_TAG} https://www.bearssl.org/git/BearSSL /tmp/bearssl \
 && mkdir -p /work/build \
 && B=/tmp/bearssl \
 && xx-clang -Oz -ffunction-sections -fdata-sections \
      -I$B/inc -I$B/src -I/work/csrc -r -o /work/build/sbcrypto.o \
      $B/src/symcipher/aes_ct.c $B/src/symcipher/aes_ct_enc.c \
      $B/src/symcipher/aes_ct_ctr.c $B/src/aead/gcm.c \
      $B/src/hash/ghash_ctmul.c /work/csrc/sb_aead.c \
 && rm -rf /tmp/bearssl
# Stream-compression object: clone zlib at a pinned release (in-container only) and
# cross-compile the raw-deflate core + our streaming shim into one relocatable
# object the V link pulls in via `#flag` (gc-sections drops the unused pieces).
ARG ZLIB_TAG=v1.3.1
RUN git clone --depth=1 --branch ${ZLIB_TAG} https://github.com/madler/zlib /tmp/zlib \
 && Z=/tmp/zlib \
 && xx-clang -Oz -ffunction-sections -fdata-sections \
      -I$Z -I/work/csrc -r -o /work/build/sbzlib.o \
      $Z/adler32.c $Z/crc32.c $Z/deflate.c $Z/inflate.c \
      $Z/inftrees.c $Z/inffast.c $Z/trees.c $Z/zutil.c \
      /work/csrc/sb_deflate.c \
 && rm -rf /tmp/zlib
COPY src/ ./src/
# SB_TEST=1 adds `-d sb_test`, compiling in the `__xxx` self-test hooks (and the
# test-only helpers they reach). The DEFAULT (unset) is a clean PRODUCTION binary:
# `-skip-unused` (implied by -prod) + `--gc-sections` then sweep all that
# scaffolding out, so the shipped `sb` carries no test code. check.sh builds with
# SB_TEST=1 to get a binary the V self-test suite can drive.
ARG SB_TEST=
# Symbol policy diverges by build:
#   production (default) — `-Wl,-s` strips the symbol table: every byte ships over
#                          the wire, so the binary carries no symbols/debug info.
#   test (SB_TEST=1)     — KEEP symbols + `-g` line info: the instrumented binary
#                          never ships, so richer backtraces on a self-test crash
#                          are worth the size.
# -gc none: the sb is a long-lived byte-pump with preallocated buffers and no
# GC pressure; it also sidesteps static-linking the boehm GC against musl.
RUN mkdir -p /out \
 && if [ -n "$SB_TEST" ]; then \
      V_DFLAGS='-d sb_test -g'; LD_STRIP=''; \
    else \
      V_DFLAGS=''; LD_STRIP='-Wl,-s'; \
    fi \
 && v -enable-globals ${V_DFLAGS} -cc xx-clang -gc none -prod -cflags "-Oz -ffunction-sections -fdata-sections -Wl,--gc-sections ${LD_STRIP} -static" -o /out/sb ./src \
 && xx-verify --static /out/sb

FROM scratch AS dist
COPY --from=build /out/sb /sb
