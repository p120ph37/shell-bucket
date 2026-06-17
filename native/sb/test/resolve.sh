# Self-tests for sb-manifest parse + os/arch resolution (no pty/network).
#   sb __resolvetest <manifest> <name> [os] [arch]  → "<path>\t<mtime>\t<exec>" | MISS
B=/b/sb
M=/tmp/manifest
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }

# tab-separated manifest
printf '%s\n' \
  "$(printf 'linux_arm64/sb\t100\tx')" \
  "$(printf 'linux_arm64/imgcat\t200\tx')" \
  "$(printf 'linux/imgcat\t150\tx')" \
  "$(printf 'imgcat\t50\tx')" \
  "$(printf 'myenvvars.sh\t60\t')" \
  "$(printf 'sb-bash.rc\t70\t')" > "$M"

r() { $B __resolvetest "$M" "$1" "$2" "$3"; }

ck "os+arch specific wins"  "$(printf 'linux_arm64/imgcat\t200\ttrue')"  "$(r imgcat Linux aarch64)"
ck "falls back to os"        "$(printf 'linux/imgcat\t150\ttrue')"        "$(r imgcat Linux x86_64)"
ck "falls back to root"      "$(printf 'imgcat\t50\ttrue')"               "$(r imgcat Darwin arm64)"
ck "sb binary path"          "$(printf 'linux_arm64/sb\t100\ttrue')"      "$(r sb Linux aarch64)"
ck "non-exec flag"           "$(printf 'myenvvars.sh\t60\tfalse')"        "$(r myenvvars.sh Linux aarch64)"
ck "miss"                    "MISS"                                       "$(r nope Linux aarch64)"
# explicit cross-platform path: a linux/amd64 host names an arm64 path → root match
ck "explicit cross-arch path" "$(printf 'linux_arm64/sb\t100\ttrue')"    "$(r linux_arm64/sb linux amd64)"
# no os/arch → root only
ck "no os/arch → root"       "$(printf 'imgcat\t50\ttrue')"               "$(r imgcat)"
echo "=== done ==="
