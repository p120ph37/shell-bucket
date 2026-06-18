# Self-tests for sb run / fetch / symlink-dispatch (manifest-driven, no pty).
# Env carries the session context the mux would export.
B=/b/sb
C=/tmp/cache
E="SB_CACHE=$C SB_TOKEN=T SB_OS=Linux SB_ARCH=aarch64"
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }
setup() { rm -rf "$C"; mkdir -p "$C"; printf 'imgcat\t100\tx\n' > "$C/sb-manifest"; }

# T1: fresh cache (mtime matches manifest) -> exec directly, no fetch
setup
printf '#!/bin/sh\necho "RAN[$1]"\n' > "$C/imgcat"; chmod +x "$C/imgcat"; touch -d @100 "$C/imgcat"
ck "run fresh -> exec" "RAN[hello]" \
  "$(env $E $B run imgcat hello </dev/null 2>/dev/null)"

# T2: symlink dispatch (argv0=imgcat) -> same as run
ln -sf "$B" /tmp/imgcat
ck "symlink dispatch" "RAN[sym]" \
  "$(env $E /tmp/imgcat sym </dev/null 2>/dev/null)"

# T3: stale/absent -> fetch (canned response) then exec
setup
resp="$(printf '#!/bin/sh\necho "FETCHED[$1]"\n' | base64 | tr -d '\n')"
out="$(printf '%s\n~EOF chmod=+x mtime=100\n' "$resp" | env $E $B run imgcat go 2>/dev/null | tr -d '\033\\')"
case "$out" in
  *"FETCHED[go]"*) echo "ok:   run stale -> fetch -> exec" ;;
  *) echo "FAIL: run stale -> fetch -> exec ([$out])" ;;
esac

# T4: fetch prints the resolved cache path -- on STDERR (stdout is the live
# protocol channel; capturing it would swallow the FILEREQ).
setup
printf '#!/bin/sh\n' > "$C/imgcat"; chmod +x "$C/imgcat"; touch -d @100 "$C/imgcat"
ck "fetch prints path (stderr)" "$C/imgcat" \
  "$(env $E $B fetch imgcat </dev/null 2>&1 >/dev/null)"

# T5: unknown tool -> exit 127
setup
env $E $B run nonesuch </dev/null >/dev/null 2>/dev/null
ck "run unknown -> 127" "127" "$?"

# T6: NO manifest (bootstrap) -> ensure_manifest fetches it FIRST, then resolves
# tmux client-side and fetches the arch path. Two canned responses on stdin.
rm -rf "$C"; mkdir -p "$C"
man="$(printf 'linux_arm64/tmux\t200\tx\n' | base64 | tr -d '\n')"
bin="$(printf 'TMUXBIN' | base64 | tr -d '\n')"
out="$(printf '%s\n~EOF\n%s\n~EOF chmod=+x mtime=200\n' "$man" "$bin" \
  | env $E $B fetch tmux 2>/dev/null | tr -d '\033\\')"
case "$out" in
  *"FILEREQ:sb-manifest:mtime=0"*) echo "ok:   auto-fetches manifest first" ;;
  *) echo "FAIL: manifest auto-fetch ([$out])" ;;
esac
case "$out" in
  *"FILEREQ:linux_arm64/tmux:mtime=0"*) echo "ok:   resolves arch path client-side" ;;
  *) echo "FAIL: client-side resolve ([$out])" ;;
esac
ck "tmux written to resolved path" "TMUXBIN" "$(cat "$C/linux_arm64/tmux" 2>/dev/null)"

# T7: cached file NEWER than the manifest mtime -> align the stamp, do NOT refetch
# (the shell-bootstrapped binary case). stdin is empty: a refetch would fail -> 127.
setup
printf '#!/bin/sh\necho "FIXED[$1]"\n' > "$C/imgcat"; chmod +x "$C/imgcat"; touch -d @200 "$C/imgcat"
ck "fixup: runs cached, no refetch" "FIXED[hi]" \
  "$(env $E $B run imgcat hi </dev/null 2>/dev/null)"
ck "fixup: mtime aligned to manifest" "100" \
  "$(stat -c %Y "$C/imgcat" 2>/dev/null || stat -f %m "$C/imgcat")"
echo "=== done ==="
