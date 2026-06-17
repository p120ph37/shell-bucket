# Self-tests for prune_cache: cache reconciliation at manifest-load (no fetching).
#   sb __prunetest <cache> <manifest-file>
B=/b/sb
C=/tmp/pc
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }

rm -rf "$C"; mkdir -p "$C/linux_arm64"
# A STALE flat sb (old mtime) — must NEVER be demoted: it's the autovivify target.
printf '#!/bin/sh\n' > "$C/sb"; chmod +x "$C/sb"; touch -d @50 "$C/sb"

# manifest: keep@200 (exec), stale@200 (exec), frag@200 (non-exec)
printf 'linux_arm64/keep\t200\tx\nlinux_arm64/stale\t200\tx\nrc.d/frag\t200\t\n' > "$C/manifest"

# cached files:
printf 'KEEP\n'  > "$C/linux_arm64/keep";  chmod +x "$C/linux_arm64/keep";  touch -d @200 "$C/linux_arm64/keep"   # current exec → keep
printf 'STALE\n' > "$C/linux_arm64/stale"; chmod +x "$C/linux_arm64/stale"; touch -d @100 "$C/linux_arm64/stale"  # stale exec → demote
printf 'GONE\n'  > "$C/linux_arm64/gone";  chmod +x "$C/linux_arm64/gone";  touch -d @100 "$C/linux_arm64/gone"   # deleted exec → rm
mkdir -p "$C/rc.d"
printf 'OLDFRAG\n' > "$C/rc.d/oldfrag"; touch -d @100 "$C/rc.d/oldfrag"   # deleted NON-exec → rm
printf 'FRAG\n'    > "$C/rc.d/frag";    touch -d @100 "$C/rc.d/frag"      # stale NON-exec → keep

$B __prunetest "$C" "$C/manifest"

[ -f "$C/linux_arm64/keep" ] && [ ! -L "$C/linux_arm64/keep" ] && echo "ok:   current binary kept" || echo "FAIL: keep"
[ -L "$C/linux_arm64/stale" ] && echo "ok:   stale binary demoted to symlink" || echo "FAIL: stale not demoted"
ck "  demoted symlink → sb" "$C/sb" "$(readlink "$C/linux_arm64/stale")"
[ ! -e "$C/linux_arm64/gone" ] && echo "ok:   upstream-deleted binary removed" || echo "FAIL: gone not removed"
[ ! -e "$C/rc.d/oldfrag" ] && echo "ok:   deleted non-binary removed" || echo "FAIL: oldfrag kept"
[ -f "$C/rc.d/frag" ] && [ ! -L "$C/rc.d/frag" ] && echo "ok:   stale non-binary kept" || echo "FAIL: frag touched"
[ -f "$C/sb" ] && [ ! -L "$C/sb" ] && echo "ok:   stale sb NOT demoted (autovivify target)" || echo "FAIL: sb demoted/touched"
echo "=== done ==="
