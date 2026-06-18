# Self-tests for `sb mux` dispatch-dir population (no pty/network).
#   sb __bintest <bindir> <self> <manifest>  -> populate <bindir>
# The dispatch set is every executable manifest entry's basename, plus `sb`,
# minus only `sb` itself + the (sourced) rc.d fragments. Executable `sb-*` SCRIPTS
# (e.g. the sb-tmux.sh launcher) ARE included so they autovivify via $PATH; the
# non-exec `.rc` runtimes / manifest fall out by the exec filter. Links -> <self>.
# Inspected with the shell (not os.ls -- populate_bin prunes before it creates,
# and os.ls under-reports same-process-created links in this static build).
B=/b/sb
D=/tmp/bin
M=/tmp/binmanifest
S=/b/sb            # symlink target (stands in for the cached binary)
ck() { if [ "$2" = "$3" ]; then echo "ok:   $1"; else echo "FAIL: $1 (exp=[$2] got=[$3])"; fi; }
dir() { ls "$D" 2>/dev/null | sort | tr '\n' ' '; }

printf '%s\n' \
  "$(printf 'linux_arm64/sb\t100\tx')" \
  "$(printf 'linux_arm64/imgcat\t200\tx')" \
  "$(printf 'imgcat\t50\tx')" \
  "$(printf 'it2copy\t60\tx')" \
  "$(printf 'sb-tmux.sh\t75\tx')" \
  "$(printf 'myenvvars.sh\t70\t')" \
  "$(printf 'sb-bash.rc\t80\t')" \
  "$(printf 'rc.d/00-x.sh\t90\t')" > "$M"

rm -rf "$D"
$B __bintest "$D" "$S" "$M"
ck "dispatch set (execs + sb-* scripts + sb; not .rc/rc.d/non-exec)" "imgcat it2copy sb sb-tmux.sh " "$(dir)"
ck "imgcat -> self"     "$S" "$(readlink "$D/imgcat")"
ck "sb -> self"         "$S" "$(readlink "$D/sb")"
ck "sb-tmux.sh -> self (autoviv launcher)" "$S" "$(readlink "$D/sb-tmux.sh")"
ck "sb-bash.rc NOT dispatched"  "" "$(readlink "$D/sb-bash.rc" 2>/dev/null)"

# Re-run with imgcat dropped + a new helper: prune imgcat, add other, keep sb.
printf '%s\n' \
  "$(printf 'it2copy\t60\tx')" \
  "$(printf 'other\t65\tx')" > "$M"
$B __bintest "$D" "$S" "$M"
ck "prune stale + add new" "it2copy other sb " "$(dir)"
ck "imgcat pruned" "" "$(readlink "$D/imgcat" 2>/dev/null)"

# A non-executable-only manifest -> just `sb`.
printf 'myenvvars.sh\t70\t\n' > "$M"
$B __bintest "$D" "$S" "$M"
ck "exec-less manifest -> sb only" "sb " "$(dir)"

# Stale entries left by a prior session (regular files + links) are all pruned.
rm -rf "$D"; mkdir -p "$D"; touch "$D/oldfile"; ln -s /x "$D/oldlink"
printf 'keep\t10\tx\n' > "$M"
$B __bintest "$D" "$S" "$M"
ck "prune prior-session cruft" "keep sb " "$(dir)"
echo "=== done ==="
