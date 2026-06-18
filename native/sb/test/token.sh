# Self-tests for `sb token` + the mux socket REBIND (the agnostic token-update
# primitive session-recovery launchers build on). `__muxserve` handles a `TOKEN:`
# line by rebinding its listen socket to the new locator + adopting its secret;
# `sb token --token=` / `--randomize` drive that over the socket.
B=/b/sb
T1="aaaaaa:secret1secret1secret1aa"
T2="bbbbbb:secret2secret2secret2bb"
waitsock() { i=0; while [ ! -S "$1" ] && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; }

SB_TOKEN=$T1 $B __muxserve & SP=$!
waitsock /tmp/sb-aaaaaa

echo "=== T1: echo on the initial socket ==="
out=$(SB_TOKEN=$T1 $B __muxclient hi 2>/dev/null)
[ "$out" = hi ] && echo "ok:   initial echo" || echo "FAIL: initial echo ([$out])"

echo "=== T2: sb token --token rebinds the socket to the new locator ==="
SB_TOKEN=$T1 $B token --token=$T2 2>/dev/null; rc=$?
[ "$rc" = 0 ] && echo "ok:   sb token exit 0" || echo "FAIL: sb token rc=$rc"
waitsock /tmp/sb-bbbbbb
[ -S /tmp/sb-bbbbbb ] && echo "ok:   new socket bound" || echo "FAIL: new socket missing"
[ ! -S /tmp/sb-aaaaaa ] && echo "ok:   old socket removed" || echo "FAIL: old socket lingers"

echo "=== T3: new token authenticates; old token's socket is gone ==="
out=$(SB_TOKEN=$T2 $B __muxclient hi2 2>/dev/null)
[ "$out" = hi2 ] && echo "ok:   echo on new socket" || echo "FAIL: new echo ([$out])"
SB_TOKEN=$T1 $B __muxclient x >/dev/null 2>&1; rc=$?
[ "$rc" = 69 ] && echo "ok:   old token -> EX_UNAVAILABLE (69)" || echo "FAIL: old token rc=$rc"

echo "=== T4: --randomize prints a fresh token and moves the socket ==="
NEW=$(SB_TOKEN=$T2 $B token --randomize 2>/dev/null)
case "$NEW" in *?:?*) echo "ok:   randomize printed <locator>:<secret>" ;; *) echo "FAIL: randomize ([$NEW])" ;; esac
LOC=${NEW%%:*}
waitsock "/tmp/sb-$LOC"
[ -S "/tmp/sb-$LOC" ] && echo "ok:   socket at randomized locator" || echo "FAIL: randomized socket"
out=$(SB_TOKEN=$NEW $B __muxclient hi3 2>/dev/null)
[ "$out" = hi3 ] && echo "ok:   echo on randomized socket" || echo "FAIL: randomized echo ([$out])"

kill $SP 2>/dev/null; rm -f /tmp/sb-aaaaaa /tmp/sb-bbbbbb "/tmp/sb-$LOC"
echo "=== done ==="
