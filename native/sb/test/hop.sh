# Self-tests for `sb hop <cmd>` / `sb h <cmd>`: the spawn+relay core (no bootstrap
# feed yet) — forkpty the command and pass bytes through.
B=/b/sb

echo "=== T1: hop relays a command + propagates its exit ==="
out=$(printf '' | $B hop sh -c 'echo HELLO_$((6+1)); exit 7' 2>/dev/null); rc=$?
echo "$out" | grep -q HELLO_7 && echo "ok:   hop relays output" || echo "FAIL: hop output ([$out])"
[ "$rc" = 7 ] && echo "ok:   hop propagates exit (7)" || echo "FAIL: hop exit ($rc)"

echo "=== T2: the spawned child gets a pty ==="
printf 'test -t 0 && echo CHILD_TTY=yes || echo CHILD_TTY=no\nexit\n' \
  | $B hop sh 2>/dev/null | grep -q 'CHILD_TTY=yes' \
  && echo "ok:   spawned child has a pty" || echo "FAIL: hop pty"

echo "=== T3: no command is a usage error ==="
$B hop </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && echo "ok:   hop no-cmd → 2" || echo "FAIL: hop no-cmd ($rc)"

echo "=== T4: the 'h' alias works ==="
out=$(printf '' | $B h sh -c 'echo VIA_H' 2>/dev/null)
echo "$out" | grep -q VIA_H && echo "ok:   sb h alias" || echo "FAIL: sb h alias ([$out])"

echo "=== done ==="
