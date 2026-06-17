# Self-tests for `sb inject <cmd>` / `sb i <cmd>`: the injector's spawn+relay
# core (no bootstrap feed yet) — forkpty the command and pass bytes through.
B=/b/sb

echo "=== T1: inject relays a command + propagates its exit ==="
out=$(printf '' | $B inject sh -c 'echo HELLO_$((6+1)); exit 7' 2>/dev/null); rc=$?
echo "$out" | grep -q HELLO_7 && echo "ok:   inject relays output" || echo "FAIL: inject output ([$out])"
[ "$rc" = 7 ] && echo "ok:   inject propagates exit (7)" || echo "FAIL: inject exit ($rc)"

echo "=== T2: the injected child gets a pty ==="
printf 'test -t 0 && echo CHILD_TTY=yes || echo CHILD_TTY=no\nexit\n' \
  | $B inject sh 2>/dev/null | grep -q 'CHILD_TTY=yes' \
  && echo "ok:   injected child has a pty" || echo "FAIL: inject pty"

echo "=== T3: no command is a usage error ==="
$B inject </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && echo "ok:   inject no-cmd → 2" || echo "FAIL: inject no-cmd ($rc)"

echo "=== T4: the 'i' alias works ==="
out=$(printf '' | $B i sh -c 'echo VIA_I' 2>/dev/null)
echo "$out" | grep -q VIA_I && echo "ok:   sb i alias" || echo "FAIL: sb i alias ([$out])"

echo "=== done ==="
