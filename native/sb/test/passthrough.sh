# sb pass-through + env-driven-launch checks. No `set -e`: cases exit
# non-zero on purpose (we assert the propagated code), which would abort the run.
#
# The pump is `sb __pumptest` -- the pure pass-through pump in isolation (SB_SHELL /
# SB_RC_FILE driven, no wrapper). `sb mux` wraps this with protocol startup
# (mux_setup: manifest/runtime fetch + dispatch symlinks), exercised end-to-end
# by the Python integration suite instead.
B="/b/sb __pumptest"

echo "=== T1: pass-through + exit-code propagation (SB_SHELL, piped stdin) ==="
out=$(printf 'echo HELLO_$((1+1))\nexit 7\n' | SB_SHELL=/bin/sh $B); rc=$?
echo "$out" | grep -q HELLO_2 && echo "T1 output: ok" || echo "T1 output: FAIL"
[ "$rc" = 7 ] && echo "T1 exit-code: ok (7)" || echo "T1 exit-code: FAIL ($rc)"

echo "=== T2: missing SB_SHELL is a usage error ==="
SB_SHELL= $B </dev/null >/dev/null 2>&1; rc=$?
[ "$rc" = 2 ] && echo "T2: ok (2)" || echo "T2: FAIL ($rc)"

echo "=== T3: SB_RC_FILE honored via --rcfile for bash ==="
printf 'exit\n' | SB_SHELL=/bin/bash SB_RC_FILE=/p/test/marker.rc $B 2>/dev/null \
  | grep -q RC_SOURCED_OK && echo "T3: ok (rcfile sourced)" || echo "T3: FAIL"

echo "=== T4: sb allocates a pty for the child (sb's own stdin is a pipe) ==="
printf 'test -t 0 && echo CHILD_TTY=yes || echo CHILD_TTY=no\nexit\n' \
  | SB_SHELL=/bin/sh $B 2>/dev/null \
  | grep -q 'CHILD_TTY=yes' && echo "T4: ok (child has a pty)" || echo "T4: FAIL"

echo "=== done ==="
