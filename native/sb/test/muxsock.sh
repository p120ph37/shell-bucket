# Self-tests for the mux socket: constant-time bearer-auth + echo roundtrip
# + sysexits failure codes. The token is `<locator>:<secret>`.
B=/b/sb
TOK="abcdef:0123456789abcdefgh"         # locator=abcdef secret=0123456789abcdefgh

SB_TOKEN=$TOK $B __muxserve & SP=$!    # bring the mux socket up in the background
i=0                                       # wait for the socket to actually bind
while [ ! -S /tmp/sb-abcdef ] && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done

echo "=== T1: auth + echo roundtrip (exit 0) ==="
out=$(SB_TOKEN=$TOK $B __muxclient "HELLO_AGENT" 2>/dev/null); rc=$?
[ "$out" = "HELLO_AGENT" ] && echo "ok:   echo roundtrip" || echo "FAIL: echo ([$out] rc=$rc)"
[ "$rc" = 0 ] && echo "ok:   success exit 0" || echo "FAIL: success exit ($rc)"

echo "=== T2: socket is at /tmp/sb-<locator>, mode 0600 ==="
[ -S /tmp/sb-abcdef ] && echo "ok:   socket at /tmp/sb-abcdef" || echo "FAIL: socket path"
perms=$(stat -c %a /tmp/sb-abcdef 2>/dev/null || stat -f %Lp /tmp/sb-abcdef 2>/dev/null)
[ "$perms" = "600" ] && echo "ok:   socket 0600" || echo "FAIL: perms ([$perms])"

echo "=== T3: same locator, WRONG secret → EX_NOPERM (77) ==="
WRONG="abcdef:WRONGsecretWRONGxx"         # same locator (same socket), bad secret
SB_TOKEN=$WRONG $B __muxclient "x" >/dev/null 2>&1; rc=$?
[ "$rc" = 77 ] && echo "ok:   wrong secret → 77" || echo "FAIL: noperm ($rc)"

echo "=== T4: no socket for this locator → EX_UNAVAILABLE (69) ==="
NOSRV="zzzzzz:0123456789abcdefgh"         # locator with no server
SB_TOKEN=$NOSRV $B __muxclient "x" >/dev/null 2>&1; rc=$?
[ "$rc" = 69 ] && echo "ok:   no socket → 69" || echo "FAIL: unavailable ($rc)"

echo "=== T5: socket-exists guard (concurrent-mux edge case) ==="
# LIVE: the running server's socket → a new sb mux would refuse.
[ "$($B __bindprobe /tmp/sb-abcdef)" = LIVE ] && echo "ok:   live socket → LIVE" || echo "FAIL: live probe"
# FREE: nonexistent path → a new sb mux binds cleanly.
[ "$($B __bindprobe /tmp/sb-none)" = FREE ] && echo "ok:   absent path → FREE" || echo "FAIL: free probe"
# STALE: a plain file (no listener) → a new sb mux unlinks + binds.
: > /tmp/sb-stalefile
[ "$($B __bindprobe /tmp/sb-stalefile)" = STALE ] && echo "ok:   dead file → STALE" || echo "FAIL: stale probe"
rm -f /tmp/sb-stalefile

kill $SP 2>/dev/null; rm -f /tmp/sb-abcdef
echo "=== done ==="
