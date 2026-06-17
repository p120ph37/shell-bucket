# Self-test for the reliable-UDP stack over REAL UDP sockets (loopback): a
# receiver and sender process establish connected UDP sockets and the ARQ
# transfers a 256KB deterministic stream, verified byte-for-byte. Exercises the
# live send/recv + monotonic-clock driver (no loss on loopback, so this proves
# the socket/clock plumbing, complementing arq.sh's simulated-loss coverage).
B="/b/sb"
SEED=42
PR=39001   # receiver port
PS=39002   # sender port
TOTAL=262144

$B __arqrecv "$PR" 127.0.0.1 "$PS" "$TOTAL" "$SEED" >/tmp/arqudp.out 2>/dev/null &
RP=$!
sleep 0.3
$B __arqsend 127.0.0.1 "$PR" "$PS" "$TOTAL" "$SEED" >/dev/null 2>&1
wait "$RP" 2>/dev/null

echo "=== Reliable-UDP over real sockets ==="
out=$(cat /tmp/arqudp.out 2>/dev/null)
if echo "$out" | grep -q "RECV:$TOTAL:OK"; then
  echo "ok:   ARQ transfers $TOTAL bytes over real UDP sockets ($out)"
else
  echo "FAIL: ARQ over UDP sockets: '$out'"
fi
