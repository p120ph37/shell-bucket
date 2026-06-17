# Self-test for NAT hole punching + establishment (loopback): two peers bind
# UNCONNECTED UDP sockets, exchange authenticated control PING/PONG to nominate a
# candidate pair, connect to it, and transfer a 128KB stream over the punched
# pair. Loopback has no NAT, so this proves the punch handshake + nomination +
# unconnected sendto/recvfrom path (real NAT traversal needs network testing).
B="/b/sb"
SEED=43
PR=39003   # receiver port
PS=39004   # sender port
TOTAL=131072

$B __punchrecv "$PR" 127.0.0.1 "$PS" "$TOTAL" "$SEED" >/tmp/punch.out 2>/dev/null &
RP=$!
sleep 0.2
$B __punchsend "$PS" 127.0.0.1 "$PR" "$TOTAL" "$SEED" >/dev/null 2>&1
wait "$RP" 2>/dev/null

echo "=== NAT hole punch + transfer (loopback) ==="
out=$(cat /tmp/punch.out 2>/dev/null)
if echo "$out" | grep -q "RECV:$TOTAL:OK"; then
  echo "ok:   hole-punch establish + $TOTAL-byte transfer ($out)"
else
  echo "FAIL: hole punch: '$out'"
fi
