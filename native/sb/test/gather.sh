# Self-test for mux-side server-reflexive (srflx) candidate gathering (loopback).
# A fake STUN observer (__stunserver) reports a fixed "public" mapping; the mux
# gather path (__gatherprobe -> real start_backhaul) queries it on its punch socket
# and must surface that mapping as its srflx AND include it in the UP:A candidate
# set. Proves non-blocking, on-socket STUN gathering for cone-NAT topologies.
# (Symmetric NAT can't be handled by STUN -- the mux falls back to in-band; that
# path is the no-STUN-servers branch already covered by the upgrade E2E test.)
B="/b/sb"
SPORT=34780          # fake STUN observer port
PUB_IP=198.51.100.77 # the "public" mapping it reports (TEST-NET-2)
PUB_PORT=41234
WRAP_IP=203.0.113.9  # a wrapper candidate to name in the offer (TEST-NET-3)
WRAP_PORT=50000

$B __stunserver "$SPORT" "$PUB_IP" "$PUB_PORT" >/dev/null 2>&1 &
SP=$!
sleep 0.3            # let the observer bind before the gather burst
out=$($B __gatherprobe 127.0.0.1 "$SPORT" "$WRAP_IP" "$WRAP_PORT" 2>&1)
wait "$SP" 2>/dev/null

echo "=== mux-side srflx gathering (loopback) ==="
if echo "$out" | grep -q "srflx: $PUB_IP:$PUB_PORT"; then
  echo "ok:   gathered srflx via STUN ($PUB_IP:$PUB_PORT)"
else
  echo "FAIL: srflx not gathered: '$out'"
fi
if echo "$out" | grep "cands:" | grep -q "$PUB_IP:$PUB_PORT"; then
  echo "ok:   srflx included in UP:A candidate set"
else
  echo "FAIL: srflx missing from answer cands: '$out'"
fi
