# Self-tests for `sb ctl` (control/status) against the __muxserve stub.
# Exercises the STATUS wire protocol, the pretty-printed output shape, and the
# BH:DOWN / BH:UP control verbs -- all over the real bearer-auth socket handshake.
B=/b/sb
T="cccccc:secret3secret3secret3cc"
waitsock() { i=0; while [ ! -S "$1" ] && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; }

SB_TOKEN=$T $B __muxserve & SP=$!
waitsock /tmp/sb-cccccc

echo "=== sb ctl status ==="
out=$(SB_TOKEN=$T $B ctl status 2>/dev/null)
echo "$out" | grep -q "sb mux status" && echo "ok:   status header present" || echo "FAIL: status header missing"
echo "$out" | grep -q "depth:"        && echo "ok:   depth field present"   || echo "FAIL: depth missing"
echo "$out" | grep -q "uptime:"       && echo "ok:   uptime field present"  || echo "FAIL: uptime missing"
echo "$out" | grep -q "Channel"       && echo "ok:   channel section"       || echo "FAIL: channel missing"
echo "$out" | grep -q "tx:"           && echo "ok:   tx stat present"       || echo "FAIL: tx stat missing"
echo "$out" | grep -q "PTY"           && echo "ok:   PTY section"           || echo "FAIL: PTY section missing"
echo "$out" | grep -q "Side-channel"  && echo "ok:   side-channel line"     || echo "FAIL: side-channel missing"
echo "$out" | grep -q "inactive"      && echo "ok:   bh_state inactive"     || echo "FAIL: inactive missing"
echo "$out" | grep -q "Clients:"      && echo "ok:   clients line"          || echo "FAIL: clients missing"
echo "$out" | grep -q "relays"        && echo "ok:   relays field"          || echo "FAIL: relays missing"
echo "$out" | grep -q "ports"         && echo "ok:   ports field"           || echo "FAIL: ports missing"
echo "$out" | grep -q "RPCs"          && echo "ok:   RPCs field"            || echo "FAIL: RPCs missing"

echo "=== sb ctl (no args = status) ==="
out2=$(SB_TOKEN=$T $B ctl 2>/dev/null)
echo "$out2" | grep -q "sb mux status" && echo "ok:   no-arg == status" || echo "FAIL: no-arg output"

echo "=== sb ctl down ==="
SB_TOKEN=$T $B ctl down >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl down exit 0" || echo "FAIL: ctl down rc=$rc"

echo "=== sb ctl up ==="
SB_TOKEN=$T $B ctl up >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl up exit 0" || echo "FAIL: ctl up rc=$rc"

echo "=== sb ctl reneg with candidates ==="
SB_TOKEN=$T $B ctl reneg 1.2.3.4:5678 >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl reneg with candidates exit 0" || echo "FAIL: ctl reneg rc=$rc"

echo "=== sb control alias ==="
out3=$(SB_TOKEN=$T $B control status 2>/dev/null)
echo "$out3" | grep -q "sb mux status" && echo "ok:   'control' alias works" || echo "FAIL: control alias"

kill $SP 2>/dev/null; rm -f /tmp/sb-cccccc
echo "=== done ==="
