# Self-tests for `sb ctl` (control/status) against the __muxserve stub.
# Exercises the STATUS wire protocol, the pretty-printed output shape, the
# udpup/udpdn backhaul verbs, and the -v / kill component inventory -- all over
# the real bearer-auth socket handshake.
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

echo "=== sb ctl -v (verbose component listing) ==="
outv=$(SB_TOKEN=$T $B ctl -v 2>/dev/null)
echo "$outv" | grep -q "Components"             && echo "ok:   components section"   || echo "FAIL: components section missing"
echo "$outv" | grep -q "relay"                  && echo "ok:   relay row listed"     || echo "FAIL: relay row missing"
echo "$outv" | grep -q "bind:127.0.0.1:8080"    && echo "ok:   port desc listed"     || echo "FAIL: port desc missing"
echo "$outv" | grep -q "rpc"                     && echo "ok:   rpc row listed"       || echo "FAIL: rpc row missing"

echo "=== sb ctl udpdn ==="
SB_TOKEN=$T $B ctl udpdn >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl udpdn exit 0" || echo "FAIL: ctl udpdn rc=$rc"

echo "=== sb ctl udpup ==="
SB_TOKEN=$T $B ctl udpup >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl udpup exit 0" || echo "FAIL: ctl udpup rc=$rc"

echo "=== sb ctl udpup with candidates ==="
SB_TOKEN=$T $B ctl udpup 1.2.3.4:5678 >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl udpup with candidates exit 0" || echo "FAIL: ctl udpup rc=$rc"

echo "=== sb ctl kill <sel> ==="
outk=$(SB_TOKEN=$T $B ctl kill rpcs 2>/dev/null); rc=$?
[ "$rc" = 0 ] && echo "ok:   ctl kill rpcs exit 0" || echo "FAIL: ctl kill rc=$rc"
echo "$outk" | grep -q "Killed" && echo "ok:   kill reports killed table" || echo "FAIL: kill table missing"

echo "=== sb ctl kill (no selector -> usage + listing, nonzero) ==="
SB_TOKEN=$T $B ctl kill >/dev/null 2>&1; rc=$?
[ "$rc" != 0 ] && echo "ok:   bare kill exits nonzero" || echo "FAIL: bare kill rc=$rc"
SB_TOKEN=$T $B ctl kill 2>&1 | grep -q "usage:" && echo "ok:   bare kill prints usage" || echo "FAIL: bare kill usage missing"

echo "=== sb control alias ==="
out3=$(SB_TOKEN=$T $B control status 2>/dev/null)
echo "$out3" | grep -q "sb mux status" && echo "ok:   'control' alias works" || echo "FAIL: control alias"

kill $SP 2>/dev/null; rm -f /tmp/sb-cccccc
echo "=== done ==="
