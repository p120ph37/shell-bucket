# Self-tests for `sb clip` against the __muxserve stub.
# Tests paste (CLIP:GET) and copy (CLIP:SET) via --paste / --copy flags,
# since stdin and stdout are both TTYs inside the test harness.
B=/b/sb
T="cccccc:secret3secret3secret3cc"
waitsock() { i=0; while [ ! -S "$1" ] && [ "$i" -lt 100 ]; do sleep 0.02; i=$((i + 1)); done; }

SB_TOKEN=$T $B __muxserve & SP=$!
waitsock /tmp/sb-cccccc

echo "=== sb clip --paste ==="
out=$(SB_TOKEN=$T $B clip --paste 2>/dev/null)
[ "$out" = "hello" ] && echo "ok:   paste returned expected content" || echo "FAIL: paste got '${out}'"

echo "=== sb clip --copy ==="
echo -n "clipboard content" | SB_TOKEN=$T $B clip --copy >/dev/null 2>&1; rc=$?
[ "$rc" = 0 ] && echo "ok:   copy exit 0" || echo "FAIL: copy rc=$rc"

kill $SP 2>/dev/null; rm -f /tmp/sb-cccccc
echo "=== done ==="
