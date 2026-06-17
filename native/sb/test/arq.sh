# Self-test for the reliable-UDP (TCP-lite ARQ) layer: sb __arqtest drives a
# 128KB transfer through a simulated 15%-loss, reordering channel on a virtual
# clock and asserts the bytes arrive intact and in order — exercising
# retransmit, the flow window, and the reorder buffer. Hermetic — no sockets.
B="/b/sb"

echo "=== Reliable-UDP ARQ ==="
$B __arqtest
