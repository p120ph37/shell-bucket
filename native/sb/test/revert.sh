# Self-test for the lossless UDP->in-band revert handoff (white-box, in-process).
#   sb __revertprobe
# Enqueue N up-frames onto a live Backhaul, fake the ARQ acking a prefix and check
# prune() advances tx_base by exactly that many frames, then capture fd 1 across a
# begin_revert + peer_revert and assert the wrapper receives, in-band, exactly
# `UP:RX:<rx>` followed by the verbatim tail of frames it never consumed -- proving
# the handoff loses nothing and duplicates nothing. Mirrors the Python
# test_udp_backhaul_lossless_revert_exactly_once on the V (mux) side.
B=/b/sb
echo "=== lossless revert handoff (mux side) ==="
$B __revertprobe 2>&1
