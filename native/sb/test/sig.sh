# Self-test for the UPGRADE signaling codec (in-band offer/answer): sb __sigtest
# encodes an offer (PSK + nonce + STUN servers + candidates) and an answer,
# decodes them back, and checks every field round-trips, plus rejection of
# truncated / malformed blobs. Hermetic — no network.
B="/b/sb"

echo "=== UPGRADE signaling codec ==="
$B __sigtest
