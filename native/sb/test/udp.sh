# Self-test for the UDP AEAD packet codec (the backhaul datagram layer):
#   sb __udptest  -> seal/open round-trip, clear seq preserved, cross-direction
#   (wrong salt) rejection, tamper + truncation rejection, empty-payload (ack)
#   packets. Hermetic -- no sockets.
B="/b/sb"

echo "=== UDP AEAD packet codec ==="
$B __udptest
