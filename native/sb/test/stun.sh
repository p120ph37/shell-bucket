# Self-test for the STUN client codec (RFC 5389): sb __stuntest builds a Binding
# Request and decodes a synthetic Success Response's XOR-MAPPED-ADDRESS, with
# negative cases (bad txid / cookie / message-type). Hermetic -- no network.
B="/b/sb"

echo "=== STUN client (RFC 5389) ==="
$B __stuntest
