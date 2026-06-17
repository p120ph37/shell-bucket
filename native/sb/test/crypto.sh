# Self-test for the AES-GCM AEAD (BearSSL backend, csrc/sb_aead.c).
#   sb __cryptotest  → NIST AES-128-GCM known-answer vector + AES-256
#   round-trip / tamper / AAD-mismatch checks, one ok:/FAIL: line each.
B="/b/sb"

echo "=== AES-GCM AEAD (BearSSL) ==="
$B __cryptotest
