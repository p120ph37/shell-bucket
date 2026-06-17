# Self-test for the stream-DEFLATE layer (zlib shim): sb __deflatetest does a
# streaming compress→inflate round-trip and confirms the persistent dictionary
# shrinks a repeated chunk. Hermetic.
B="/b/sb"

echo "=== Stream DEFLATE (zlib) ==="
$B __deflatetest
