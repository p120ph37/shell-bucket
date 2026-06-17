#ifndef SB_DEFLATE_H
#define SB_DEFLATE_H

/* Streaming raw-DEFLATE (RFC 1951, zlib wbits=-15) for the UDP backhaul.
 *
 * A flat C shim over zlib's streaming API so the V side never touches z_stream:
 * one persistent compressor + one persistent decompressor per direction, with a
 * sync flush per chunk (so the receiver can inflate up to that point immediately
 * while the cross-chunk dictionary is retained). Sits between the frame layer and
 * the reliable ARQ byte stream — the ARQ guarantees order, so the dictionary is
 * valid across the whole session. Raw deflate (no zlib/gzip header): the AES-GCM
 * tag already authenticates each ARQ packet, so the container checksum is dead
 * weight, and per-chunk framing overhead is zero. */

#include <stddef.h>

void *sb_deflate_new(void); /* a streaming compressor (free with sb_deflate_close) */
void *sb_inflate_new(void); /* a streaming decompressor (free with sb_inflate_close) */
void sb_deflate_close(void *h);
void sb_inflate_close(void *h);

/* Compress / inflate one chunk with Z_SYNC_FLUSH. Return a malloc'd buffer of
 * `*out_len` bytes (free it with sb_zfree), or NULL on error. */
unsigned char *sb_deflate_chunk(void *h, const unsigned char *in, size_t in_len, size_t *out_len);
unsigned char *sb_inflate_chunk(void *h, const unsigned char *in, size_t in_len, size_t *out_len);
void sb_zfree(void *p);

#endif /* SB_DEFLATE_H */
