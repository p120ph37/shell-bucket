#include "sb_deflate.h"

#include <stdlib.h>
#include <zlib.h>

void *sb_deflate_new(void) {
	z_stream *s = calloc(1, sizeof(z_stream));
	if (!s)
		return NULL;
	/* level 6, raw deflate (windowBits -15), default mem/strategy. */
	if (deflateInit2(s, 6, Z_DEFLATED, -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
		free(s);
		return NULL;
	}
	return s;
}

void *sb_inflate_new(void) {
	z_stream *s = calloc(1, sizeof(z_stream));
	if (!s)
		return NULL;
	if (inflateInit2(s, -15) != Z_OK) {
		free(s);
		return NULL;
	}
	return s;
}

void sb_deflate_close(void *h) {
	if (h) {
		deflateEnd((z_stream *)h);
		free(h);
	}
}

void sb_inflate_close(void *h) {
	if (h) {
		inflateEnd((z_stream *)h);
		free(h);
	}
}

unsigned char *sb_deflate_chunk(void *h, const unsigned char *in, size_t in_len, size_t *out_len) {
	z_stream *s = (z_stream *)h;
	size_t cap = deflateBound(s, in_len) + 16;
	unsigned char *out = malloc(cap);
	if (!out)
		return NULL;
	s->next_in = (unsigned char *)in;
	s->avail_in = (uInt)in_len;
	s->next_out = out;
	s->avail_out = (uInt)cap;
	/* Z_SYNC_FLUSH emits everything for this chunk and keeps the dictionary. */
	if (deflate(s, Z_SYNC_FLUSH) != Z_OK || s->avail_in != 0) {
		free(out);
		return NULL;
	}
	*out_len = cap - s->avail_out;
	return out;
}

unsigned char *sb_inflate_chunk(void *h, const unsigned char *in, size_t in_len, size_t *out_len) {
	z_stream *s = (z_stream *)h;
	s->next_in = (unsigned char *)in;
	s->avail_in = (uInt)in_len;
	size_t cap = in_len * 4 + 256, len = 0;
	unsigned char *out = malloc(cap);
	if (!out)
		return NULL;
	for (;;) {
		s->next_out = out + len;
		s->avail_out = (uInt)(cap - len);
		int r = inflate(s, Z_SYNC_FLUSH);
		len = cap - s->avail_out;
		if (r == Z_OK && s->avail_out == 0) { /* output buffer full — grow + continue */
			cap *= 2;
			unsigned char *n = realloc(out, cap);
			if (!n) {
				free(out);
				return NULL;
			}
			out = n;
			continue;
		}
		if (r == Z_OK || r == Z_BUF_ERROR) /* all sync-flushed input consumed */
			break;
		free(out);
		return NULL;
	}
	*out_len = len;
	return out;
}

void sb_zfree(void *p) { free(p); }
