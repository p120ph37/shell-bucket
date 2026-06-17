#include "sb_aead.h"
#include <bearssl.h>

/* GCM drives AES in CTR mode, so only the encrypt direction of the cipher is
 * ever used (decryption is the same keystream). br_ghash_ctmul is the portable
 * constant-time GHASH. Together these pull in exactly five BearSSL objects:
 * aes_ct, aes_ct_enc, aes_ct_ctr, gcm, ghash_ctmul. */

int sb_aesgcm_seal(const uint8_t *key, size_t key_len, const uint8_t iv[12],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *data, size_t data_len, uint8_t tag[16]) {
	br_aes_ct_ctr_keys bc;
	br_gcm_context gc;
	br_aes_ct_ctr_init(&bc, key, key_len);
	br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
	br_gcm_reset(&gc, iv, 12);
	if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
	br_gcm_flip(&gc);
	br_gcm_run(&gc, 1, data, data_len);
	br_gcm_get_tag(&gc, tag);
	return 0;
}

int sb_aesgcm_open(const uint8_t *key, size_t key_len, const uint8_t iv[12],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *data, size_t data_len, const uint8_t tag[16]) {
	br_aes_ct_ctr_keys bc;
	br_gcm_context gc;
	br_aes_ct_ctr_init(&bc, key, key_len);
	br_gcm_init(&gc, &bc.vtable, br_ghash_ctmul);
	br_gcm_reset(&gc, iv, 12);
	if (aad_len) br_gcm_aad_inject(&gc, aad, aad_len);
	br_gcm_flip(&gc);
	br_gcm_run(&gc, 0, data, data_len);
	return br_gcm_check_tag(&gc, tag) ? 0 : -1;
}
