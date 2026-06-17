#ifndef SB_AEAD_H
#define SB_AEAD_H

/* AES-GCM AEAD over BearSSL's constant-time backend (aes_ct + ghash_ctmul).
 *
 * A flat C shim so the V side never has to thread BearSSL's context structs
 * through FFI: it sees two byte-pointer functions and nothing else. The whole
 * BearSSL surface stays behind this translation unit.
 *
 * key_len selects AES-128/192/256 (16/24/32). iv is the 12-byte GCM nonce.
 * Plaintext/ciphertext is transformed in place. The 16-byte tag is written by
 * seal and verified by open. */

#include <stddef.h>
#include <stdint.h>

/* Returns 0 on success. */
int sb_aesgcm_seal(const uint8_t *key, size_t key_len, const uint8_t iv[12],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *data, size_t data_len, uint8_t tag[16]);

/* Returns 0 if the tag verifies, -1 on authentication failure. On failure the
 * plaintext is still written (GCM is a stream cipher) but MUST be discarded. */
int sb_aesgcm_open(const uint8_t *key, size_t key_len, const uint8_t iv[12],
                   const uint8_t *aad, size_t aad_len,
                   uint8_t *data, size_t data_len, const uint8_t tag[16]);

#endif /* SB_AEAD_H */
