/**
 * Device wrap-key management + AES-256-GCM for TOTP secrets at rest.
 *
 * Plaintext secrets exist only in RAM (base32 / raw key as used by TOTP).
 * LittleFS JSON uses blob field `sec` (v2 schema), never raw `secret`.
 */
#ifndef CRYPTICK_SECRET_CRYPTO_H
#define CRYPTICK_SECRET_CRYPTO_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest plaintext accepted by secret_crypto_wrap(), in bytes. */
#define SECRET_CRYPTO_PT_MAX 128

/**
 * Buffer size that is always large enough for one wrap of SECRET_CRYPTO_PT_MAX
 * bytes: base64 of (1 version + 12 nonce + pt + 16 tag), rounded up, plus NUL.
 */
#define SECRET_CRYPTO_B64_MAX \
    ((((1 + 12 + SECRET_CRYPTO_PT_MAX + 16) + 2) / 3) * 4 + 1)

/** Load or create 256-bit wrap key in NVS. Safe to call multiple times. */
bool secret_crypto_init(void);

/**
 * Test / unit-test only: inject a fixed key (32 bytes). Skips NVS.
 * Must be called before wrap/unwrap (or after init override).
 */
void secret_crypto_set_test_key(const uint8_t key[32]);

/**
 * Encrypt secret bytes → base64(version|nonce|ct|tag) into out (NUL-terminated).
 * pt_len must be 1..SECRET_CRYPTO_PT_MAX; a SECRET_CRYPTO_B64_MAX buffer always fits.
 */
bool secret_crypto_wrap(const uint8_t *pt, size_t pt_len,
                        char *out, size_t out_cap);

/**
 * Decrypt base64 blob → plaintext. *pt_len is bytes written (<= pt_cap).
 */
bool secret_crypto_unwrap(const char *b64,
                          uint8_t *pt, size_t pt_cap, size_t *pt_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTICK_SECRET_CRYPTO_H */
