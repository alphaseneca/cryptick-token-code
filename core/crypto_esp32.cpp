#include "crypto.h"
#include <string.h>
#include <Arduino.h>
#include "esp_random.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"
#include "mbedtls/md.h"
#include "mbedtls/aes.h"
#include "uECC.h"

extern "C" {

static mbedtls_sha256_context sha256_ctx;
static mbedtls_sha512_context sha512_ctx;
static mbedtls_md_context_t hmac_ctx;

static const struct uECC_Curve_t * _es256_curve = NULL;
static const uint8_t * _signing_key = NULL;
static int _key_len = 0;

static uint8_t master_secret[64] = {0};
static uint8_t transport_secret[32] = {0};

void crypto_sha256_init(void) {
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0); // 0 = SHA-256
}

void crypto_sha256_update(uint8_t * data, size_t len) {
    mbedtls_sha256_update(&sha256_ctx, data, len);
}

void crypto_sha256_update_secret() {
    mbedtls_sha256_update(&sha256_ctx, master_secret, 32);
}

void crypto_sha256_final(uint8_t * hash) {
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);
}

void crypto_sha512_init(void) {
    mbedtls_sha512_init(&sha512_ctx);
    mbedtls_sha512_starts(&sha512_ctx, 0); // 0 = SHA-512
}

void crypto_sha512_update(const uint8_t * data, size_t len) {
    mbedtls_sha512_update(&sha512_ctx, data, len);
}

void crypto_sha512_final(uint8_t * hash) {
    mbedtls_sha512_finish(&sha512_ctx, hash);
    mbedtls_sha512_free(&sha512_ctx);
}

void crypto_sha256_hmac_init(uint8_t * key, uint32_t klen, uint8_t * hmac) {
    mbedtls_md_init(&hmac_ctx);
    mbedtls_md_setup(&hmac_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1); // 1 = HMAC
    
    if (key == CRYPTO_MASTER_KEY) {
        key = master_secret;
        klen = 32;
    } else if (key == CRYPTO_TRANSPORT_KEY) {
        key = transport_secret;
        klen = 32;
    }
    mbedtls_md_hmac_starts(&hmac_ctx, key, klen);
}

void crypto_sha256_hmac_update(uint8_t * data, size_t len) {
    mbedtls_md_hmac_update(&hmac_ctx, data, len);
}

void crypto_sha256_hmac_final(uint8_t * key, uint32_t klen, uint8_t * hmac) {
    mbedtls_md_hmac_finish(&hmac_ctx, hmac);
    mbedtls_md_free(&hmac_ctx);
}

/* uECC_RNG_Function: second arg is unsigned (not size_t) — cast was unsafe. */
static int cryptick_uecc_rng(uint8_t *dest, unsigned size)
{
    if (!dest || size == 0)
        return 0;
    esp_fill_random(dest, (size_t)size);
    return 1;
}

void crypto_ecc256_init(void) {
    uECC_set_rng(cryptick_uecc_rng);
    _es256_curve = uECC_secp256r1();
}

extern uint8_t * device_get_attestation_key();

void crypto_ecc256_load_attestation_key(void) {
    _signing_key = device_get_attestation_key();
    _key_len = 32;
}

/* secp256r1 group order n (big-endian). Chrome/BoringSSL reject high-S ECDSA. */
static const uint8_t SECP256R1_N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51
};
/* floor(n/2) — if s > n/2, replace s with n-s (RFC 6979 low-S). */
static const uint8_t SECP256R1_HALF_N[32] = {
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00,
    0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42,
    0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8
};

static int cmp_be32(const uint8_t *a, const uint8_t *b)
{
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void sub_be32(uint8_t *out, const uint8_t *a, const uint8_t *b)
{
    int borrow = 0;
    for (int i = 31; i >= 0; i--) {
        int v = (int)a[i] - (int)b[i] - borrow;
        if (v < 0) {
            v += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = (uint8_t)v;
    }
}

/** Normalize r||s (64 bytes) so S is low — required by Chrome WebAuthn/U2F. */
static void ecdsa_normalize_low_s(uint8_t *sig)
{
    uint8_t *s = sig + 32;
    if (cmp_be32(s, SECP256R1_HALF_N) > 0) {
        uint8_t ns[32];
        sub_be32(ns, SECP256R1_N, s);
        memcpy(s, ns, 32);
    }
}

void crypto_ecc256_sign(uint8_t * data, int len, uint8_t * sig) {
    int ok = 0;
    for (int attempt = 0; attempt < 8 && !ok; attempt++) {
        ok = uECC_sign(_signing_key, data, (unsigned)len, sig, _es256_curve);
    }
    if (!ok) {
        /* Never emit uninitialized garbage to the host/browser */
        memset(sig, 0, 64);
        return;
    }
    ecdsa_normalize_low_s(sig);
}

void crypto_ecdsa_sign(uint8_t * data, int len, uint8_t * sig, int MBEDTLS_ECP_ID) {
    (void)MBEDTLS_ECP_ID;
    crypto_ecc256_sign(data, len, sig);
}

static mbedtls_aes_context aes_ctx;
static uint8_t aes_iv[16];
static uint8_t aes_current_key[32];

void crypto_aes256_init(uint8_t * key, uint8_t * nonce) {
    mbedtls_aes_init(&aes_ctx);
    if (key == CRYPTO_TRANSPORT_KEY) {
        memcpy(aes_current_key, transport_secret, 32);
    } else {
        memcpy(aes_current_key, key, 32);
    }
    mbedtls_aes_setkey_enc(&aes_ctx, aes_current_key, 256);
    if (nonce) {
        memcpy(aes_iv, nonce, 16);
    } else {
        memset(aes_iv, 0, 16);
    }
}

void crypto_aes256_reset_iv(uint8_t * nonce) {
    if (nonce) {
        memcpy(aes_iv, nonce, 16);
    } else {
        memset(aes_iv, 0, 16);
    }
}

void crypto_aes256_encrypt(uint8_t * buf, int length) {
    mbedtls_aes_crypt_cbc(&aes_ctx, MBEDTLS_AES_ENCRYPT, length, aes_iv, buf, buf);
}

void crypto_aes256_decrypt(uint8_t * buf, int length) {
    mbedtls_aes_context dec_ctx;
    mbedtls_aes_init(&dec_ctx);
    mbedtls_aes_setkey_dec(&dec_ctx, aes_current_key, 256);
    uint8_t iv_copy[16];
    memcpy(iv_copy, aes_iv, 16); 
    mbedtls_aes_crypt_cbc(&dec_ctx, MBEDTLS_AES_DECRYPT, length, iv_copy, buf, buf);
    mbedtls_aes_free(&dec_ctx);
}

void crypto_reset_master_secret() {
    extern int ctap_generate_rng(uint8_t * dst, size_t num);
    ctap_generate_rng(master_secret, 64);
    ctap_generate_rng(transport_secret, 32);
}

void crypto_load_master_secret(uint8_t * key) {
    memcpy(master_secret, key, 64);
    memcpy(transport_secret, key+64, 32);
}

void generate_private_key(uint8_t * data, int len, uint8_t * data2, int len2, uint8_t * privkey) {
    crypto_sha256_hmac_init(CRYPTO_MASTER_KEY, 0, privkey);
    // Not threadsafe to use hmac_ctx like this consecutively without starts/finish properly, so we will use mbedtls directly
    mbedtls_md_context_t local_ctx;
    mbedtls_md_init(&local_ctx);
    mbedtls_md_setup(&local_ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
    mbedtls_md_hmac_starts(&local_ctx, master_secret, 32);
    mbedtls_md_hmac_update(&local_ctx, data, len);
    if(data2 && len2 > 0) mbedtls_md_hmac_update(&local_ctx, data2, len2);
    mbedtls_md_hmac_update(&local_ctx, master_secret, 32);
    mbedtls_md_hmac_finish(&local_ctx, privkey);
    mbedtls_md_free(&local_ctx);

    crypto_aes256_init(master_secret + 32, NULL);
    crypto_aes256_encrypt(privkey, 32);
}

void crypto_ecc256_derive_public_key(uint8_t * data, int len, uint8_t * x, uint8_t * y) {
    uint8_t privkey[32];
    uint8_t pubkey[64];
    generate_private_key(data, len, NULL, 0, privkey);
    memset(pubkey, 0, sizeof(pubkey));
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
    memcpy(x, pubkey, 32);
    memcpy(y, pubkey+32, 32);
}

void crypto_ecc256_compute_public_key(uint8_t * privkey, uint8_t * pubkey) {
    uECC_compute_public_key(privkey, pubkey, _es256_curve);
}

void crypto_ecc256_load_key(uint8_t * data, int len, uint8_t * data2, int len2) {
    static uint8_t privkey[32];
    generate_private_key(data, len, data2, len2, privkey);
    _signing_key = privkey;
    _key_len = 32;
}

void crypto_load_external_key(uint8_t * key, int len) {
    _signing_key = key;
    _key_len = len;
}

void crypto_ecc256_make_key_pair(uint8_t * pubkey, uint8_t * privkey) {
    uECC_make_key(pubkey, privkey, _es256_curve);
}

void crypto_ecc256_shared_secret(const uint8_t * pubkey, const uint8_t * privkey, uint8_t * shared_secret) {
    uECC_shared_secret(pubkey, privkey, shared_secret, _es256_curve);
}

/* Ed25519 stubs for compilation, only used if algorithm invokes it */
void crypto_ed25519_derive_public_key(uint8_t * data, int len, uint8_t * x) { memset(x,0,32); }
void crypto_ed25519_load_key(uint8_t * data, int len) {}
void crypto_ed25519_sign(uint8_t * data1, int len1, uint8_t * data2, int len2, uint8_t * sig) { memset(sig,0,64); }

} // extern C
