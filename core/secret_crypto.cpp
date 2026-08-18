#include "secret_crypto.h"

#include <Preferences.h>
#include <string.h>
#include <mbedtls/gcm.h>
#include <mbedtls/base64.h>
#include <esp_random.h>

/* Wire format version of the AEAD blob (inside base64). */
#define SC_BLOB_VER 0x01
#define SC_NONCE_LEN 12
#define SC_TAG_LEN 16
#define SC_KEY_LEN 32

static uint8_t s_key[SC_KEY_LEN];
static bool s_ready = false;
static bool s_test_key = false;

void secret_crypto_set_test_key(const uint8_t key[32])
{
    if (!key)
        return;
    memcpy(s_key, key, SC_KEY_LEN);
    s_ready = true;
    s_test_key = true;
}

bool secret_crypto_init(void)
{
    if (s_ready)
        return true;

    Preferences prefs;
    if (!prefs.begin("cryptick", false))
        return false;

    size_t n = prefs.getBytesLength("wrapk");
    if (n == SC_KEY_LEN) {
        if (prefs.getBytes("wrapk", s_key, SC_KEY_LEN) != SC_KEY_LEN) {
            prefs.end();
            return false;
        }
    } else {
        esp_fill_random(s_key, SC_KEY_LEN);
        if (prefs.putBytes("wrapk", s_key, SC_KEY_LEN) != SC_KEY_LEN) {
            prefs.end();
            memset(s_key, 0, sizeof(s_key));
            return false;
        }
    }
    prefs.end();
    s_ready = true;
    s_test_key = false;
    return true;
}

bool secret_crypto_wrap(const uint8_t *pt, size_t pt_len,
                        char *out, size_t out_cap)
{
    if (!pt || !out || out_cap < 8 || pt_len == 0 || pt_len > SECRET_CRYPTO_PT_MAX)
        return false;
    if (!s_ready && !secret_crypto_init())
        return false;

    uint8_t nonce[SC_NONCE_LEN];
    esp_fill_random(nonce, sizeof(nonce));
    if (s_test_key) {
        /* Deterministic nonce for host/Unity vectors only (versioned test path) */
        for (int i = 0; i < SC_NONCE_LEN; i++)
            nonce[i] = (uint8_t)(0xA0 + i);
    }

    uint8_t ct[SECRET_CRYPTO_PT_MAX];
    uint8_t tag[SC_TAG_LEN];
    if (pt_len > sizeof(ct))
        return false;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_key, SC_KEY_LEN * 8) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int rc = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, pt_len,
                                       nonce, SC_NONCE_LEN,
                                       NULL, 0,
                                       pt, ct,
                                       SC_TAG_LEN, tag);
    mbedtls_gcm_free(&gcm);
    if (rc != 0)
        return false;

    /* blob = ver | nonce | ct | tag */
    uint8_t blob[1 + SC_NONCE_LEN + SECRET_CRYPTO_PT_MAX + SC_TAG_LEN];
    size_t blob_len = 1 + SC_NONCE_LEN + pt_len + SC_TAG_LEN;
    blob[0] = SC_BLOB_VER;
    memcpy(blob + 1, nonce, SC_NONCE_LEN);
    memcpy(blob + 1 + SC_NONCE_LEN, ct, pt_len);
    memcpy(blob + 1 + SC_NONCE_LEN + pt_len, tag, SC_TAG_LEN);

    size_t olen = 0;
    if (mbedtls_base64_encode((unsigned char *)out, out_cap - 1, &olen,
                              blob, blob_len) != 0)
        return false;
    out[olen] = '\0';
    return true;
}

bool secret_crypto_unwrap(const char *b64,
                          uint8_t *pt, size_t pt_cap, size_t *pt_len)
{
    if (!b64 || !pt || !pt_len || pt_cap == 0)
        return false;
    if (!s_ready && !secret_crypto_init())
        return false;

    uint8_t blob[1 + SC_NONCE_LEN + SECRET_CRYPTO_PT_MAX + SC_TAG_LEN];
    size_t blen = 0;
    size_t b64len = strlen(b64);
    if (mbedtls_base64_decode(blob, sizeof(blob), &blen,
                              (const unsigned char *)b64, b64len) != 0)
        return false;
    if (blen < 1 + SC_NONCE_LEN + SC_TAG_LEN + 1)
        return false;
    if (blob[0] != SC_BLOB_VER)
        return false;

    size_t clen = blen - 1 - SC_NONCE_LEN - SC_TAG_LEN;
    if (clen == 0 || clen > pt_cap || clen > SECRET_CRYPTO_PT_MAX)
        return false;

    const uint8_t *nonce = blob + 1;
    const uint8_t *ct = blob + 1 + SC_NONCE_LEN;
    const uint8_t *tag = blob + 1 + SC_NONCE_LEN + clen;

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    if (mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, s_key, SC_KEY_LEN * 8) != 0) {
        mbedtls_gcm_free(&gcm);
        return false;
    }
    int rc = mbedtls_gcm_auth_decrypt(&gcm, clen,
                                      nonce, SC_NONCE_LEN,
                                      NULL, 0,
                                      tag, SC_TAG_LEN,
                                      ct, pt);
    mbedtls_gcm_free(&gcm);
    if (rc != 0)
        return false;
    *pt_len = clen;
    return true;
}
