/**
 * L1: AES-GCM wrap/unwrap of TOTP raw secrets (mbedtls).
 * Uses fixed test key + nonce path in secret_crypto (test-key mode).
 */
#include <Arduino.h>
#include <unity.h>
#include <string.h>
#include "secret_crypto.h"

static const uint8_t TEST_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f};

void setUp(void)
{
    secret_crypto_set_test_key(TEST_KEY);
}

void tearDown(void) {}

void test_wrap_unwrap_round_trip(void)
{
    const uint8_t pt[] = {0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21}; /* Hello! */
    char b64[SECRET_CRYPTO_B64_MAX];
    TEST_ASSERT_TRUE(secret_crypto_wrap(pt, sizeof(pt), b64, sizeof(b64)));
    TEST_ASSERT_TRUE(strlen(b64) > 16);

    uint8_t out[32];
    size_t olen = 0;
    TEST_ASSERT_TRUE(secret_crypto_unwrap(b64, out, sizeof(out), &olen));
    TEST_ASSERT_EQUAL_UINT(sizeof(pt), olen);
    TEST_ASSERT_EQUAL_MEMORY(pt, out, sizeof(pt));
}

void test_unwrap_tamper_fails(void)
{
    const uint8_t pt[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    char b64[SECRET_CRYPTO_B64_MAX];
    TEST_ASSERT_TRUE(secret_crypto_wrap(pt, sizeof(pt), b64, sizeof(b64)));
    /* Flip one character in base64 safely */
    size_t n = strlen(b64);
    TEST_ASSERT_TRUE(n > 8);
    if (b64[n / 2] != 'A')
        b64[n / 2] = 'A';
    else
        b64[n / 2] = 'B';

    uint8_t out[32];
    size_t olen = 0;
    TEST_ASSERT_FALSE(secret_crypto_unwrap(b64, out, sizeof(out), &olen));
}

void test_empty_pt_rejected(void)
{
    char b64[SECRET_CRYPTO_B64_MAX];
    TEST_ASSERT_FALSE(secret_crypto_wrap((const uint8_t *)"", 0, b64, sizeof(b64)));
}

void setup()
{
    delay(500);
    UNITY_BEGIN();
    RUN_TEST(test_wrap_unwrap_round_trip);
    RUN_TEST(test_unwrap_tamper_fails);
    RUN_TEST(test_empty_pt_rejected);
    UNITY_END();
}

void loop() {}
