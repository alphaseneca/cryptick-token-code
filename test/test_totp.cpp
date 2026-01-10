#include <Arduino.h>
#include <unity.h>
#include "Crypto.h"
#include "TOTP.h"

void test_sha1()
{
    String input = "Hello, World!";
    String expected = "0a0a9f2a6772942557ab5355d76af442f8f65e01";
    String result = Crypto::sha1(input);
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), result.c_str());
}

void test_sha256()
{
    String input = "Hello, World!";
    String expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f";
    String result = Crypto::sha256(input);
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), result.c_str());
}

void test_base32_decode()
{
    String input = "JBSWY3DPEHPK3PXP";
    String result = TOTP::base32Decode(input);
    // The decoded result should be a binary string
    TEST_ASSERT_TRUE(result.length() > 0);
}

void test_totp_generation()
{
    String secret = "JBSWY3DPEHPK3PXP";
    uint64_t counter = 0;
    String result = TOTP::generateTOTP(secret, counter, 6, "SHA1");
    // TOTP should generate a 6-digit code
    TEST_ASSERT_EQUAL(6, result.length());
    TEST_ASSERT_TRUE(result.toInt() >= 0);
    TEST_ASSERT_TRUE(result.toInt() < 1000000);
}

void test_hmac_sha1()
{
    String key = "key";
    String data = "The quick brown fox jumps over the lazy dog";
    String result = Crypto::hmacSHA1(key, data);
    // HMAC should produce a hex string
    TEST_ASSERT_TRUE(result.length() > 0);
    TEST_ASSERT_TRUE(result.length() % 2 == 0); // Even length for hex
}

void test_hmac_sha256()
{
    String key = "key";
    String data = "The quick brown fox jumps over the lazy dog";
    String result = Crypto::hmacSHA256(key, data);
    // HMAC should produce a hex string
    TEST_ASSERT_TRUE(result.length() > 0);
    TEST_ASSERT_TRUE(result.length() % 2 == 0); // Even length for hex
}

void setup()
{
    delay(2000);
    UNITY_BEGIN();

    RUN_TEST(test_sha1);
    RUN_TEST(test_sha256);
    RUN_TEST(test_base32_decode);
    RUN_TEST(test_totp_generation);
    RUN_TEST(test_hmac_sha1);
    RUN_TEST(test_hmac_sha256);

    UNITY_END();
}

void loop()
{
    // Test completed
}