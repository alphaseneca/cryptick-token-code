#include <Arduino.h>
#include <unity.h>
#include "../core/totp.h"

void test_totp_base32_decode(void)
{
    uint8_t buf[32];
    int n = totp_base32_decode("JBSWY3DPEHPK3PXP", buf, sizeof(buf));
    TEST_ASSERT_GREATER_THAN(0, n);
    TEST_ASSERT_LESS_OR_EQUAL(32, n);
}

void test_totp_base32_decode_invalid(void)
{
    uint8_t buf[32];
    int n = totp_base32_decode("", buf, sizeof(buf));
    TEST_ASSERT_EQUAL(0, n);
}

void test_totp_generate(void)
{
    TOTPCredential cred;
    cred.secret = "JBSWY3DPEHPK3PXP";
    cred.digits = 6;
    cred.period = 30;
    cred.algorithm = "SHA1";
    cred.label = "Test";
    cred.issuer = "TestIssuer";
    String code = totp_generate(cred, 1);
    TEST_ASSERT_TRUE(code.length() == 6 || code.length() > 6);
}

void test_totp_generate_known_time(void)
{
    TOTPCredential cred;
    cred.secret = "JBSWY3DPEHPK3PXP";
    cred.digits = 6;
    cred.period = 30;
    cred.algorithm = "SHA1";
    cred.label = "Test";
    cred.issuer = "TestIssuer";
    uint32_t ts = 59;
    String code = totp_generate(cred, ts);
    TEST_ASSERT_EQUAL(6, code.length());
    TEST_ASSERT_TRUE(code.toInt() >= 0 && code.toInt() <= 999999);
}

static void run_all_tests(void)
{
    RUN_TEST(test_totp_base32_decode);
    RUN_TEST(test_totp_base32_decode_invalid);
    RUN_TEST(test_totp_generate);
    RUN_TEST(test_totp_generate_known_time);
}

void setup()
{
    delay(2000);
    UNITY_BEGIN();
    run_all_tests();
    UNITY_END();
}

void loop()
{
}
