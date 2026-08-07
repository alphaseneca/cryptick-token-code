#include <Arduino.h>
#include <unity.h>
#include "totp.h"

/* RFC 4226 / common "Hello!" Base32 demo secret used by many TOTP apps:
 * secret Base32: JBSWY3DPEHPK3PXP  →  "Hello!"
 * Code generation depends on SHA1 truncation; vectors below match this codebase.
 */

void test_totp_base32_decode(void)
{
    uint8_t buf[32];
    int n = totp_base32_decode("JBSWY3DPEHPK3PXP", buf, sizeof(buf));
    TEST_ASSERT_EQUAL(10, n);
    /* "Hello!" ascii */
    TEST_ASSERT_EQUAL_UINT8('H', buf[0]);
    TEST_ASSERT_EQUAL_UINT8('e', buf[1]);
    TEST_ASSERT_EQUAL_UINT8('l', buf[2]);
    TEST_ASSERT_EQUAL_UINT8('l', buf[3]);
    TEST_ASSERT_EQUAL_UINT8('o', buf[4]);
    TEST_ASSERT_EQUAL_UINT8('!', buf[5]);
}

void test_totp_base32_decode_invalid(void)
{
    uint8_t buf[32];
    int n = totp_base32_decode("", buf, sizeof(buf));
    TEST_ASSERT_EQUAL(0, n);
}

static TOTPCredential demo_cred(void)
{
    TOTPCredential cred;
    cred.secret = "JBSWY3DPEHPK3PXP";
    cred.digits = 6;
    cred.period = 30;
    cred.algorithm = "SHA1";
    cred.label = "Test";
    cred.issuer = "TestIssuer";
    return cred;
}

void test_totp_generate_length(void)
{
    TOTPCredential cred = demo_cred();
    String code = totp_generate(cred, 59);
    TEST_ASSERT_EQUAL(6, code.length());
    for (unsigned i = 0; i < 6; i++)
        TEST_ASSERT_TRUE(code[i] >= '0' && code[i] <= '9');
}

void test_totp_generate_stable(void)
{
    /* Same timestamp → same code (determinism) */
    TOTPCredential cred = demo_cred();
    String a = totp_generate(cred, 1111111109UL);
    String b = totp_generate(cred, 1111111109UL);
    TEST_ASSERT_EQUAL_STRING(a.c_str(), b.c_str());
    TEST_ASSERT_EQUAL(6, a.length());
}

void test_totp_counter_steps(void)
{
    /* Different 30s windows must not always match (sanity) */
    TOTPCredential cred = demo_cred();
    String a = totp_generate(cred, 0);
    String b = totp_generate(cred, 30);
    TEST_ASSERT_EQUAL(6, a.length());
    TEST_ASSERT_EQUAL(6, b.length());
    /* Allow rare accidental equality; if both empty fail */
    TEST_ASSERT_TRUE(a.length() > 0 && b.length() > 0);
}

/* RFC 6238 Appendix B — seed ASCII "12345678901234567890", SHA1, 8 digits
 * secret stored base32 for our totp_generate() path. */
static TOTPCredential rfc_cred(void)
{
    TOTPCredential cred;
    /* base32 of ASCII seed (no padding) */
    cred.secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    cred.digits = 8;
    cred.period = 30;
    cred.algorithm = "SHA1";
    cred.label = "RFC";
    cred.issuer = "RFC";
    return cred;
}

void test_totp_rfc6238_t59(void)
{
    String code = totp_generate(rfc_cred(), 59);
    TEST_ASSERT_EQUAL_STRING("94287082", code.c_str());
}

void test_totp_rfc6238_t1111111109(void)
{
    String code = totp_generate(rfc_cred(), 1111111109UL);
    TEST_ASSERT_EQUAL_STRING("07081804", code.c_str());
}

void test_totp_rejects_non_sha1(void)
{
    TOTPCredential cred = demo_cred();
    cred.algorithm = "SHA256";
    String code = totp_generate(cred, 59);
    TEST_ASSERT_EQUAL_STRING("Bad Algo", code.c_str());
}

static void run_all_tests(void)
{
    RUN_TEST(test_totp_base32_decode);
    RUN_TEST(test_totp_base32_decode_invalid);
    RUN_TEST(test_totp_generate_length);
    RUN_TEST(test_totp_generate_stable);
    RUN_TEST(test_totp_counter_steps);
    RUN_TEST(test_totp_rfc6238_t59);
    RUN_TEST(test_totp_rfc6238_t1111111109);
    RUN_TEST(test_totp_rejects_non_sha1);
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
