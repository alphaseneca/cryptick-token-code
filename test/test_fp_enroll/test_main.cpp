#include <Arduino.h>
#include <unity.h>
#include "fingerprint_r558s.h"
#include <Stream.h>
#include <string.h>

/* Minimal mock: records TX, feeds RX from a scripted queue. */

class MockFpStream : public Stream {
public:
    uint8_t rx[512];
    size_t rx_len = 0;
    size_t rx_pos = 0;
    uint8_t last_tx[128];
    size_t last_tx_len = 0;

    void feed(const uint8_t *d, size_t n)
    {
        if (n > sizeof(rx))
            n = sizeof(rx);
        memcpy(rx, d, n);
        rx_len = n;
        rx_pos = 0;
    }

    int available() override { return (int)(rx_len - rx_pos); }
    int read() override
    {
        if (rx_pos >= rx_len)
            return -1;
        return rx[rx_pos++];
    }
    int peek() override
    {
        if (rx_pos >= rx_len)
            return -1;
        return rx[rx_pos];
    }
    size_t write(uint8_t b) override
    {
        if (last_tx_len < sizeof(last_tx))
            last_tx[last_tx_len++] = b;
        return 1;
    }
    size_t write(const uint8_t *buffer, size_t size) override
    {
        for (size_t i = 0; i < size; i++)
            write(buffer[i]);
        return size;
    }
    void flush() override {}
};

/** Build R558-S ack: header + PID 0x07 + len + payload + checksum */
static size_t build_ack(uint8_t *out, size_t max, const uint8_t *payload, uint16_t plen)
{
    if (max < 11 + plen)
        return 0;
    out[0] = 0xEF;
    out[1] = 0x01;
    out[2] = out[3] = out[4] = out[5] = 0xFF;
    out[6] = 0x07;
    uint16_t pktLen = plen + 2;
    out[7] = (pktLen >> 8) & 0xFF;
    out[8] = pktLen & 0xFF;
    memcpy(out + 9, payload, plen);
    uint32_t sum = 0x07 + out[7] + out[8];
    for (uint16_t i = 0; i < plen; i++)
        sum += payload[i];
    out[9 + plen] = (sum >> 8) & 0xFF;
    out[10 + plen] = sum & 0xFF;
    return 11 + plen;
}

static void feed_ae(MockFpStream &ss, uint8_t conf, uint8_t p1, uint8_t p2)
{
    uint8_t payload[3] = {conf, p1, p2};
    uint8_t ack[32];
    size_t n = build_ack(ack, sizeof(ack), payload, 3);
    TEST_ASSERT_TRUE(n > 0);
    ss.feed(ack, n);
}

void test_enroll_start_sets_wait_finger(void)
{
    MockFpStream ss;
    R558SFingerprint fp(ss);
    fp.setTimeout(50);
    fp.setCapacity(120);
    int r = fp.enrollStart(3); /* fixed slot skips free-id path */
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, r);
    TEST_ASSERT_EQUAL(3, fp.enrollId());

    EnrollNbState st;
    uint8_t step;
    r = fp.enrollPoll(st, step);
    TEST_ASSERT_EQUAL(ENROLL_WAIT_FINGER, st);
    TEST_ASSERT_EQUAL(1, step);
}

void test_autoenroll_state_machine_to_store(void)
{
    MockFpStream ss;
    R558SFingerprint fp(ss);
    fp.setTimeout(50);
    fp.setCapacity(120);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollStart(7));

    EnrollNbState st;
    uint8_t step;

    /* Image collected for entry 1 → BUSY */
    feed_ae(ss, 0x00, AE_P1_GETIMAGE, 1);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_BUSY, st);
    TEST_ASSERT_EQUAL(1, step);

    /* Leave finger after entry 1 */
    feed_ae(ss, 0x00, AE_P1_LEAVE, 1);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_WAIT_REMOVE, st);
    TEST_ASSERT_EQUAL(1, step);

    /* Second capture / genchar */
    feed_ae(ss, 0x00, AE_P1_GETIMAGE, 2);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_BUSY, st);
    TEST_ASSERT_EQUAL(2, step);

    feed_ae(ss, 0x00, AE_P1_GENCHAR, 2);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_BUSY, st);

    feed_ae(ss, 0x00, AE_P1_MERGE, 0);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_BUSY, st);

    /* Store success: conf=00 p1=06 p2=F2 */
    feed_ae(ss, 0x00, AE_P1_STORE, 0xF2);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollPoll(st, step));
    TEST_ASSERT_EQUAL(ENROLL_DONE, st);
    TEST_ASSERT_EQUAL(7, fp.enrollId());
}

void test_autoenroll_terminal_fail(void)
{
    MockFpStream ss;
    R558SFingerprint fp(ss);
    fp.setTimeout(50);
    fp.setCapacity(120);
    TEST_ASSERT_EQUAL(FINGERPRINT_OK, fp.enrollStart(1));

    EnrollNbState st;
    uint8_t step;
    /* Library full is terminal */
    feed_ae(ss, FINGERPRINT_LIBFULL, AE_P1_STORE, 0);
    int r = fp.enrollPoll(st, step);
    TEST_ASSERT_EQUAL(ENROLL_FAILED, st);
    TEST_ASSERT_EQUAL(FINGERPRINT_LIBFULL, r);
}

void test_error_messages_nonnull(void)
{
    TEST_ASSERT_NOT_NULL(R558SFingerprint::getErrorMessage(FINGERPRINT_OK));
    TEST_ASSERT_NOT_NULL(R558SFingerprint::getErrorMessage(FINGERPRINT_NOFINGER));
    TEST_ASSERT_NOT_NULL(R558SFingerprint::getErrorMessage(FINGERPRINT_TIMEOUT));
    TEST_ASSERT_NOT_NULL(R558SFingerprint::getErrorMessage(FINGERPRINT_IMAGEFAIL));
    TEST_ASSERT_NOT_NULL(R558SFingerprint::getErrorMessage(FINGERPRINT_ILLEGALDATA));
    TEST_ASSERT_EQUAL_STRING("Merge failed (not same finger)",
                             R558SFingerprint::getErrorMessage(FINGERPRINT_MERGEFAIL));
}

void setup()
{
    delay(1500);
    UNITY_BEGIN();
    RUN_TEST(test_enroll_start_sets_wait_finger);
    RUN_TEST(test_autoenroll_state_machine_to_store);
    RUN_TEST(test_autoenroll_terminal_fail);
    RUN_TEST(test_error_messages_nonnull);
    UNITY_END();
}

void loop() {}
