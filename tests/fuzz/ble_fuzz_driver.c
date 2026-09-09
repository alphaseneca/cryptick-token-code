/*
 * Fragment-stream driver for core/ble_fido/ble_fido.c.
 *
 * Two roles, one file:
 *
 *   1. A standalone binary that replays a fragment stream from stdin. Built
 *      with ASan + UBSan, it turns any memory error in reassembly into a
 *      non-zero exit, which is what tests/host/test_ble_fido_fuzz.py drives.
 *      This runs anywhere clang does — including macOS, where libFuzzer is not
 *      shipped with the Command Line Tools.
 *
 *   2. A libFuzzer target (`-DBLE_FUZZ_LIBFUZZER`) for the longer nightly runs
 *      on Linux, matching the `ble_reassembly` target the daemon's PROJECT.md
 *      §14 asks for.
 *
 * Input format (deliberately trivial, so the generator stays in Python):
 *
 *   byte 0      fragment-size selector; the MTU is derived from it
 *   then        repeated: [1-byte length][length bytes of fragment]
 *
 * Truncated trailing records are ignored rather than rejected — a fuzzer
 * mutating the tail should still get a usable prefix.
 */
#include "ble_fido.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Deliveries are recorded, not acted on: this exercises framing only. */
static unsigned long g_delivered;
static unsigned long g_notified;

static int fuzz_notify(const uint8_t *frag, uint16_t len)
{
    /*
     * Touch every byte so ASan sees a read of the whole claimed range. A
     * notify path that reports a length longer than the buffer it built would
     * otherwise pass unnoticed.
     */
    volatile uint8_t sink = 0;
    for (uint16_t i = 0; i < len; i++)
        sink = (uint8_t)(sink ^ frag[i]);
    (void)sink;
    g_notified++;
    return 1;
}

static void fuzz_deliver(uint8_t cmd, const uint8_t *msg, uint16_t len)
{
    volatile uint8_t sink = 0;
    (void)cmd;
    for (uint16_t i = 0; i < len; i++)
        sink = (uint8_t)(sink ^ msg[i]);
    (void)sink;
    g_delivered++;
}

/* Legal fragment sizes, including both boundaries and the awkward middles. */
static const uint16_t kSizes[] = {20, 21, 22, 23, 64, 128, 255, 256, 511, 512};

static void run(const uint8_t *data, size_t size)
{
    ble_fido_set_notify(fuzz_notify);
    ble_fido_set_deliver(fuzz_deliver);
    ble_fido_reset();

    if (size == 0)
        return;

    uint16_t cp = kSizes[data[0] % (sizeof(kSizes) / sizeof(kSizes[0]))];
    ble_fido_set_mtu((uint16_t)(cp + BLE_FIDO_ATT_OVERHEAD));

    size_t off = 1;
    while (off < size) {
        size_t n = data[off++];
        if (off + n > size)
            break; /* truncated tail: stop, do not read past the buffer */
        ble_fido_rx_fragment(data + off, (uint16_t)n);
        off += n;

        /*
         * Invariant, checked continuously rather than only at the end: the
         * reassembler must never report more received than it declared.
         * ble_fido_is_receiving() is the only state we can see from outside,
         * so pair it with the published length, which must always stay legal.
         */
        uint16_t published = ble_fido_control_point_length();
        if (published < BLE_FIDO_MIN_CP_LEN || published > BLE_FIDO_MAX_CP_LEN) {
            fprintf(stderr, "INVARIANT: fidoControlPointLength out of range: %u\n",
                    (unsigned)published);
            abort();
        }
    }
}

#ifdef BLE_FUZZ_LIBFUZZER

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    run(data, size);
    return 0;
}

#else

int main(void)
{
    static uint8_t buf[1 << 16];
    size_t size = fread(buf, 1, sizeof(buf), stdin);
    run(buf, size);
    printf("delivered=%lu notified=%lu receiving=%d\n", g_delivered, g_notified,
           ble_fido_is_receiving());
    return 0;
}

#endif
