#include "piv.h"
#include <string.h>

/* PIV Application AID (NIST) */
static const uint8_t PIV_AID[PIV_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

static void put_sw(uint8_t *out, size_t *len, uint16_t sw)
{
    out[0] = (uint8_t)(sw >> 8);
    out[1] = (uint8_t)(sw & 0xFF);
    *len = 2;
}

/**
 * Minimal PIV APDU stub:
 * - SELECT by AID → 9000 if PIV AID matches
 * - everything else → 6D00 / 6A82 until full applet lands
 *
 * Slots 9a/9d, GENERATE, VERIFY, GENERAL AUTHENTICATE: not implemented.
 */
int piv_handle_apdu(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t out_max)
{
    size_t len = 0;
    if (!cmd || !out || out_max < 2)
        return -1;
    if (cmd_len < 4) {
        put_sw(out, &len, 0x6700);
        return (int)len;
    }

    uint8_t cla = cmd[0];
    uint8_t ins = cmd[1];
    uint8_t p1 = cmd[2];
    uint8_t p2 = cmd[3];
    (void)cla;

    if (ins == 0xA4) {
        /* SELECT */
        size_t lc = (cmd_len > 4) ? cmd[4] : 0;
        if (cmd_len < 5 + lc) {
            put_sw(out, &len, 0x6700);
            return (int)len;
        }
        if (p1 == 0x04 && lc == PIV_AID_LEN &&
            memcmp(cmd + 5, PIV_AID, PIV_AID_LEN) == 0) {
            put_sw(out, &len, 0x9000);
            return (int)len;
        }
        put_sw(out, &len, 0x6A82);
        return (int)len;
    }

    (void)p2;
    put_sw(out, &len, 0x6D00); /* INS not supported in stub */
    return (int)len;
}
