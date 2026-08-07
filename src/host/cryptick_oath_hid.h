#ifndef CRYPTICK_OATH_HID_H
#define CRYPTICK_OATH_HID_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Handle CTAPHID_CRYPTICK_OATH body (APDU-lite + YKOATH TLV).
 * Request layout: CLA | INS | P1 | P2 | Lc | data[Lc]
 * Response: optional TLV… | SW1 | SW2  (0x90 0x00 = OK)
 *
 * Returns 0 on success (SW always present in resp). Non-zero only if
 * response buffer unusable; caller may emit SW 6F00.
 */
int cryptick_oath_hid_handle(const uint8_t *req, uint16_t req_len,
                             uint8_t *resp, uint16_t *resp_len);

#ifdef __cplusplus
}
#endif

#endif
