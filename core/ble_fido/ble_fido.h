#ifndef CORE_BLE_FIDO_H
#define CORE_BLE_FIDO_H

#include <stdint.h>
#include <stdbool.h>

/**
 * BLE FIDO/OATH scaffolding.
 * Goal: reassemble GATT notifications into the same CTAPHID pipeline used on USB.
 * Product MVP remains USB; BLE is wireless transport for FIDO + OATH later.
 * Not started as a NimBLE service in this build (see docs + AGENTS backlog).
 */
#ifdef __cplusplus
extern "C" {
#endif

void ble_fido_init(void);
void ble_fido_poll(void);
bool ble_fido_active(void);
/** Feed a reassembled 64-byte CTAPHID report into the USB HID queue path when ready. */
void ble_fido_push_ctaphid_report(const uint8_t report[64]);

#ifdef __cplusplus
}
#endif

#endif
