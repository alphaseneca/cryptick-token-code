#ifndef CORE_BLE_PIV_H
#define CORE_BLE_PIV_H

#include <stdint.h>

/*
 * This service is an addition to the FIDO one, not an alternative to it:
 * ble_fido_gatt_init() owns NimBLEDevice::init() and the GATT server, the
 * framing is ble_fido.c's, and the request queue lives beside the CTAP one so
 * the two serialise. Building it alone would link against none of that.
 */
#if defined(CRYPTICK_BLE_PIV) && CRYPTICK_BLE_PIV
#if !defined(CRYPTICK_BLE_FIDO) || !CRYPTICK_BLE_FIDO
#error "CRYPTICK_BLE_PIV requires CRYPTICK_BLE_FIDO"
#endif
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PIV over BLE — the private GATT service that carries ISO 7816 APDUs to the
 * applet, specified in the daemon's docs/device-protocol.md.
 *
 * The framing is the CTAP BLE transport's, byte for byte, so ble_fido.c serves
 * both services through separate contexts. That is why this header declares a
 * service and not a protocol: every framing rule settled for 0xFFFD applies
 * here unchanged, including the one that took two rounds — a CANCEL is acted
 * on when its first fragment arrives, whatever length it declares, and is
 * never answered (CTAP2 §11.4.8).
 *
 * Nothing here may reach a FIDO credential. This is the only door to the PIV
 * key material, not a second door to the FIDO material, and an implementation
 * that routed a request from this service into ctap_request() would have
 * collapsed that distinction. Requests go to piv_handle_apdu().
 */

/* Randomly generated, sharing a base so tooling groups them. No meaning. */
#define BLE_PIV_UUID_SERVICE           "FBF6EB90-7F39-41B1-A191-9527CC42F8BE"
#define BLE_PIV_UUID_CONTROL_POINT     "FBF6EB91-7F39-41B1-A191-9527CC42F8BE"
#define BLE_PIV_UUID_STATUS            "FBF6EB92-7F39-41B1-A191-9527CC42F8BE"
#define BLE_PIV_UUID_CONTROL_POINT_LEN "FBF6EB93-7F39-41B1-A191-9527CC42F8BE"
#define BLE_PIV_UUID_ATR               "FBF6EB94-7F39-41B1-A191-9527CC42F8BE"

/**
 * Reassembly ceiling, both directions.
 *
 * The applet takes short APDUs only and rejects extended-length encoding with
 * 6700, so the longest legal command is CLA INS P1 P2 Lc ‖ 255 ‖ Le = 261.
 * Responses never exceed 258, because the applet chains at 256. One constant
 * serves both directions; an HLEN above it is refused at the initialization
 * fragment, before anything is buffered.
 */
#define BLE_PIV_MAX_MSG 261

/** APDU command, which reuses MSG's value: same slot, same framing rules. */
#define BLE_PIV_CMD_APDU 0x83

/** Bring up the service. Requires ble_fido_gatt_init() to have run. */
void ble_piv_gatt_init(void);

/** Drop reassembly state (disconnect). */
void ble_piv_reset(void);

/** Recompute pivControlPointLength from a negotiated ATT MTU. */
void ble_piv_set_mtu(uint16_t att_mtu);

/** Notify one complete response APDU, fragmented as needed. */
int ble_piv_send_response(const uint8_t *apdu, uint16_t len);

/** Notify a one-byte transport error. */
int ble_piv_send_error(uint8_t err);

/** Notify a one-byte KEEPALIVE (PROCESSING / UP_NEEDED). */
int ble_piv_send_keepalive(uint8_t status);

/** True once the service is registered. Notifying still needs a subscriber. */
int ble_piv_ready(void);

/**
 * Hand one complete command APDU to the task that owns the applet.
 *
 * Implemented in the FIDO HAL, because PIV and FIDO must serialise through one
 * consumer: they share the device's user-presence gate, and one fingerprint
 * touch must never satisfy whichever ceremony reads the flag first. Returns 0
 * if a transaction is already in flight, which the caller reports as ERR_BUSY.
 */
int piv_ble_submit_apdu(const uint8_t *apdu, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif
