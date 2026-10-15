#ifndef CORE_BLE_DAEMON_H
#define CORE_BLE_DAEMON_H

#include <stdint.h>
#include <board_config.h>

#if defined(CRYPTICK_BLE_FIDO) && CRYPTICK_BLE_FIDO

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Daemon Bridge over BLE — private GATT service carrying CTAP messages
 * between cryptick-daemon and the token.
 *
 * Base UUID: FBF6EB80-7F39-41B1-A191-9527CC42F8BE
 */
#define BLE_DAEMON_UUID_SERVICE           "FBF6EB80-7F39-41B1-A191-9527CC42F8BE"
#define BLE_DAEMON_UUID_CONTROL_POINT     "FBF6EB81-7F39-41B1-A191-9527CC42F8BE"
#define BLE_DAEMON_UUID_STATUS            "FBF6EB82-7F39-41B1-A191-9527CC42F8BE"
#define BLE_DAEMON_UUID_CONTROL_POINT_LEN "FBF6EB83-7F39-41B1-A191-9527CC42F8BE"
#define BLE_DAEMON_UUID_VERSION           "FBF6EB84-7F39-41B1-A191-9527CC42F8BE"

#define BLE_DAEMON_MAX_MSG 7609

/** Bring up the daemon service. Requires ble_fido_gatt_init() to have run. */
void ble_daemon_gatt_init(void);

/** Drop reassembly state (disconnect). */
void ble_daemon_reset(void);

/** Recompute controlPointLength from a negotiated ATT MTU. */
void ble_daemon_set_mtu(uint16_t att_mtu);

/** Notify one complete response, fragmented as needed. */
int ble_daemon_send_response(uint8_t cmd, const uint8_t *resp, uint16_t len);

/** Notify a one-byte transport error. */
int ble_daemon_send_error(uint8_t err);

/** Notify a one-byte KEEPALIVE (PROCESSING / UP_NEEDED). */
int ble_daemon_send_keepalive(uint8_t status);

/** True once the service is registered. */
int ble_daemon_ready(void);

/** Hand one reassembled message to the FIDO task. */
int daemon_ble_submit_request(uint8_t cmd, const uint8_t *msg, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTICK_BLE_FIDO */

#endif /* CORE_BLE_DAEMON_H */
