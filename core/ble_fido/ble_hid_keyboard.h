#ifndef BLE_HID_KEYBOARD_H_
#define BLE_HID_KEYBOARD_H_

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the BLE HID Keyboard GATT service on the NimBLE server.
 * Requires ble_fido_gatt_init() to have created the server first.
 */
void ble_hid_keyboard_init(void);

/**
 * Returns true if a BLE peer is connected and ready to receive keystrokes.
 */
bool ble_hid_keyboard_is_connected(void);

/**
 * Types the given PIN string followed by Return key over BLE HID.
 * Returns true if sent, false if not connected.
 */
bool ble_hid_type_pin(const char *pin);

/**
 * Default helper to type the PIV PIN (123456).
 */
bool ble_hid_type_piv_pin(void);

/**
 * Types the TOTP code for the specified account index using current synced UTC.
 */
bool ble_hid_type_current_totp(int account_idx);

/**
 * Types any arbitrary string over BLE HID Keyboard.
 */
bool ble_hid_type_string(const char *str);

#ifdef __cplusplus
}
#endif

#endif /* BLE_HID_KEYBOARD_H_ */
