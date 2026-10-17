#ifndef DRIVERS_USB_DEVICE_H
#define DRIVERS_USB_DEVICE_H

#include <stdint.h>
#include <stdbool.h>

/**
 * USB native device (ESP32-S3 USB-C) — when CRYPTICK_USB_STACK=1:
 *   - 1× CDC → logs @ 115200
 *   - 1× HID → FIDO CTAPHID + Cryptick OATH + ENTERBOOT
 *
 * Default product build: stack off; host uses CH340 UART0 (see cryptick_console.h).
 * Brand when USB on: VID 0x1209 PID 0xBEEE "Cryptick Token".
 */

#ifdef __cplusplus
extern "C" {
#endif

void usb_device_init(void);
void usb_device_enter_bootloader(void);
void usb_device_poll_bootloader(void);
/** True when TinyUSB stack mounted to host (always false if stack off) */
bool usb_device_mounted(void);
/**
 * Factory-unique device identity, derived at boot from the ESP32-S3's burned-in
 * eFuse base MAC (esp_efuse_mac_get_default) — never random or hardcoded.
 * Formatted "CT-XXXXXXXXXXXX" (12 uppercase hex chars = the 6 MAC bytes in
 * order, no separators). In the product USB build (ARDUINO_USB_MODE=0) this
 * exact string is also programmed as the USB iSerialNumber string descriptor
 * (see usb_device_init()). Computed once on first call; same string every boot
 * on a given chip.
 */
const char *usb_device_serial_number(void);
bool usb_hid_read_report(uint8_t buffer[64]);
/**
 * Reliable HID IN: wait for endpoint free, submit one 64-byte report, wait for
 * host completion (ready again). Used for CTAPHID responses (multi-frame MSG).
 */
bool usb_hid_send_report(const uint8_t buffer[64]);
/**
 * Best-effort HID IN: drop immediately if endpoint busy / not mounted.
 * Used for CTAPHID keepalives so they never block multi-frame writeback.
 */
bool usb_hid_try_send_report(const uint8_t buffer[64]);

#define usb_hid_init usb_device_init

#ifdef __cplusplus
}

#include <Arduino.h>
extern Stream &USBLog;
#endif

#endif
