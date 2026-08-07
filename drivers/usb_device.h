#ifndef DRIVERS_USB_DEVICE_H
#define DRIVERS_USB_DEVICE_H

#include <stdint.h>
#include <stdbool.h>

/**
 * USB native device (ESP32-S3 USB-C):
 *   - 1× CDC → Arduino Serial (CLI + logs @ 115200)
 *   - 1× HID → FIDO CTAPHID
 *
 * When working, Windows shows VID 0x1209 PID 0xBEEE "Cryptick Token".
 * Espressif VID 0x303A is ROM download / Serial-JTAG only — not app CLI.
 */

#ifdef __cplusplus
extern "C" {
#endif

void usb_device_init(void);
void usb_device_enter_bootloader(void);
void usb_device_poll_bootloader(void);
/** True when TinyUSB stack mounted to host */
bool usb_device_mounted(void);
bool usb_hid_read_report(uint8_t buffer[64]);
bool usb_hid_send_report(const uint8_t buffer[64]);

#define usb_hid_init usb_device_init

#ifdef __cplusplus
}

#include <Arduino.h>
extern Stream &USBLog;
#endif

#endif
