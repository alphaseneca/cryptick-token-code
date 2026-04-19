#ifndef DRIVERS_USB_HID_H
#define DRIVERS_USB_HID_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/**
 * @file usb_hid.h
 * @brief Raw USB Human Interface Device (HID) hardware abstraction layer.
 *
 * This module is solely responsible for initializing the hardware USB stack
 * (via TinyUSB) and providing an unstructured 64-byte pipe for IN/OUT reports.
 * It is completely unaware of the FIDO/CTAPHID protocols.
 */

#ifdef __cplusplus
extern "C" {
#endif

void usb_hid_init(void);
bool usb_hid_read_report(uint8_t buffer[64]);
bool usb_hid_send_report(const uint8_t buffer[64]);

#ifdef __cplusplus
}
#endif

#endif
