#ifndef DRIVERS_USB_CCID_H
#define DRIVERS_USB_CCID_H

#include <stdint.h>
#include <stdbool.h>

/**
 * USB CCID scaffolding for future PIV / Mac login.
 * Not registered on the product composite until Phase 7 is complete.
 */
#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

void usb_ccid_init(void);
void usb_ccid_poll(void);

/** True once the CCID interface is registered on the product composite. */
bool usb_ccid_enabled(void);

/** Feed one complete CCID message from bulk-OUT; returns the reply length. */
size_t usb_ccid_on_message(const uint8_t *msg, size_t len);

/** The reply built by the last usb_ccid_on_message(), for bulk-IN. */
const uint8_t *usb_ccid_take_reply(size_t *len);

#ifdef __cplusplus
}
#endif

#endif
