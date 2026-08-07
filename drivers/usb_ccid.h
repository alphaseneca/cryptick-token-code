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

void usb_ccid_init(void);
void usb_ccid_poll(void);
bool usb_ccid_enabled(void);

#ifdef __cplusplus
}
#endif

#endif
