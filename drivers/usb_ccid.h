#ifndef DRIVERS_USB_CCID_H
#define DRIVERS_USB_CCID_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/*
 * USB CCID transport for the PIV applet.
 *
 * The protocol is in ccid_proto.c and is host-tested; this is the TinyUSB
 * glue: descriptors, a class driver, endpoint plumbing and the hand-off to
 * the FIDO task.
 *
 * Threading. Reassembly runs on the TinyUSB task, which must never block: a
 * PIV signature waits on a fingerprint for up to 29 s, and doing that on the
 * USB task would stall CDC and HID with it. Complete messages are therefore
 * posted to the FIDO task, which is already the one place that reaches the
 * presence gate. usb_ccid_pump() is that task's end of the queue.
 */

#ifdef __cplusplus
extern "C" {
#endif

void usb_ccid_init(void);
void usb_ccid_poll(void);

/**
 * Reserve endpoints and add the CCID interface to the composite.
 *
 * Must run before USB.begin() and after the CDC instance exists, since CDC
 * reserves its endpoints at construction. Returns false — leaving the
 * composite exactly as it was — when the interface is latched off or the
 * endpoint budget is exhausted. Never fails in a way that takes USB down
 * with it: a CCID that does not enumerate must still leave a device that can
 * be reflashed over CDC.
 */
bool usb_ccid_register(void);

/**
 * Report that the composite reached the configured state.
 *
 * Clears the enumeration-failure latch. See usb_ccid_register().
 */
void usb_ccid_mount_ok(void);

/** True once the CCID interface is registered on the product composite. */
bool usb_ccid_enabled(void);

/**
 * Run one queued CCID message through the applet, from the FIDO task.
 *
 * Returns true if a message was handled. Blocks for as long as the applet
 * does, which for a signature is a fingerprint wait.
 */
bool usb_ccid_pump(void);

/** Feed one complete CCID message from bulk-OUT; returns the reply length. */
size_t usb_ccid_on_message(const uint8_t *msg, size_t len);

/** The reply built by the last usb_ccid_on_message(), for bulk-IN. */
const uint8_t *usb_ccid_take_reply(size_t *len);

#ifdef __cplusplus
}
#endif

#endif
