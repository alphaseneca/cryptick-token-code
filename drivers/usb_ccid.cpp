/*
 * USB CCID transport for the PIV applet.
 *
 * The protocol itself lives in ccid_proto.c, which is freestanding and fully
 * host-tested (tests/host/test_ccid_proto.py). What is left here is the part
 * that cannot be tested off-device: TinyUSB descriptors, interface
 * registration and the two bulk endpoints.
 *
 * That split is deliberate. Every defect found in this project so far has been
 * in platform glue rather than in protocol logic, so the glue is kept as small
 * as it can be.
 *
 * STATUS: not registered on the product composite. `usb_ccid_enabled()`
 * returns false and nothing calls into here yet, so the applet is currently
 * reachable only from the host test suite. What remains:
 *
 *   1. A CCID class descriptor (bInterfaceClass 0x0B) plus its 54-byte
 *      functional descriptor — dwProtocols must advertise T=1 to match the ATR
 *      and the parameters ccid_proto.c reports.
 *   2. Two bulk endpoints (IN/OUT). The S3 has enough left alongside CDC+HID,
 *      but the budget is the thing to check first: adding CCID to a composite
 *      that already enumerates is where this usually goes wrong.
 *   3. Reassembly of a bulk transfer into one complete CCID message before
 *      calling usb_ccid_on_message() — a message can span several 64-byte
 *      packets, and ccid_handle_message() requires a whole one.
 *
 * Until then this is compiled, not wired: it keeps signature drift against
 * ccid_proto.h visible to the build rather than to a future bring-up session.
 */
#include "usb_ccid.h"
#include "ccid_proto.h"

#include <string.h>

/* One message in flight; CCID is strictly request/response per slot. */
static uint8_t _reply[CCID_MAX_MESSAGE];
static size_t  _reply_len;

void usb_ccid_init(void)
{
    ccid_reset();
    _reply_len = 0;
}

/**
 * Feed one complete CCID message from the bulk-OUT endpoint.
 *
 * Returns the reply length, with the reply available from
 * usb_ccid_take_reply(). A zero return means the message was too short to
 * carry a header, which is the one case with no legal answer — every other
 * malformed input is reported inside a well-formed reply, because a reader
 * that goes silent wedges the host waiting on a bSeq that never arrives.
 */
size_t usb_ccid_on_message(const uint8_t *msg, size_t len)
{
    _reply_len = ccid_handle_message(msg, len, _reply, sizeof(_reply));
    return _reply_len;
}

const uint8_t *usb_ccid_take_reply(size_t *len)
{
    if (len)
        *len = _reply_len;
    return _reply_len ? _reply : NULL;
}

void usb_ccid_poll(void) {}

bool usb_ccid_enabled(void)
{
    /* Flip only once the descriptors above exist and enumerate. */
    return false;
}
