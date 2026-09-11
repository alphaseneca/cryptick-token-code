#ifndef DRIVERS_CCID_DESCRIPTORS_H
#define DRIVERS_CCID_DESCRIPTORS_H

#include <stdint.h>
#include <stddef.h>
#include "ccid_proto.h"

/*
 * The CCID interface descriptor set, as data.
 *
 * Descriptors are the only part of the USB glue that can be checked without a
 * host and a reader, so they are kept here — freestanding, no TinyUSB — and
 * the host suite compiles this file and asserts on the actual bytes
 * (tests/host/test_ccid_descriptors.py). usb_ccid.cpp copies the template and
 * patches in the interface number, string index and endpoint addresses, which
 * are the only fields not known until registration.
 *
 * The USB constants below are spelled out rather than taken from tusb.h so
 * this stays compilable on the host; usb_ccid.cpp static_asserts them against
 * TinyUSB's own values, so a divergence fails the firmware build.
 */

#define CCID_DESC_TYPE_INTERFACE 0x04
#define CCID_DESC_TYPE_ENDPOINT  0x05
#define CCID_DESC_TYPE_FUNCTIONAL 0x21
#define CCID_XFER_BULK           0x02
#define CCID_INTERFACE_CLASS     0x0B  /* what makes an OS smartcard stack bind */
#define CCID_EP_SIZE             64

#define CCID_ITF_DESC_LEN   9
#define CCID_FUNC_DESC_LEN  54
#define CCID_EP_DESC_LEN    7
#define CCID_DESC_TOTAL_LEN (CCID_ITF_DESC_LEN + CCID_FUNC_DESC_LEN + 2 * CCID_EP_DESC_LEN)

/* Fields patched at registration. Asserted against the field they name. */
#define CCID_OFF_ITF_NUM 2
#define CCID_OFF_ITF_STR 8
#define CCID_OFF_EP_OUT  (CCID_ITF_DESC_LEN + CCID_FUNC_DESC_LEN + 2)
#define CCID_OFF_EP_IN   (CCID_ITF_DESC_LEN + CCID_FUNC_DESC_LEN + CCID_EP_DESC_LEN + 2)

/*
 * dwFeatures. Every bit is a promise about what this reader does, and
 * over-claiming is how a host ends up sending bytes the applet cannot parse.
 *
 *   0x00000040  parameter negotiation done by the CCID — SetParameters is
 *               accepted and ignored, so the host must not expect to drive it.
 *   0x00000800  automatic IFSD exchange as the first exchange — trivially
 *               true, there being no real T=1 block layer underneath.
 *   0x00020000  short APDU level exchange. Deliberately not the
 *               short-and-extended value (0x00040000) that comparable devices
 *               ship: piv.c decodes short APDUs only, and a host told it may
 *               send an extended one would have its 3-byte Lc read as a
 *               one-byte zero. TPDU level (0x00010000) is wrong the other way
 *               — ccid_proto.c forwards whole APDUs and implements no T=1
 *               block layer, so a host sending TPDUs would get nonsense back.
 */
#define CCID_DW_FEATURES 0x00020840UL

/* T=1 only, which is what the ATR in ccid_proto.c encodes (TD1 = 0x01). */
#define CCID_DW_PROTOCOLS 0x00000002UL

#define CCID_U16_(v) (uint8_t)((v) & 0xFF), (uint8_t)(((v) >> 8) & 0xFF)
#define CCID_U32_(v) (uint8_t)((v) & 0xFF), (uint8_t)(((v) >> 8) & 0xFF), \
                     (uint8_t)(((v) >> 16) & 0xFF), (uint8_t)(((v) >> 24) & 0xFF)

#define CCID_DESCRIPTOR_TEMPLATE {                                            \
    /* Interface. Subclass and protocol are both 0: bulk transfer, no ICCD. */\
    CCID_ITF_DESC_LEN, CCID_DESC_TYPE_INTERFACE, 0x00, 0x00, 0x02,            \
        CCID_INTERFACE_CLASS, 0x00, 0x00, 0x00,                               \
                                                                              \
    /* CCID class descriptor (CCID 1.1 section 5.1). */                       \
    CCID_FUNC_DESC_LEN,                                                       \
    CCID_DESC_TYPE_FUNCTIONAL,                                                \
    CCID_U16_(0x0110),            /* bcdCCID 1.10                          */ \
    0x00,                         /* bMaxSlotIndex — one slot              */ \
    0x07,                         /* bVoltageSupport 5.0/3.0/1.8           */ \
    CCID_U32_(CCID_DW_PROTOCOLS), /* dwProtocols                           */ \
    CCID_U32_(3580UL),            /* dwDefaultClock (kHz)                  */ \
    CCID_U32_(3580UL),            /* dwMaximumClock (kHz)                  */ \
    0x00,                         /* bNumClockSupported — default only     */ \
    CCID_U32_(9600UL),            /* dwDataRate (bps)                      */ \
    CCID_U32_(115200UL),          /* dwMaxDataRate (bps)                   */ \
    0x00,                         /* bNumDataRatesSupported                */ \
    CCID_U32_(254UL),             /* dwMaxIFSD                             */ \
    CCID_U32_(0UL),               /* dwSynchProtocols — none               */ \
    CCID_U32_(0UL),               /* dwMechanical — no card movement       */ \
    CCID_U32_(CCID_DW_FEATURES),  /* dwFeatures                            */ \
    CCID_U32_(CCID_MAX_MESSAGE),  /* dwMaxCCIDMessageLength                */ \
    0xFF,                         /* bClassGetResponse — echo class        */ \
    0xFF,                         /* bClassEnvelope — echo class           */ \
    CCID_U16_(0x0000),            /* wLcdLayout — no display               */ \
    0x00,                         /* bPINSupport — no PIN pad              */ \
    0x01,                         /* bMaxCCIDBusySlots                     */ \
                                                                              \
    /* Bulk OUT, then bulk IN. Addresses patched in at registration. */       \
    CCID_EP_DESC_LEN, CCID_DESC_TYPE_ENDPOINT, 0x00, CCID_XFER_BULK,          \
        CCID_U16_(CCID_EP_SIZE), 0x00,                                        \
    CCID_EP_DESC_LEN, CCID_DESC_TYPE_ENDPOINT, 0x80, CCID_XFER_BULK,          \
        CCID_U16_(CCID_EP_SIZE), 0x00,                                        \
}

#ifdef __cplusplus
extern "C" {
#endif

/** The template above, as bytes. Exposed so the host suite can assert on it. */
const uint8_t *ccid_descriptor_template(size_t *len);

#ifdef __cplusplus
}
#endif

#endif
