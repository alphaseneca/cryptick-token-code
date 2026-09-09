#ifndef DRIVERS_CCID_PROTO_H
#define DRIVERS_CCID_PROTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * CCID bulk message layer (USB CCID 1.1, §6).
 *
 * This is the protocol an OS smartcard stack speaks to a reader: PC/SC on
 * Windows, pcscd on Linux, CryptoTokenKit on macOS. It wraps the ISO 7816
 * APDUs that core/piv understands, so the applet needs no idea it is on USB.
 *
 * Freestanding on purpose, exactly like core/ble_fido/ble_fido.c: no TinyUSB,
 * no FreeRTOS, no endpoints. The host test suite compiles and drives it, which
 * leaves only descriptors and endpoint plumbing in the part that cannot be
 * tested off-device — and that is where every bug in this project has been.
 *
 * Every message begins with a 10-byte header. Lengths are little-endian, which
 * is the opposite of everything in the FIDO BLE transport; mixing them up is
 * the classic CCID bug.
 */

#define CCID_HEADER_LEN 10

/* Host → reader */
#define CCID_PC_TO_RDR_ICC_POWER_ON   0x62
#define CCID_PC_TO_RDR_ICC_POWER_OFF  0x63
#define CCID_PC_TO_RDR_GET_SLOT_STATUS 0x65
#define CCID_PC_TO_RDR_XFR_BLOCK      0x6F
#define CCID_PC_TO_RDR_GET_PARAMETERS 0x6C
#define CCID_PC_TO_RDR_RESET_PARAMETERS 0x6D
#define CCID_PC_TO_RDR_SET_PARAMETERS 0x61
#define CCID_PC_TO_RDR_ABORT          0x72

/* Reader → host */
#define CCID_RDR_TO_PC_DATA_BLOCK  0x80
#define CCID_RDR_TO_PC_SLOT_STATUS 0x81
#define CCID_RDR_TO_PC_PARAMETERS  0x82

/* bStatus: bits 0-1 ICC status, bits 6-7 command status. */
#define CCID_ICC_PRESENT_ACTIVE   0x00
#define CCID_ICC_PRESENT_INACTIVE 0x01
#define CCID_ICC_NOT_PRESENT      0x02
#define CCID_CMD_FAILED           0x40

/* bError values we emit. */
#define CCID_ERR_NONE            0x00
#define CCID_ERR_SLOT_NOT_EXIST  0x05
#define CCID_ERR_CMD_NOT_SUPPORTED 0x00
#define CCID_ERR_ICC_MUTE        0xFE
#define CCID_ERR_BAD_LENGTH      0x01

/**
 * Largest APDU exchange. A PIV certificate read is chained by the applet in
 * 256-byte pieces, so this only has to hold one short-APDU round trip with
 * headroom, not a whole certificate.
 */
#define CCID_MAX_APDU 512

/** Largest message we ever emit: header + ATR or APDU response. */
#define CCID_MAX_MESSAGE (CCID_HEADER_LEN + CCID_MAX_APDU)

/**
 * Handle one complete PC_to_RDR message and build the reply.
 *
 * `in`/`in_len` is the whole bulk-OUT message including its header.
 * Writes the RDR_to_PC reply to `out` and returns its length, or 0 if the
 * message was too short to carry a header — the only case with no legal reply,
 * since a reply needs the sequence number the header carries.
 *
 * Never returns an error to the caller for a malformed *body*: CCID reports
 * those in bStatus/bError inside a well-formed reply, and a reader that goes
 * silent instead wedges the host's stack waiting for a response that matches
 * its bSeq.
 */
size_t ccid_handle_message(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_max);

/** Power state, so the glue can report it and tests can assert on it. */
int ccid_icc_powered(void);

/** Reset to the powered-off state (USB reset / configuration change). */
void ccid_reset(void);

/**
 * The ATR reported on power-on. Returns its length and points *atr at it.
 * Exposed so a test can check the checksum rather than trusting the constant.
 */
size_t ccid_get_atr(const uint8_t **atr);

#ifdef __cplusplus
}
#endif

#endif
