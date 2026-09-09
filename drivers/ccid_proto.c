#include "ccid_proto.h"
#include "piv.h"
#include <string.h>

/*
 * ATR (ISO 7816-3).
 *
 *   TS  = 0x3B  direct convention
 *   T0  = 0x80  TD1 present, no historical bytes
 *   TD1 = 0x01  protocol T=1, no further interface bytes
 *   TCK = 0x81  XOR of every byte after TS, mandatory whenever T=1 is offered
 *
 * Deliberately minimal. Card identity in PIV comes from SELECT by AID, not
 * from the ATR — historical bytes here would be decoration that a host is
 * entitled to match on and then be surprised by.
 */
static const uint8_t kAtr[] = {0x3B, 0x80, 0x01, 0x81};

static int _powered;

int ccid_icc_powered(void) { return _powered; }

void ccid_reset(void)
{
    _powered = 0;
    piv_reset();
}

size_t ccid_get_atr(const uint8_t **atr)
{
    if (atr)
        *atr = kAtr;
    return sizeof(kAtr);
}

/** dwLength is little-endian — the opposite of the BLE transport's HLEN. */
static void put_le32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static uint32_t get_le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/**
 * Build a reply header. `slot` and `seq` are echoed from the command: a reply
 * carrying the wrong bSeq is worse than no reply, because the host matches on
 * it and will pair our answer with a different request.
 */
static size_t reply(uint8_t *out, uint8_t type, uint32_t len, uint8_t slot,
                    uint8_t seq, uint8_t status, uint8_t error, uint8_t param)
{
    out[0] = type;
    put_le32(out + 1, len);
    out[5] = slot;
    out[6] = seq;
    out[7] = status;
    out[8] = error;
    out[9] = param;
    return CCID_HEADER_LEN;
}

static size_t fail(uint8_t *out, uint8_t type, uint8_t slot, uint8_t seq,
                   uint8_t error)
{
    uint8_t icc = _powered ? CCID_ICC_PRESENT_ACTIVE : CCID_ICC_PRESENT_INACTIVE;
    return reply(out, type, 0, slot, seq, (uint8_t)(icc | CCID_CMD_FAILED),
                 error, 0);
}

size_t ccid_handle_message(const uint8_t *in, size_t in_len,
                           uint8_t *out, size_t out_max)
{
    if (!in || !out || in_len < CCID_HEADER_LEN || out_max < CCID_HEADER_LEN)
        return 0; /* no header means no bSeq, so there is nothing to reply to */

    uint8_t  type = in[0];
    uint32_t dw   = get_le32(in + 1);
    uint8_t  slot = in[5];
    uint8_t  seq  = in[6];

    const uint8_t *body = in + CCID_HEADER_LEN;
    size_t avail = in_len - CCID_HEADER_LEN;

    /* One slot. A host probing slot 1 gets a clean refusal, not silence. */
    if (slot != 0)
        return fail(out, CCID_RDR_TO_PC_SLOT_STATUS, slot, seq,
                    CCID_ERR_SLOT_NOT_EXIST);

    /* dwLength must describe the body we actually received. */
    if (dw != avail)
        return fail(out, CCID_RDR_TO_PC_SLOT_STATUS, slot, seq,
                    CCID_ERR_BAD_LENGTH);

    uint8_t icc = _powered ? CCID_ICC_PRESENT_ACTIVE : CCID_ICC_PRESENT_INACTIVE;

    switch (type) {
    case CCID_PC_TO_RDR_ICC_POWER_ON: {
        size_t atr_len = sizeof(kAtr);
        if (out_max < CCID_HEADER_LEN + atr_len)
            return fail(out, CCID_RDR_TO_PC_DATA_BLOCK, slot, seq,
                        CCID_ERR_BAD_LENGTH);
        _powered = 1;
        /* A fresh card: any PIN verified over the previous session is gone. */
        piv_reset();
        size_t n = reply(out, CCID_RDR_TO_PC_DATA_BLOCK, (uint32_t)atr_len,
                         slot, seq, CCID_ICC_PRESENT_ACTIVE, CCID_ERR_NONE, 0);
        memcpy(out + n, kAtr, atr_len);
        return n + atr_len;
    }

    case CCID_PC_TO_RDR_ICC_POWER_OFF:
        _powered = 0;
        /*
         * Powering the card off must drop PIN verification. Otherwise an
         * attacker with physical access power-cycles the reader and inherits
         * the previous session's authentication.
         */
        piv_reset();
        return reply(out, CCID_RDR_TO_PC_SLOT_STATUS, 0, slot, seq,
                     CCID_ICC_PRESENT_INACTIVE, CCID_ERR_NONE, 0);

    case CCID_PC_TO_RDR_GET_SLOT_STATUS:
        return reply(out, CCID_RDR_TO_PC_SLOT_STATUS, 0, slot, seq, icc,
                     CCID_ERR_NONE, 0);

    case CCID_PC_TO_RDR_XFR_BLOCK: {
        if (!_powered)
            return fail(out, CCID_RDR_TO_PC_DATA_BLOCK, slot, seq,
                        CCID_ERR_ICC_MUTE);
        if (avail == 0 || avail > CCID_MAX_APDU)
            return fail(out, CCID_RDR_TO_PC_DATA_BLOCK, slot, seq,
                        CCID_ERR_BAD_LENGTH);

        size_t room = out_max - CCID_HEADER_LEN;
        if (room > CCID_MAX_APDU)
            room = CCID_MAX_APDU;

        int n = piv_handle_apdu(body, avail, out + CCID_HEADER_LEN, room);
        if (n < 2) {
            /*
             * The applet could not answer at all. Report a mute card rather
             * than an empty data block: an empty one reads as a valid
             * zero-length response and the host parses it as a framing error.
             */
            return fail(out, CCID_RDR_TO_PC_DATA_BLOCK, slot, seq,
                        CCID_ERR_ICC_MUTE);
        }
        reply(out, CCID_RDR_TO_PC_DATA_BLOCK, (uint32_t)n, slot, seq,
              CCID_ICC_PRESENT_ACTIVE, CCID_ERR_NONE, 0);
        return CCID_HEADER_LEN + (size_t)n;
    }

    case CCID_PC_TO_RDR_GET_PARAMETERS:
    case CCID_PC_TO_RDR_SET_PARAMETERS:
    case CCID_PC_TO_RDR_RESET_PARAMETERS: {
        /*
         * T=1 protocol data (CCID 1.1 §6.1.7). The values are the defaults
         * every reader reports; the host mostly wants to see that T=1 is what
         * it is going to get.
         */
        static const uint8_t kT1Params[7] = {
            0x11, /* bmFindexDindex */
            0x10, /* bmTCCKST1: T=1, direct convention, LRC */
            0x00, /* bGuardTimeT1 */
            0x4D, /* bwaitingIntegersT1 */
            0x00, /* bClockStop */
            0x20, /* bIFSC */
            0x00, /* bNadValue */
        };
        if (out_max < CCID_HEADER_LEN + sizeof(kT1Params))
            return fail(out, CCID_RDR_TO_PC_PARAMETERS, slot, seq,
                        CCID_ERR_BAD_LENGTH);
        size_t n = reply(out, CCID_RDR_TO_PC_PARAMETERS,
                         (uint32_t)sizeof(kT1Params), slot, seq, icc,
                         CCID_ERR_NONE, 0x01 /* bProtocolNum = T=1 */);
        memcpy(out + n, kT1Params, sizeof(kT1Params));
        return n + sizeof(kT1Params);
    }

    case CCID_PC_TO_RDR_ABORT:
        /* Nothing runs asynchronously here, so there is nothing to abort. */
        return reply(out, CCID_RDR_TO_PC_SLOT_STATUS, 0, slot, seq, icc,
                     CCID_ERR_NONE, 0);

    default:
        /*
         * Unknown command. bError carries the offset of the offending byte,
         * which for an unsupported bMessageType is byte 0.
         */
        return fail(out, CCID_RDR_TO_PC_SLOT_STATUS, slot, seq,
                    CCID_ERR_CMD_NOT_SUPPORTED);
    }
}
