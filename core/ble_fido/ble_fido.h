#ifndef CORE_BLE_FIDO_H
#define CORE_BLE_FIDO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * FIDO BLE transport framing (CTAP2 §11.2).
 *
 * This is NOT CTAPHID over BLE. CTAPHID is the USB HID transport and nothing
 * else: 64-byte reports, 4-byte channel IDs, a 7-byte init header, and an INIT
 * handshake to allocate a CID. The BLE transport shares none of that.
 *
 *                    CTAPHID (USB)                FIDO BLE
 *   Unit             64-byte report, fixed        fragment, 20..512
 *   Init header      CID(4) CMD(1) BCNT(2) = 7    CMD(1) HLEN(2, BE) = 3
 *   Cont header      CID(4) SEQ(1) = 5            SEQ(1) = 1
 *   Channels         yes (CIDs, INIT handshake)   none
 *
 * CTAP2 CBOR rides directly inside MSG, not inside a CTAPHID frame. Building
 * this as a tunnel would leave a token only a bespoke host daemon could drive:
 * Windows' native BLE FIDO stack, libfido2, Chrome/Edge and
 * webauthn-authenticator-rs would all fail to talk to it.
 *
 * Everything here is freestanding byte work — no NimBLE, no FreeRTOS — so the
 * host test suite compiles this file and drives the state machine directly.
 * Platform glue supplies the two callbacks below.
 */

/* --- GATT service and characteristics ---------------------------------- */

/** 16-bit FIDO Service UUID; must also appear in the advertisement. */
#define BLE_FIDO_SERVICE_UUID16 0xFFFD

#define BLE_FIDO_UUID_CONTROL_POINT     "F1D0FFF1-DEAA-ECEE-B42F-C9BA7ED623BB"
#define BLE_FIDO_UUID_STATUS            "F1D0FFF2-DEAA-ECEE-B42F-C9BA7ED623BB"
#define BLE_FIDO_UUID_CONTROL_POINT_LEN "F1D0FFF3-DEAA-ECEE-B42F-C9BA7ED623BB"
#define BLE_FIDO_UUID_SERVICE_REVISION  "F1D0FFF4-DEAA-ECEE-B42F-C9BA7ED623BB"

/** fidoServiceRevisionBitfield: bit 5 = FIDO2, bit 6 = U2F 1.2, bit 7 = U2F 1.1. */
#define BLE_FIDO_REVISION_FIDO2   0x20
#define BLE_FIDO_REVISION_U2F_12  0x40
#define BLE_FIDO_REVISION_U2F_11  0x80

/* --- Commands ----------------------------------------------------------- */

#define BLE_FIDO_CMD_PING      0x81
#define BLE_FIDO_CMD_KEEPALIVE 0x82
#define BLE_FIDO_CMD_MSG       0x83
#define BLE_FIDO_CMD_CANCEL    0xBE
#define BLE_FIDO_CMD_ERROR     0xBF

/* KEEPALIVE payload byte. */
#define BLE_FIDO_STATUS_PROCESSING 0x01
#define BLE_FIDO_STATUS_UP_NEEDED  0x02

/* --- Errors, emitted as the one-byte body of CMD_ERROR ------------------ */

#define BLE_FIDO_ERR_NONE        0x00
#define BLE_FIDO_ERR_INVALID_CMD 0x01
#define BLE_FIDO_ERR_INVALID_PAR 0x02
#define BLE_FIDO_ERR_INVALID_LEN 0x03
#define BLE_FIDO_ERR_INVALID_SEQ 0x04
#define BLE_FIDO_ERR_REQ_TIMEOUT 0x05
/* Real BLE code (CTAP2 §11.4.4.3) — only 0x0a/0x0b are HID-reserved. Reporting
 * a busy authenticator as ERR_OTHER loses the one thing the peer can act on. */
#define BLE_FIDO_ERR_BUSY        0x06
#define BLE_FIDO_ERR_OTHER       0x7F

/* --- Bounds -------------------------------------------------------------- */

/**
 * Reassembly ceiling. HLEN is 16-bit, so a peer may declare up to 65535 bytes;
 * we must not allocate that. This mirrors CTAP_MAX_MESSAGE_SIZE in ctap.h —
 * the ESP32 glue static-asserts the two agree, so this header stays
 * independent of the CTAP stack for host builds.
 */
#define BLE_FIDO_MAX_MSG 1200

/** fidoControlPointLength bounds (CTAP2 §11.2.3). */
#define BLE_FIDO_MIN_CP_LEN 20
#define BLE_FIDO_MAX_CP_LEN 512

/** ATT protocol overhead: a write/notify carries ATT_MTU - 3 payload bytes. */
#define BLE_FIDO_ATT_OVERHEAD 3

/* --- Platform callbacks -------------------------------------------------- */

/**
 * Send one fragment as a notification on fidoStatus.
 * Return non-zero on success. Set by the GATT glue.
 */
typedef int (*ble_fido_notify_fn)(const uint8_t *frag, uint16_t len);

/**
 * Hand a fully reassembled request to the CTAP layer.
 *
 * Called from whichever task runs the GATT write callback, so it must not
 * touch the CTAP core directly — it posts to the single FIDO task instead.
 * See docs/ARCHITECTURE.md#threading-model.
 */
typedef void (*ble_fido_deliver_fn)(uint8_t cmd, const uint8_t *msg, uint16_t len);

void ble_fido_set_notify(ble_fido_notify_fn fn);
void ble_fido_set_deliver(ble_fido_deliver_fn fn);

/* --- Contexts ------------------------------------------------------------ */

/*
 * One context per GATT service.
 *
 * The framing above is not specific to FIDO: PIV over BLE reuses it byte for
 * byte on its own service, so the state it keeps has to be per-service rather
 * than per-image. A second service sharing one reassembler would let a
 * fragment written to one interleave with a message being assembled on the
 * other, and neither peer would have any way to tell.
 *
 * The message buffer is supplied by the caller because the two services cap
 * messages very differently -- CTAP needs 1200 bytes, PIV 261 -- and a fixed
 * buffer per context would spend most of the second one on nothing.
 *
 * Treat the fields as private; they are exposed only so a context can be a
 * plain object with no allocator behind it.
 */

/** PING is a FIDO command. A service that does not offer it refuses it. */
#define BLE_FIDO_CTX_NO_PING 0x01u

typedef struct {
    uint8_t  *msg;       /* caller-owned reassembly buffer */
    uint16_t  msg_cap;   /* its size, and the largest HLEN accepted */
    uint16_t  declared;  /* HLEN from the init fragment */
    uint16_t  received;  /* bytes delivered so far */
    uint8_t   cmd;       /* command from the init fragment */
    uint8_t   seq;       /* SEQ of the last continuation */
    int       active;    /* mid-reassembly */
    uint16_t  cp_len;    /* published control point length */
    uint32_t  flags;
    ble_fido_notify_fn  notify;
    ble_fido_deliver_fn deliver;
} ble_fido_ctx_t;

/**
 * Prepare a context around a caller-owned buffer.
 *
 * `cap` is both the buffer size and the reassembly ceiling: an init fragment
 * declaring more is refused before anything is copied.
 */
void ble_fido_ctx_init(ble_fido_ctx_t *ctx, uint8_t *buf, uint16_t cap,
                       uint32_t flags);

void ble_fido_ctx_set_notify(ble_fido_ctx_t *ctx, ble_fido_notify_fn fn);
void ble_fido_ctx_set_deliver(ble_fido_ctx_t *ctx, ble_fido_deliver_fn fn);
void ble_fido_ctx_reset(ble_fido_ctx_t *ctx);
uint8_t ble_fido_ctx_rx_fragment(ble_fido_ctx_t *ctx, const uint8_t *frag, uint16_t len);
void ble_fido_ctx_set_mtu(ble_fido_ctx_t *ctx, uint16_t att_mtu);
uint16_t ble_fido_ctx_control_point_length(const ble_fido_ctx_t *ctx);
int ble_fido_ctx_send_response(ble_fido_ctx_t *ctx, uint8_t cmd, const uint8_t *data, uint16_t len);
int ble_fido_ctx_send_keepalive(ble_fido_ctx_t *ctx, uint8_t status);
int ble_fido_ctx_send_error(ble_fido_ctx_t *ctx, uint8_t err);
int ble_fido_ctx_is_receiving(const ble_fido_ctx_t *ctx);

/** The context behind the no-argument calls below: the FIDO service on 0xFFFD. */
ble_fido_ctx_t *ble_fido_default_ctx(void);

/* --- Transport ----------------------------------------------------------- */

/*
 * CANCEL (CTAP2 §11.4.8) is answered by silence:
 *
 *   "Whether a request was cancelled or not, the authenticator MUST NOT reply
 *    to the cancel message itself."
 *
 * So it is the one command allowed to interrupt a message in flight, it is
 * accepted with any HLEN (its payload is ignored), and it never produces a
 * CMD_ERROR — there is no legal way to report a malformed cancel, which is why
 * rejecting one is unimplementable rather than merely strict.
 */

/** Reset framing state; call on init, disconnect, CANCEL and timeout. */
void ble_fido_reset(void);

/**
 * Feed one fragment received on fidoControlPoint.
 * Returns BLE_FIDO_ERR_NONE, or the error already emitted as CMD_ERROR.
 */
uint8_t ble_fido_rx_fragment(const uint8_t *frag, uint16_t len);

/** Recompute fidoControlPointLength from a negotiated ATT MTU. */
void ble_fido_set_mtu(uint16_t att_mtu);

/** Current fidoControlPointLength. Never send a fragment larger than this. */
uint16_t ble_fido_control_point_length(void);

/** Fragment and notify a complete response. Returns non-zero on success. */
int ble_fido_send_response(uint8_t cmd, const uint8_t *data, uint16_t len);

/** One-byte KEEPALIVE notification (PROCESSING / UP_NEEDED). */
int ble_fido_send_keepalive(uint8_t status);

/** One-byte CMD_ERROR notification. */
int ble_fido_send_error(uint8_t err);

/** Non-zero while a request is partially reassembled. */
int ble_fido_is_receiving(void);

/**
 * Bring up the GATT service and start advertising (ESP32/NimBLE glue in
 * ble_gatt_esp32.cpp). Idempotent. Not built when CRYPTICK_BLE_FIDO is 0.
 */
void ble_fido_gatt_init(void);

#ifdef __cplusplus
}
#endif

#endif
