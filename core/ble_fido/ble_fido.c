#include "ble_fido.h"
#include <string.h>

/*
 * Reassembly state. One transaction at a time: the BLE transport has no
 * channel IDs, so there is nothing to multiplex and nothing to key state on.
 */
static uint8_t  _msg[BLE_FIDO_MAX_MSG];
static uint16_t _declared;   /* HLEN from the init fragment */
static uint16_t _received;   /* bytes delivered so far */
static uint8_t  _cmd;        /* command from the init fragment */
static uint8_t  _seq;        /* SEQ of the last continuation */
static int      _active;     /* mid-reassembly */

/* Published fidoControlPointLength. Conservative until an MTU is negotiated. */
static uint16_t _cp_len = BLE_FIDO_MIN_CP_LEN;

static ble_fido_notify_fn  _notify;
static ble_fido_deliver_fn _deliver;

void ble_fido_set_notify(ble_fido_notify_fn fn) { _notify = fn; }
void ble_fido_set_deliver(ble_fido_deliver_fn fn) { _deliver = fn; }

void ble_fido_reset(void)
{
    _declared = 0;
    _received = 0;
    _cmd = 0;
    _seq = 0;
    _active = 0;
}

int ble_fido_is_receiving(void) { return _active; }

uint16_t ble_fido_control_point_length(void) { return _cp_len; }

void ble_fido_set_mtu(uint16_t att_mtu)
{
    uint16_t len = (att_mtu > BLE_FIDO_ATT_OVERHEAD)
                       ? (uint16_t)(att_mtu - BLE_FIDO_ATT_OVERHEAD)
                       : 0;
    if (len < BLE_FIDO_MIN_CP_LEN)
        len = BLE_FIDO_MIN_CP_LEN;
    if (len > BLE_FIDO_MAX_CP_LEN)
        len = BLE_FIDO_MAX_CP_LEN;
    _cp_len = len;
}

int ble_fido_send_error(uint8_t err)
{
    uint8_t frag[4];
    if (!_notify)
        return 0;
    frag[0] = BLE_FIDO_CMD_ERROR;
    frag[1] = 0;
    frag[2] = 1;
    frag[3] = err;
    return _notify(frag, 4);
}

int ble_fido_send_keepalive(uint8_t status)
{
    uint8_t frag[4];
    if (!_notify)
        return 0;
    frag[0] = BLE_FIDO_CMD_KEEPALIVE;
    frag[1] = 0;
    frag[2] = 1;
    frag[3] = status;
    return _notify(frag, 4);
}

/** Abort the in-flight transaction and tell the peer why. */
static uint8_t fail(uint8_t err)
{
    ble_fido_reset();
    ble_fido_send_error(err);
    return err;
}

int ble_fido_send_response(uint8_t cmd, const uint8_t *data, uint16_t len)
{
    uint8_t frag[BLE_FIDO_MAX_CP_LEN];
    uint16_t cp = _cp_len;
    uint16_t off = 0;
    uint8_t seq = 0;
    uint16_t chunk;

    if (!_notify)
        return 0;
    if (len && !data)
        return 0;
    if (cp < BLE_FIDO_MIN_CP_LEN || cp > BLE_FIDO_MAX_CP_LEN)
        return 0;

    /*
     * A CANCEL is intercepted on its first fragment and the rest discarded, so
     * a multi-fragment one is something this encoder could build and no
     * reassembler could ever accept — ours or the daemon's. Refuse to emit it
     * rather than putting unreadable bytes on the wire.
     *
     * Nothing here sends CANCEL today (it is a host-to-device command), so this
     * is a guard on the API rather than a live path. Anything we emit, we must
     * be able to read back.
     */
    if (cmd == BLE_FIDO_CMD_CANCEL && len != 0)
        return 0;

    /* Init fragment: CMD ‖ HLEN(2, big-endian) ‖ data */
    frag[0] = cmd;
    frag[1] = (uint8_t)(len >> 8);
    frag[2] = (uint8_t)(len & 0xFF);

    chunk = (uint16_t)(cp - 3);
    if (chunk > len)
        chunk = len;
    if (chunk)
        memcpy(frag + 3, data, chunk);
    if (!_notify(frag, (uint16_t)(3 + chunk)))
        return 0;
    off = chunk;

    /* Continuations: SEQ(1, high bit clear, wraps 0x7f → 0x00) ‖ data */
    while (off < len) {
        frag[0] = seq;
        chunk = (uint16_t)(cp - 1);
        if (chunk > (uint16_t)(len - off))
            chunk = (uint16_t)(len - off);
        memcpy(frag + 1, data + off, chunk);
        if (!_notify(frag, (uint16_t)(1 + chunk)))
            return 0;
        off = (uint16_t)(off + chunk);
        seq = (uint8_t)((seq + 1) & 0x7F);
    }
    return 1;
}

uint8_t ble_fido_rx_fragment(const uint8_t *frag, uint16_t len)
{
    if (!frag || len == 0)
        return fail(BLE_FIDO_ERR_INVALID_LEN);

    /*
     * CANCEL first, before any check that could produce a reply.
     *
     * CTAP2 §11.4.8: "Whether a request was cancelled or not, the authenticator
     * MUST NOT reply to the cancel message itself." Every rejection path below
     * emits CMD_ERROR, so a CANCEL routed through them violates that MUST NOT
     * — which is what happened when this was treated as an ordinary init
     * fragment and answered with ERR_INVALID_SEQ.
     *
     * Consequences, all of them deliberate: CANCEL may interrupt a message in
     * flight (the only command that may), its declared length is ignored
     * rather than validated, and an over-long or truncated CANCEL is still
     * answered with silence. The cancelled request replies for itself with
     * CTAP2_ERR_KEEPALIVE_CANCEL.
     */
    if (frag[0] == BLE_FIDO_CMD_CANCEL) {
        ble_fido_reset();
        if (_deliver)
            _deliver(BLE_FIDO_CMD_CANCEL, NULL, 0);
        return BLE_FIDO_ERR_NONE;
    }

    /*
     * Never accept a fragment larger than the length we published. A peer that
     * ignores fidoControlPointLength is either broken or probing.
     */
    if (len > _cp_len)
        return fail(BLE_FIDO_ERR_INVALID_LEN);

    if (frag[0] & 0x80) {
        /* --- Init fragment: CMD ‖ HLEN(2, big-endian) ‖ data ----------- */
        uint16_t hlen;
        uint16_t chunk;
        uint8_t cmd = frag[0];

        /*
         * An init fragment mid-transaction is a protocol violation, not a
         * second conversation: this transport has no channels, so exactly one
         * transaction is in flight at a time. Fail closed — the abort leaves
         * the reassembler idle, so a host that timed out and retries gets a
         * clean start on its next init at the cost of one round trip.
         *
         * The daemon's ble-framing crate rejects this identically
         * (UnexpectedInitFragment → InvalidSeq); the two halves of the product
         * must agree on the wire or the golden transcripts drift.
         */
        if (_active)
            return fail(BLE_FIDO_ERR_INVALID_SEQ);

        if (len < 3)
            return fail(BLE_FIDO_ERR_INVALID_LEN);

        /*
         * KEEPALIVE (0x82) and ERROR (0xBF) are device→host only. A peer
         * writing them to fidoControlPoint is malformed. The daemon's
         * reassembler accepts them because it sits on the receiving end of
         * those; this asymmetry is by role, not by disagreement.
         */
        if (cmd != BLE_FIDO_CMD_PING && cmd != BLE_FIDO_CMD_MSG)
            return fail(BLE_FIDO_ERR_INVALID_CMD);

        hlen = (uint16_t)((frag[1] << 8) | frag[2]);
        chunk = (uint16_t)(len - 3);

        /*
         * Bound before allocating. HLEN is 16-bit, so a peer can declare 65535;
         * the stack's own ceiling is BLE_FIDO_MAX_MSG. Half-flashed firmware
         * and interrupted OTAs produce exactly this class of
         * malformed-but-authenticated input, so be strict.
         */
        if (hlen > BLE_FIDO_MAX_MSG)
            return fail(BLE_FIDO_ERR_INVALID_LEN);
        if (chunk > hlen)
            return fail(BLE_FIDO_ERR_INVALID_LEN);

        _cmd = cmd;
        _declared = hlen;
        _received = chunk;
        _seq = 0xFF; /* no continuation seen yet; next must be 0 */
        _active = 1;
        if (chunk)
            memcpy(_msg, frag + 3, chunk);

    } else {
        /* --- Continuation fragment: SEQ ‖ data -------------------------- */
        uint8_t seq = frag[0];
        uint16_t chunk = (uint16_t)(len - 1);
        uint8_t expected;

        if (!_active)
            return fail(BLE_FIDO_ERR_INVALID_SEQ);

        /* A continuation carrying no data lets a peer stall forever. */
        if (chunk == 0)
            return fail(BLE_FIDO_ERR_INVALID_LEN);

        expected = (uint8_t)((_seq == 0xFF) ? 0 : ((_seq + 1) & 0x7F));
        if (seq != expected)
            return fail(BLE_FIDO_ERR_INVALID_SEQ);

        if ((uint32_t)_received + chunk > _declared)
            return fail(BLE_FIDO_ERR_INVALID_LEN);

        memcpy(_msg + _received, frag + 1, chunk);
        _received = (uint16_t)(_received + chunk);
        _seq = seq;
    }

    if (_active && _received == _declared) {
        uint8_t cmd = _cmd;
        uint16_t len_done = _received;

        _active = 0;
        if (cmd == BLE_FIDO_CMD_PING) {
            /* Echo the payload straight back; never reaches the CTAP core. */
            ble_fido_send_response(BLE_FIDO_CMD_PING, _msg, len_done);
        } else if (_deliver) {
            _deliver(cmd, _msg, len_done);
        }
    }

    return BLE_FIDO_ERR_NONE;
}
