#include "ble_fido.h"
#include <string.h>

/*
 * Framing state lives in a context, one per GATT service.
 *
 * Within a context there is still exactly one transaction at a time: the BLE
 * transport has no channel IDs, so there is nothing to multiplex and nothing
 * to key state on. What a second context buys is a second *service* — PIV over
 * BLE reuses this framing byte for byte — not a second concurrent request.
 *
 * The no-argument functions at the bottom of this file operate on the FIDO
 * service's context, which is what every existing caller and the conformance
 * corpus drive.
 */

void ble_fido_ctx_init(ble_fido_ctx_t *ctx, uint8_t *buf, uint16_t cap,
                       uint32_t flags)
{
    if (!ctx)
        return;
    memset(ctx, 0, sizeof(*ctx));
    ctx->msg = buf;
    ctx->msg_cap = buf ? cap : 0;
    ctx->flags = flags;
    /* Conservative until an MTU is negotiated. */
    ctx->cp_len = BLE_FIDO_MIN_CP_LEN;
}

void ble_fido_ctx_set_notify(ble_fido_ctx_t *ctx, ble_fido_notify_fn fn)
{
    if (ctx) ctx->notify = fn;
}

void ble_fido_ctx_set_deliver(ble_fido_ctx_t *ctx, ble_fido_deliver_fn fn)
{
    if (ctx) ctx->deliver = fn;
}

void ble_fido_ctx_reset(ble_fido_ctx_t *ctx)
{
    if (!ctx)
        return;
    ctx->declared = 0;
    ctx->received = 0;
    ctx->cmd = 0;
    ctx->seq = 0;
    ctx->active = 0;
}

int ble_fido_ctx_is_receiving(const ble_fido_ctx_t *ctx)
{
    return ctx ? ctx->active : 0;
}

uint16_t ble_fido_ctx_control_point_length(const ble_fido_ctx_t *ctx)
{
    return ctx ? ctx->cp_len : BLE_FIDO_MIN_CP_LEN;
}

void ble_fido_ctx_set_mtu(ble_fido_ctx_t *ctx, uint16_t att_mtu)
{
    uint16_t len;
    if (!ctx)
        return;
    len = (att_mtu > BLE_FIDO_ATT_OVERHEAD)
              ? (uint16_t)(att_mtu - BLE_FIDO_ATT_OVERHEAD)
              : 0;
    if (len < BLE_FIDO_MIN_CP_LEN)
        len = BLE_FIDO_MIN_CP_LEN;
    if (len > BLE_FIDO_MAX_CP_LEN)
        len = BLE_FIDO_MAX_CP_LEN;
    ctx->cp_len = len;
}

int ble_fido_ctx_send_error(ble_fido_ctx_t *ctx, uint8_t err)
{
    uint8_t frag[4];
    if (!ctx || !ctx->notify)
        return 0;
    frag[0] = BLE_FIDO_CMD_ERROR;
    frag[1] = 0;
    frag[2] = 1;
    frag[3] = err;
    return ctx->notify(frag, 4);
}

int ble_fido_ctx_send_keepalive(ble_fido_ctx_t *ctx, uint8_t status)
{
    uint8_t frag[4];
    if (!ctx || !ctx->notify)
        return 0;
    frag[0] = BLE_FIDO_CMD_KEEPALIVE;
    frag[1] = 0;
    frag[2] = 1;
    frag[3] = status;
    return ctx->notify(frag, 4);
}

/** Abort the in-flight transaction and tell the peer why. */
static uint8_t fail(ble_fido_ctx_t *ctx, uint8_t err)
{
    ble_fido_ctx_reset(ctx);
    ble_fido_ctx_send_error(ctx, err);
    return err;
}

int ble_fido_ctx_send_response(ble_fido_ctx_t *ctx, uint8_t cmd,
                               const uint8_t *data, uint16_t len)
{
    uint8_t frag[BLE_FIDO_MAX_CP_LEN];
    uint16_t cp;
    uint16_t off = 0;
    uint8_t seq = 0;
    uint16_t chunk;

    if (!ctx || !ctx->notify)
        return 0;
    if (len && !data)
        return 0;

    cp = ctx->cp_len;
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
    if (!ctx->notify(frag, (uint16_t)(3 + chunk)))
        return 0;
    off = chunk;

    /* Continuations: SEQ(1, high bit clear, wraps 0x7f → 0x00) ‖ data */
    while (off < len) {
        frag[0] = seq;
        chunk = (uint16_t)(cp - 1);
        if (chunk > (uint16_t)(len - off))
            chunk = (uint16_t)(len - off);
        memcpy(frag + 1, data + off, chunk);
        if (!ctx->notify(frag, (uint16_t)(1 + chunk)))
            return 0;
        off = (uint16_t)(off + chunk);
        seq = (uint8_t)((seq + 1) & 0x7F);
    }
    return 1;
}

uint8_t ble_fido_ctx_rx_fragment(ble_fido_ctx_t *ctx, const uint8_t *frag,
                                 uint16_t len)
{
    if (!ctx || !ctx->msg)
        return BLE_FIDO_ERR_OTHER;
    if (!frag || len == 0)
        return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

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
        ble_fido_ctx_reset(ctx);
        if (ctx->deliver)
            ctx->deliver(BLE_FIDO_CMD_CANCEL, NULL, 0);
        return BLE_FIDO_ERR_NONE;
    }

    /*
     * Never accept a fragment larger than the length we published. A peer that
     * ignores fidoControlPointLength is either broken or probing.
     */
    if (len > ctx->cp_len)
        return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

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
        if (ctx->active)
            return fail(ctx, BLE_FIDO_ERR_INVALID_SEQ);

        if (len < 3)
            return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

        /*
         * KEEPALIVE (0x82) and ERROR (0xBF) are device→host only. A peer
         * writing them to fidoControlPoint is malformed. The daemon's
         * reassembler accepts them because it sits on the receiving end of
         * those; this asymmetry is by role, not by disagreement.
         *
         * PING is refused outright on a service that does not offer it. A
         * service reachable only after an authenticated bond has no use for an
         * echo, and answering one would be inventing a command the peer was
         * never told about.
         */
        if (cmd == BLE_FIDO_CMD_PING) {
            if (ctx->flags & BLE_FIDO_CTX_NO_PING)
                return fail(ctx, BLE_FIDO_ERR_INVALID_CMD);
        } else if (cmd != BLE_FIDO_CMD_MSG) {
            return fail(ctx, BLE_FIDO_ERR_INVALID_CMD);
        }

        hlen = (uint16_t)((frag[1] << 8) | frag[2]);
        chunk = (uint16_t)(len - 3);

        /*
         * Bound before allocating. HLEN is 16-bit, so a peer can declare 65535;
         * the ceiling is this context's buffer, which differs per service.
         * Half-flashed firmware and interrupted OTAs produce exactly this class
         * of malformed-but-authenticated input, so be strict.
         */
        if (hlen > ctx->msg_cap)
            return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);
        if (chunk > hlen)
            return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

        ctx->cmd = cmd;
        ctx->declared = hlen;
        ctx->received = chunk;
        ctx->seq = 0xFF; /* no continuation seen yet; next must be 0 */
        ctx->active = 1;
        if (chunk)
            memcpy(ctx->msg, frag + 3, chunk);

    } else {
        /* --- Continuation fragment: SEQ ‖ data -------------------------- */
        uint8_t seq = frag[0];
        uint16_t chunk = (uint16_t)(len - 1);
        uint8_t expected;

        if (!ctx->active)
            return fail(ctx, BLE_FIDO_ERR_INVALID_SEQ);

        /* A continuation carrying no data lets a peer stall forever. */
        if (chunk == 0)
            return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

        expected = (uint8_t)((ctx->seq == 0xFF) ? 0 : ((ctx->seq + 1) & 0x7F));
        if (seq != expected)
            return fail(ctx, BLE_FIDO_ERR_INVALID_SEQ);

        if ((uint32_t)ctx->received + chunk > ctx->declared)
            return fail(ctx, BLE_FIDO_ERR_INVALID_LEN);

        memcpy(ctx->msg + ctx->received, frag + 1, chunk);
        ctx->received = (uint16_t)(ctx->received + chunk);
        ctx->seq = seq;
    }

    if (ctx->active && ctx->received == ctx->declared) {
        uint8_t cmd = ctx->cmd;
        uint16_t len_done = ctx->received;

        ctx->active = 0;
        if (cmd == BLE_FIDO_CMD_PING) {
            /* Echo the payload straight back; never reaches the CTAP core. */
            ble_fido_ctx_send_response(ctx, BLE_FIDO_CMD_PING, ctx->msg, len_done);
        } else if (ctx->deliver) {
            ctx->deliver(cmd, ctx->msg, len_done);
        }
    }

    return BLE_FIDO_ERR_NONE;
}

/* --- The FIDO service's context ------------------------------------------ */

/*
 * Kept as no-argument calls because every existing caller, the conformance
 * corpus and the fuzz driver address the FIDO service and nothing else. A
 * second service uses the ble_fido_ctx_* API directly.
 */

static uint8_t        _fido_msg[BLE_FIDO_MAX_MSG];
static ble_fido_ctx_t _fido_ctx;
static int            _fido_ctx_ready;

ble_fido_ctx_t *ble_fido_default_ctx(void)
{
    if (!_fido_ctx_ready) {
        _fido_ctx_ready = 1;
        ble_fido_ctx_init(&_fido_ctx, _fido_msg, (uint16_t)sizeof(_fido_msg), 0);
    }
    return &_fido_ctx;
}

void ble_fido_set_notify(ble_fido_notify_fn fn)
{
    ble_fido_ctx_set_notify(ble_fido_default_ctx(), fn);
}

void ble_fido_set_deliver(ble_fido_deliver_fn fn)
{
    ble_fido_ctx_set_deliver(ble_fido_default_ctx(), fn);
}

void ble_fido_reset(void) { ble_fido_ctx_reset(ble_fido_default_ctx()); }

int ble_fido_is_receiving(void)
{
    return ble_fido_ctx_is_receiving(ble_fido_default_ctx());
}

uint16_t ble_fido_control_point_length(void)
{
    return ble_fido_ctx_control_point_length(ble_fido_default_ctx());
}

void ble_fido_set_mtu(uint16_t att_mtu)
{
    ble_fido_ctx_set_mtu(ble_fido_default_ctx(), att_mtu);
}

int ble_fido_send_error(uint8_t err)
{
    return ble_fido_ctx_send_error(ble_fido_default_ctx(), err);
}

int ble_fido_send_keepalive(uint8_t status)
{
    return ble_fido_ctx_send_keepalive(ble_fido_default_ctx(), status);
}

int ble_fido_send_response(uint8_t cmd, const uint8_t *data, uint16_t len)
{
    return ble_fido_ctx_send_response(ble_fido_default_ctx(), cmd, data, len);
}

uint8_t ble_fido_rx_fragment(const uint8_t *frag, uint16_t len)
{
    return ble_fido_ctx_rx_fragment(ble_fido_default_ctx(), frag, len);
}
