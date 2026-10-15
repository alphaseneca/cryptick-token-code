#include "piv.h"
#include <string.h>

/* PIV Application AID (NIST SP 800-73-4) */
static const uint8_t PIV_AID[PIV_AID_LEN] = {
    0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00
};

static const piv_hal_t *_hal;

/* PIN verification is per-session: it dies with the card reset / deselect. */
static int _pin_verified;

/*
 * Pending response for GET RESPONSE chaining.
 *
 * A PIV certificate is comfortably larger than the 256 bytes a short APDU can
 * return, so every real client reads one across several GET RESPONSEs. Without
 * this, GET DATA for a certificate simply cannot answer and login never gets
 * off the ground.
 *
 * `data` points either into HAL-owned storage (certificates, which we must not
 * copy — they are up to a couple of KB) or into `_scratch` for responses we
 * generate ourselves.
 */
/*
 * ISO 7816-4 command chaining (CLA bit 0x10).
 *
 * Without it a certificate cannot be written at all: 700 bytes of DER needs a
 * 716-byte PUT DATA body and Lc stops at 255. The applet rejected the chaining
 * class outright, which made provisioning -- and therefore login -- unreachable
 * however complete the rest of it was.
 */
static uint8_t _chain[PIV_MAX_CHAIN];
static size_t  _chain_len;
static int     _chain_active;
static uint8_t _chain_ins, _chain_p1, _chain_p2;

static const uint8_t *_pending;
static size_t         _pending_len;
static size_t         _pending_off;
static uint8_t        _scratch[PIV_SCRATCH_LEN];

/* --- Small helpers -------------------------------------------------------- */

static int put_sw(uint8_t *out, size_t out_max, uint16_t sw)
{
    if (out_max < 2)
        return -1;
    out[0] = (uint8_t)(sw >> 8);
    out[1] = (uint8_t)(sw & 0xFF);
    return 2;
}

static void pending_clear(void)
{
    _pending = NULL;
    _pending_len = 0;
    _pending_off = 0;
}

/**
 * Emit up to `le` bytes of the pending response, leaving the rest for GET
 * RESPONSE. SW is 9000 when nothing remains, else 61xx with the count still
 * outstanding (0x61 0x00 conventionally meaning "256 or more").
 */
static int emit_pending(uint8_t *out, size_t out_max, size_t le)
{
    size_t remaining = _pending_len - _pending_off;
    size_t chunk = remaining < le ? remaining : le;

    if (out_max < chunk + 2)
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);

    if (chunk)
        memcpy(out, _pending + _pending_off, chunk);
    _pending_off += chunk;

    remaining = _pending_len - _pending_off;
    if (remaining == 0) {
        pending_clear();
        return (int)chunk + put_sw(out + chunk, out_max - chunk, PIV_SW_OK);
    }
    return (int)chunk + put_sw(out + chunk, out_max - chunk,
                               (uint16_t)(0x6100 | (remaining > 255 ? 0 : remaining)));
}

/** Start a chained response from a buffer the caller guarantees stays valid. */
static int respond(const uint8_t *data, size_t len, size_t le,
                   uint8_t *out, size_t out_max)
{
    _pending = data;
    _pending_len = len;
    _pending_off = 0;
    if (le == 0)
        le = 256;
    return emit_pending(out, out_max, le);
}

/* --- BER-TLV -------------------------------------------------------------- */

/** Write a BER length. Returns bytes written, or 0 if it does not fit. */
static size_t tlv_put_len(uint8_t *out, size_t out_max, size_t len)
{
    if (len < 0x80) {
        if (out_max < 1) return 0;
        out[0] = (uint8_t)len;
        return 1;
    }
    if (len <= 0xFF) {
        if (out_max < 2) return 0;
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    }
    if (out_max < 3) return 0;
    out[0] = 0x82;
    out[1] = (uint8_t)(len >> 8);
    out[2] = (uint8_t)(len & 0xFF);
    return 3;
}

/**
 * Read a BER length. Advances *off past it. Returns 1 on success.
 * Rejects indefinite length and anything wider than two bytes: neither occurs
 * in PIV, and accepting them only widens the parser's attack surface.
 */
static int tlv_get_len(const uint8_t *buf, size_t buf_len, size_t *off, size_t *len)
{
    if (*off >= buf_len)
        return 0;
    uint8_t b = buf[(*off)++];
    if (b < 0x80) {
        *len = b;
        return 1;
    }
    if (b == 0x81) {
        if (*off + 1 > buf_len) return 0;
        *len = buf[(*off)++];
        return 1;
    }
    if (b == 0x82) {
        if (*off + 2 > buf_len) return 0;
        *len = (size_t)(buf[*off] << 8) | buf[*off + 1];
        *off += 2;
        return 1;
    }
    return 0;
}

/* --- SELECT --------------------------------------------------------------- */

/**
 * The application property template (tag 0x61) a conformant SELECT returns.
 * A bare 9000 is enough for OpenSC but CryptoTokenKit reads the AID back, so
 * the stub's old answer would have selected and then stalled.
 */
static int select_response(size_t le, uint8_t *out, size_t out_max)
{
    size_t n = 0;
    uint8_t *p = _scratch;

    p[n++] = 0x61;             /* application property template */
    size_t len_at = n++;       /* one-byte length, patched below */

    p[n++] = 0x4F;             /* application identifier */
    p[n++] = 0x09;
    memcpy(p + n, PIV_AID, 9); /* RID + PIX, without the version bytes */
    n += 9;

    p[n++] = 0x79;             /* coexistent tag allocation authority */
    p[n++] = 0x07;
    p[n++] = 0x4F;
    p[n++] = 0x05;
    memcpy(p + n, PIV_AID, 5); /* NIST RID */
    n += 5;

    p[len_at] = (uint8_t)(n - len_at - 1);
    return respond(_scratch, n, le, out, out_max);
}

/* --- GET DATA ------------------------------------------------------------- */

/**
 * GET DATA carries the object id in a 0x5C tag-list. PIV object ids are three
 * bytes (0x5FC1xx); the two one-byte ids are the discovery objects.
 */
static int parse_object_tag(const uint8_t *data, size_t len, uint32_t *tag)
{
    size_t off = 0;
    size_t tl;

    if (len < 2 || data[0] != 0x5C)
        return 0;
    off = 1;
    if (!tlv_get_len(data, len, &off, &tl))
        return 0;
    if (tl == 0 || tl > 3 || off + tl > len)
        return 0;

    *tag = 0;
    for (size_t i = 0; i < tl; i++)
        *tag = (*tag << 8) | data[off + i];
    return 1;
}

/* --- GENERAL AUTHENTICATE ------------------------------------------------- */

/**
 * The dynamic authentication template (0x7C) carries a challenge in 0x81; the
 * response goes back in 0x82. For ECDSA the "challenge" is already the hash to
 * sign, so the applet never hashes anything itself.
 */
static int general_authenticate(uint8_t alg, uint8_t slot,
                                const uint8_t *data, size_t len,
                                size_t le, uint8_t *out, size_t out_max)
{
    size_t off = 0, tmpl_len = 0;
    const uint8_t *challenge = NULL;
    size_t challenge_len = 0;

    /* P-256 only: the device has one curve and advertises nothing else. */
    if (alg != 0x11)
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);

    switch (slot) {
    case PIV_SLOT_AUTHENTICATION:
    case PIV_SLOT_SIGNATURE:
    case PIV_SLOT_KEY_MANAGEMENT:
    case PIV_SLOT_CARD_AUTH:
        break;
    default:
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
    }

    if (len < 2 || data[0] != 0x7C)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);
    off = 1;
    if (!tlv_get_len(data, len, &off, &tmpl_len) || off + tmpl_len > len)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    /* Walk the template for 0x81 (sign challenge) or 0x85 (ECDH peer pubkey). */
    size_t end = off + tmpl_len;
    const uint8_t *peer_pub = NULL;
    size_t peer_pub_len = 0;

    while (off + 1 < end) {
        uint8_t t = data[off++];
        size_t l;
        if (!tlv_get_len(data, end, &off, &l) || off + l > end)
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        if (t == 0x81) {
            challenge = data + off;
            challenge_len = l;
        } else if (t == 0x85) {
            peer_pub = data + off;
            peer_pub_len = l;
        }
        off += l;
    }

    if (!challenge && !peer_pub)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    /*
     * Card Authentication (9E) is the one slot defined to work without a PIN —
     * it exists for contactless building access. Every other slot is a login
     * credential and must not operate for an unauthenticated caller.
     */
    if (slot != PIV_SLOT_CARD_AUTH && !_pin_verified)
        return put_sw(out, out_max, PIV_SW_SECURITY_NOT_SATISFIED);

    /*
     * Touch policy. The PIN proves who is asking; presence proves someone is
     * physically here, which is what stops silent signing by malware that has
     * watched the PIN go past.
     */
    if (_hal->user_presence && !_hal->user_presence(slot))
        return put_sw(out, out_max, PIV_SW_SECURITY_NOT_SATISFIED);

    if (peer_pub) {
        /* ECDH Key Agreement (NIST SP 800-73-4) */
        if (peer_pub_len != PIV_PUBKEY_LEN || peer_pub[0] != 0x04)
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        if (!_hal || !_hal->ecdh_p256)
            return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);

        uint8_t shared[32];
        if (!_hal->ecdh_p256(slot, peer_pub, shared))
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);

        /* Wrap as 7C 22 82 20 <shared[32]>. */
        size_t n = 0;
        _scratch[n++] = 0x7C;
        _scratch[n++] = 0x22;
        _scratch[n++] = 0x82;
        _scratch[n++] = 0x20;
        memcpy(_scratch + n, shared, 32);
        n += 32;
        memset(shared, 0, sizeof(shared));
        return respond(_scratch, n, le, out, out_max);
    }

    /* ECDSA Signature (Tag 81) */
    if (challenge_len != 32)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    if (!_hal || !_hal->sign_p256)
        return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);

    uint8_t der[80];
    size_t der_len = sizeof(der);
    if (!_hal->sign_p256(slot, challenge, der, &der_len) || der_len == 0 ||
        der_len > sizeof(der))
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    /* Wrap as 7C L 82 L <sig>. */
    size_t n = 0;
    _scratch[n++] = 0x7C;
    size_t inner = 1 + (der_len < 0x80 ? 1 : 2) + der_len;
    size_t w = tlv_put_len(_scratch + n, sizeof(_scratch) - n, inner);
    if (!w) return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
    n += w;
    _scratch[n++] = 0x82;
    w = tlv_put_len(_scratch + n, sizeof(_scratch) - n, der_len);
    if (!w || n + w + der_len > sizeof(_scratch))
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
    n += w;
    memcpy(_scratch + n, der, der_len);
    n += der_len;

    return respond(_scratch, n, le, out, out_max);
}

/* --- Synthesised identity objects ----------------------------------------- */

/*
 * CCC and CHUID are the two objects a card is expected to carry from the
 * factory. A host that finds neither concludes there is no card worth talking
 * to: OpenSC reads the CCC during discovery and CryptoTokenKit wants a CHUID
 * before it will surface a token. Leaving them absent means GET DATA answers
 * 6A82 and login never starts, however good the rest of the applet is.
 *
 * They are synthesised on demand rather than written at first boot. Nothing is
 * spent in flash unless someone provisions a real one, and PUT DATA still
 * overrides — the stored object wins whenever it exists.
 */

/** Append tag ‖ one-byte length ‖ value. Returns 0 if it would not fit. */
static size_t tlv_append(uint8_t *buf, size_t off, size_t cap, uint8_t tag,
                         const uint8_t *val, size_t len)
{
    if (off + 2 + len > cap || len > 0x7F)
        return 0;
    buf[off++] = tag;
    buf[off++] = (uint8_t)len;
    if (len)
        memcpy(buf + off, val, len);
    return off + len;
}

/*
 * FASC-N placeholder for a non-federal issuer.
 *
 * A real FASC-N is a BCD-encoded federal credential number with parity bits.
 * This device issues no such credential, and the conventional answer for a
 * non-federal PIV-compatible token is a fixed placeholder — hosts key on the
 * GUID and the certificate, not on this. It is here because the field is
 * mandatory, not because it identifies anything.
 */
static const uint8_t kFascnPlaceholder[25] = {
    0xD4, 0xE7, 0x39, 0xDA, 0x50, 0x1C, 0xA0, 0x5C, 0x17, 0x94, 0x58, 0x21,
    0x08, 0x42, 0x10, 0xC3, 0xF5, 0x34, 0x10, 0xC3, 0xF5, 0x34, 0x10, 0xC3,
    0xF5,
};

/*
 * CHUID expiry. The field is mandatory and some hosts refuse an expired card,
 * but this device has no issuance lifecycle to express, so it is a fixed far
 * future date rather than a computed one — an expiry that quietly arrives
 * would take login down with it.
 */
static const uint8_t kChuidExpiry[8] = {'2', '0', '5', '0', '0', '1', '0', '1'};

/** Build the CHUID (SP 800-73-4 part 1, table 9) into `out`. */
static size_t build_chuid(uint8_t *out, size_t cap)
{
    uint8_t guid[PIV_GUID_LEN];
    uint8_t body[80];
    size_t n = 0;

    if (!_hal || !_hal->device_guid || !_hal->device_guid(guid))
        return 0;

    n = tlv_append(body, n, sizeof(body), 0x30, kFascnPlaceholder,
                   sizeof(kFascnPlaceholder));
    if (n) n = tlv_append(body, n, sizeof(body), 0x34, guid, sizeof(guid));
    if (n) n = tlv_append(body, n, sizeof(body), 0x35, kChuidExpiry,
                          sizeof(kChuidExpiry));
    /* Issuer signature: empty. This card is not part of a federal PKI, and an
     * empty 0x3E says so honestly rather than forging one. */
    if (n) n = tlv_append(body, n, sizeof(body), 0x3E, NULL, 0);
    if (n) n = tlv_append(body, n, sizeof(body), 0xFE, NULL, 0);
    if (!n)
        return 0;

    if (cap < n + 2)
        return 0;
    out[0] = 0x53;
    out[1] = (uint8_t)n;
    memcpy(out + 2, body, n);
    return n + 2;
}

/** Build the CCC (SP 800-73-4 part 1, table 8) into `out`. */
static size_t build_ccc(uint8_t *out, size_t cap)
{
    uint8_t guid[PIV_GUID_LEN];
    uint8_t body[80];
    uint8_t card_id[21];
    size_t n = 0;

    if (!_hal || !_hal->device_guid || !_hal->device_guid(guid))
        return 0;

    /* Card identifier: the GSC-RID, a 0xFF issuer byte, then device-unique
     * bytes taken from the GUID so the two objects agree on identity. */
    static const uint8_t kGscRid[] = {0xA0, 0x00, 0x00, 0x01, 0x16, 0xFF};
    memcpy(card_id, kGscRid, sizeof(kGscRid));
    memcpy(card_id + sizeof(kGscRid), guid, sizeof(card_id) - sizeof(kGscRid));

    n = tlv_append(body, n, sizeof(body), 0xF0, card_id, sizeof(card_id));
    {
        static const uint8_t v21 = 0x21;   /* container + grammar version */
        static const uint8_t pkcs15 = 0x00; /* no PKCS#15 */
        static const uint8_t model = 0x10;  /* registered data model */
        if (n) n = tlv_append(body, n, sizeof(body), 0xF1, &v21, 1);
        if (n) n = tlv_append(body, n, sizeof(body), 0xF2, &v21, 1);
        if (n) n = tlv_append(body, n, sizeof(body), 0xF3, NULL, 0);
        if (n) n = tlv_append(body, n, sizeof(body), 0xF4, &pkcs15, 1);
        if (n) n = tlv_append(body, n, sizeof(body), 0xF5, &model, 1);
    }
    /* The remaining containers are defined but unused on this card. They are
     * emitted empty rather than omitted: a host walking the table expects to
     * find them, and an absent tag is not the same as an empty one. */
    for (uint8_t tag = 0; n && tag < 8; tag++) {
        static const uint8_t kEmpty[] = {0xF6, 0xF7, 0xFA, 0xFB,
                                         0xFC, 0xFD, 0xFE, 0x00};
        if (kEmpty[tag] == 0x00)
            break;
        n = tlv_append(body, n, sizeof(body), kEmpty[tag], NULL, 0);
    }
    if (!n)
        return 0;

    if (cap < n + 2)
        return 0;
    out[0] = 0x53;
    out[1] = (uint8_t)n;
    memcpy(out + 2, body, n);
    return n + 2;
}

/**
 * Build a synthesised object into `_scratch`, or 0 if this tag has none.
 * A stored object always wins; this is only reached when none exists.
 */
static size_t synthesize_object(uint32_t tag)
{
    switch (tag) {
    case PIV_OBJ_CHUID:
        return build_chuid(_scratch, sizeof(_scratch));
    case PIV_OBJ_CCC:
        return build_ccc(_scratch, sizeof(_scratch));
    default:
        return 0;
    }
}

/* --- GENERATE ASYMMETRIC KEY PAIR ----------------------------------------- */

/**
 * Roll a slot key and hand back the public half, so a certificate can be
 * issued against it.
 *
 * Real PIV gates this behind the card management key (9B) via a mutual
 * authenticate. This device has no 9B key, so the gate is a verified PIN plus
 * a fingerprint instead. That is a deliberate substitution, not an oversight:
 * the operation destroys the usability of any certificate already issued for
 * the slot, so it must not be reachable by an unauthenticated caller.
 */
static int generate_keypair(uint8_t p1, uint8_t slot,
                            const uint8_t *data, size_t len,
                            size_t le, uint8_t *out, size_t out_max)
{
    if (p1 != 0x00)
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);

    switch (slot) {
    case PIV_SLOT_AUTHENTICATION:
    case PIV_SLOT_SIGNATURE:
    case PIV_SLOT_KEY_MANAGEMENT:
    case PIV_SLOT_CARD_AUTH:
        break;
    default:
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
    }

    /* Control reference template: AC L 80 01 <alg>. P-256 only. */
    if (!data || len < 5 || data[0] != 0xAC)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);
    {
        size_t off = 1, tl;
        if (!tlv_get_len(data, len, &off, &tl) || off + tl > len)
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        size_t end = off + tl;
        int alg_seen = 0;
        while (off + 1 < end) {
            uint8_t t = data[off++];
            size_t l;
            if (!tlv_get_len(data, end, &off, &l) || off + l > end)
                return put_sw(out, out_max, PIV_SW_WRONG_DATA);
            if (t == 0x80) {
                if (l != 1 || data[off] != 0x11)
                    return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
                alg_seen = 1;
            }
            off += l;
        }
        if (!alg_seen)
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
    }

    if (!_pin_verified)
        return put_sw(out, out_max, PIV_SW_SECURITY_NOT_SATISFIED);
    if (!_hal || !_hal->key_generate || !_hal->public_key)
        return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);
    if (_hal->user_presence && !_hal->user_presence(slot))
        return put_sw(out, out_max, PIV_SW_SECURITY_NOT_SATISFIED);

    if (!_hal->key_generate(slot))
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    uint8_t pub[PIV_PUBKEY_LEN];
    if (!_hal->public_key(slot, pub))
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    /* 7F49 L 86 L <point> */
    size_t n = 0;
    _scratch[n++] = 0x7F;
    _scratch[n++] = 0x49;
    size_t inner = 2 + PIV_PUBKEY_LEN; /* 86 + one length byte + point */
    size_t w = tlv_put_len(_scratch + n, sizeof(_scratch) - n, inner);
    if (!w) return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
    n += w;
    _scratch[n++] = 0x86;
    _scratch[n++] = PIV_PUBKEY_LEN;
    if (n + PIV_PUBKEY_LEN > sizeof(_scratch))
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
    memcpy(_scratch + n, pub, PIV_PUBKEY_LEN);
    n += PIV_PUBKEY_LEN;

    return respond(_scratch, n, le, out, out_max);
}

/* --- VERIFY --------------------------------------------------------------- */

/** Strip padding from a PIN block; handles 0xFF padding, 0x00 padding, or raw unpadded PIN. */
static size_t pin_block_len(const uint8_t *block, size_t lc)
{
    if (!block || lc < PIV_PIN_MIN_LEN)
        return 0;

    size_t n = 0;
    while (n < lc && n < PIV_PIN_BLOCK_LEN && block[n] != 0xFF && block[n] != 0x00)
        n++;

    return (n >= PIV_PIN_MIN_LEN && n <= PIV_PIN_MAX_LEN) ? n : 0;
}

static int verify(uint8_t p1, uint8_t p2, const uint8_t *data, size_t lc,
                  uint8_t *out, size_t out_max)
{
    /* 0x80 is the application PIN; 0x00/0x81 (global, PUK) are not supported. */
    if (p2 != 0x80)
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);

    if (!_hal || !_hal->pin_check || !_hal->pin_retries_get)
        return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);

    int retries = _hal->pin_retries_get();

    /* P1=0xFF resets the verification state without presenting a PIN. */
    if (p1 == 0xFF) {
        if (lc != 0)
            return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
        _pin_verified = 0;
        return put_sw(out, out_max, PIV_SW_OK);
    }
    if (p1 != 0x00)
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);

    /*
     * Empty body is the standard way to ask "how many tries do I have left"
     * without spending one. Clients do this before prompting the user.
     */
    if (lc == 0) {
        if (retries <= 0)
            return put_sw(out, out_max, PIV_SW_AUTH_BLOCKED);
        if (_pin_verified)
            return put_sw(out, out_max, PIV_SW_OK);
        return put_sw(out, out_max, PIV_SW_VERIFY_FAILED(retries));
    }

    if (retries <= 0)
        return put_sw(out, out_max, PIV_SW_AUTH_BLOCKED);

    if (lc < PIV_PIN_MIN_LEN || lc > PIV_PIN_BLOCK_LEN)
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);

    size_t pin_len = pin_block_len(data, lc);
    if (pin_len == 0)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    if (_hal->pin_check(data, pin_len)) {
        _pin_verified = 1;
        if (_hal->pin_retries_set)
            _hal->pin_retries_set(PIV_PIN_MAX_RETRIES);
        return put_sw(out, out_max, PIV_SW_OK);
    }

    /*
     * A wrong PIN clears any earlier verification. Otherwise a caller who
     * authenticated once could keep signing while guessing, and the counter
     * would be the only thing moving.
     */
    _pin_verified = 0;
    retries--;
    if (_hal->pin_retries_set)
        _hal->pin_retries_set(retries);
    if (retries <= 0)
        return put_sw(out, out_max, PIV_SW_AUTH_BLOCKED);
    return put_sw(out, out_max, PIV_SW_VERIFY_FAILED(retries));
}

/* --- CHANGE REFERENCE DATA ------------------------------------------------ */

/**
 * Change the application PIN.
 *
 * Without this the device ships on the SP 800-73 default and there is no way
 * off it, which makes the PIN decorative. The old PIN is presented alongside
 * the new one, so a wrong attempt spends a retry exactly like VERIFY.
 */
static int change_reference(uint8_t p1, uint8_t p2,
                            const uint8_t *data, size_t lc,
                            uint8_t *out, size_t out_max)
{
    if (p1 != 0x00 || p2 != 0x80)
        return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
    if (!_hal || !_hal->pin_check || !_hal->pin_set || !_hal->pin_retries_get)
        return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);

    int retries = _hal->pin_retries_get();
    if (retries <= 0)
        return put_sw(out, out_max, PIV_SW_AUTH_BLOCKED);

    /* Old block ‖ new block, 8 bytes each. */
    if (!data || lc != 2 * PIV_PIN_BLOCK_LEN)
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);

    size_t old_len = pin_block_len(data, PIV_PIN_BLOCK_LEN);
    size_t new_len = pin_block_len(data + PIV_PIN_BLOCK_LEN, PIV_PIN_BLOCK_LEN);
    if (old_len == 0 || new_len == 0)
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    if (!_hal->pin_check(data, old_len)) {
        /*
         * A wrong current PIN costs a retry and drops the session, the same as
         * VERIFY — otherwise this instruction is a counter-free oracle for
         * guessing the PIN.
         */
        _pin_verified = 0;
        retries--;
        if (_hal->pin_retries_set)
            _hal->pin_retries_set(retries);
        if (retries <= 0)
            return put_sw(out, out_max, PIV_SW_AUTH_BLOCKED);
        return put_sw(out, out_max, PIV_SW_VERIFY_FAILED(retries));
    }

    if (!_hal->pin_set(data + PIV_PIN_BLOCK_LEN, new_len))
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);

    _pin_verified = 1;
    if (_hal->pin_retries_set)
        _hal->pin_retries_set(PIV_PIN_MAX_RETRIES);
    return put_sw(out, out_max, PIV_SW_OK);
}

/* --- Entry point ---------------------------------------------------------- */

void piv_init(const piv_hal_t *hal)
{
    _hal = hal;
    piv_reset();
}

static void chain_clear(void)
{
    _chain_len = 0;
    _chain_active = 0;
    _chain_ins = _chain_p1 = _chain_p2 = 0;
}

void piv_reset(void)
{
    _pin_verified = 0;
    pending_clear();
    chain_clear();
}

int piv_pin_is_verified(void) { return _pin_verified; }

int piv_handle_apdu(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t out_max)
{
    if (!cmd || !out || out_max < 2)
        return -1;
    if (cmd_len < 4)
        return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);

    uint8_t cla = cmd[0];
    uint8_t ins = cmd[1];
    uint8_t p1 = cmd[2];
    uint8_t p2 = cmd[3];

    /*
     * Class 0x00, or 0x10 for a command chain. Secure messaging (0x0C) and
     * logical channels (0x03) are not implemented, and masking those bits off
     * would misread the APDU rather than refuse it — a chained command's
     * body is not a whole body.
     */
    if (cla != 0x00 && cla != 0x10)
        return put_sw(out, out_max, PIV_SW_CLA_UNSUPPORTED);

    /*
     * ISO 7816-4 short APDU cases. The ambiguity that matters is case 2: in a
     * 5-byte APDU the fifth byte is **Le**, not Lc. Reading it as Lc makes
     * every `00 C0 00 00 xx` GET RESPONSE look like a body truncated to
     * nothing, which breaks certificate chaining and therefore login.
     *
     *   4              case 1  no body, no response expected
     *   5              case 2  Le only        (0 means 256)
     *   5 + Lc         case 3  body, no Le
     *   5 + Lc + 1     case 4  body and Le    (0 means 256)
     */
    size_t lc = 0, le = 0;
    const uint8_t *data = NULL;

    if (cmd_len == 4) {
        le = 0;
    } else if (cmd_len == 5) {
        le = cmd[4] == 0 ? 256 : cmd[4];
    } else if (cmd[4] == 0 && cmd_len >= 7) {
        /* Extended length APDU (ISO 7816-4) */
        lc = ((size_t)cmd[5] << 8) | cmd[6];
        if (lc == 0) {
            /* Case 2E: Le only */
            if (cmd_len == 7) {
                le = 65536;
            } else {
                return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
            }
        } else {
            /* Case 3E / 4E */
            if (cmd_len < 7 + lc)
                return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
            data = cmd + 7;
            if (cmd_len == 7 + lc)
                le = 65536;
            else if (cmd_len == 7 + lc + 2)
                le = ((size_t)cmd[7 + lc] << 8) | cmd[7 + lc + 1];
            else
                return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
        }
    } else {
        /* Short APDU (ISO 7816-4) */
        lc = cmd[4];
        if (lc == 0 || cmd_len < 5 + lc)
            return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
        data = cmd + 5;
        if (cmd_len == 5 + lc)
            le = 256;
        else if (cmd_len == 5 + lc + 1)
            le = cmd[5 + lc] == 0 ? 256 : cmd[5 + lc];
        else
            return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
    }

    /*
     * Any command other than GET RESPONSE abandons a chained response. A
     * client that interleaves other commands has lost its place, and handing
     * it the tail of a stale certificate would be worse than an error.
     */
    if (ins != PIV_INS_GET_RESPONSE && _pending)
        pending_clear();

    /*
     * Command chaining. CLA bit 0x10 means "more blocks follow": accumulate
     * the body and answer 9000 without acting. The final block arrives with
     * CLA 0x00 and is processed as one whole command.
     *
     * A chain that changes INS/P1/P2 mid-way is abandoned rather than
     * stitched together — the blocks would not be one command, and silently
     * concatenating them would hand the applet a body its sender never wrote.
     */
    if (_chain_active &&
        (ins != _chain_ins || p1 != _chain_p1 || p2 != _chain_p2)) {
        chain_clear();
        return put_sw(out, out_max, PIV_SW_WRONG_DATA);
    }

    if (cla == 0x10) {
        if (lc == 0 || !data) {
            chain_clear();
            return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
        }
        if (_chain_len + lc > sizeof(_chain)) {
            chain_clear();
            return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
        }
        if (!_chain_active) {
            _chain_active = 1;
            _chain_ins = ins;
            _chain_p1 = p1;
            _chain_p2 = p2;
        }
        memcpy(_chain + _chain_len, data, lc);
        _chain_len += lc;
        return put_sw(out, out_max, PIV_SW_OK);
    }

    if (_chain_active) {
        /* Final block: append it and process the assembled command. */
        if (lc) {
            if (!data || _chain_len + lc > sizeof(_chain)) {
                chain_clear();
                return put_sw(out, out_max, PIV_SW_WRONG_LENGTH);
            }
            memcpy(_chain + _chain_len, data, lc);
            _chain_len += lc;
        }
        data = _chain;
        lc = _chain_len;
        _chain_active = 0;
        _chain_len = 0;
    }

    switch (ins) {
    case PIV_INS_SELECT: {
        if (p1 != 0x04 || p2 != 0x00)
            return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
        /*
         * Prefix match, not exact match. The trailing 01 00 is the PIV
         * application version, not part of the identity: real clients select
         * with the right-truncated 9-byte AID (SP 800-73), and P1=0x04 is
         * defined as a DF-name prefix match. Requiring all 11 bytes answered
         * 6A82 to those clients, which is invisible to the applet but fatal to
         * both the pam_pkcs11 and the CryptoTokenKit login paths.
         */
        if (lc < PIV_AID_MIN_LEN || lc > PIV_AID_LEN || !data ||
            memcmp(data, PIV_AID, lc) != 0)
            return put_sw(out, out_max, PIV_SW_NOT_FOUND);
        /* Selecting the application resets PIN state, as a card reset would. */
        piv_reset();
        return select_response(le, out, out_max);
    }

    case PIV_INS_GET_RESPONSE: {
        if (!_pending)
            return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);
        if (p1 != 0x00 || p2 != 0x00)
            return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
        return emit_pending(out, out_max, le ? le : 256);
    }

    case PIV_INS_GET_DATA: {
        uint32_t tag;
        const uint8_t *obj;
        size_t obj_len;

        if (p1 != 0x3F || p2 != 0xFF)
            return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
        if (!data || !parse_object_tag(data, lc, &tag))
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        if (_hal && _hal->get_object && _hal->get_object(tag, &obj, &obj_len) &&
            obj && obj_len)
            return respond(obj, obj_len, le, out, out_max);

        /* Nothing stored: CCC and CHUID are synthesised, everything else is
         * genuinely absent. */
        {
            size_t n = synthesize_object(tag);
            if (n)
                return respond(_scratch, n, le, out, out_max);
        }
        return put_sw(out, out_max, PIV_SW_NOT_FOUND);
    }

    case PIV_INS_PUT_DATA: {
        uint32_t tag;
        if (p1 != 0x3F || p2 != 0xFF)
            return put_sw(out, out_max, PIV_SW_WRONG_P1P2);
        /* Provisioning writes a credential, so it needs the PIN. */
        if (!_pin_verified)
            return put_sw(out, out_max, PIV_SW_SECURITY_NOT_SATISFIED);
        if (!data || !parse_object_tag(data, lc, &tag))
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        if (!_hal || !_hal->set_object)
            return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);
        {
            /*
             * Store the whole 0x53 container, wrapper included.
             *
             * GET DATA returns a stored object verbatim, and SP 800-73 defines
             * the response as the data object *with* its 0x53 tag -- which is
             * what the synthesised CCC and CHUID emit. Storing only the inner
             * value made a provisioned certificate come back as a bare 0x70
             * where a host expects 0x53 0x70, so provisioned and synthesised
             * objects disagreed on shape and only the certificate -- the one
             * object login needs -- was wrong.
             */
            size_t off = 1, tl;
            if (!tlv_get_len(data, lc, &off, &tl))
                return put_sw(out, out_max, PIV_SW_WRONG_DATA);
            off += tl;
            if (off + 1 >= lc || data[off] != 0x53)
                return put_sw(out, out_max, PIV_SW_WRONG_DATA);
            size_t container = off;
            off++;
            size_t vlen;
            if (!tlv_get_len(data, lc, &off, &vlen) || off + vlen > lc)
                return put_sw(out, out_max, PIV_SW_WRONG_DATA);
            if (!_hal->set_object(tag, data + container,
                                  (off + vlen) - container))
                return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        }
        return put_sw(out, out_max, PIV_SW_OK);
    }

    case PIV_INS_VERIFY:
        return verify(p1, p2, data, lc, out, out_max);

    case PIV_INS_CHANGE_REFERENCE:
        return change_reference(p1, p2, data, lc, out, out_max);

    case PIV_INS_GENERATE_KEYPAIR:
        return generate_keypair(p1, p2, data, lc, le, out, out_max);

    case PIV_INS_GENERAL_AUTHENTICATE:
        if (!data)
            return put_sw(out, out_max, PIV_SW_WRONG_DATA);
        return general_authenticate(p1, p2, data, lc, le, out, out_max);

    default:
        return put_sw(out, out_max, PIV_SW_INS_UNSUPPORTED);
    }
}
