#include "totp.h"
#include <string.h>
#include <ctype.h>

/* ════════════════════════════════════════════════════════════════════════
 * Self-contained SHA-1 (FIPS 180-4) + HMAC-SHA1 (RFC 2104)
 * No mbedtls, no external deps — works on any platform.
 * ════════════════════════════════════════════════════════════════════════ */

static uint32_t _rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

typedef struct
{
    uint32_t h[5];
    uint64_t totalLen;
    uint8_t buf[64];
    int bufLen;
} sha1_ctx;

static void sha1_init(sha1_ctx *c)
{
    c->h[0] = 0x67452301;
    c->h[1] = 0xEFCDAB89;
    c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476;
    c->h[4] = 0xC3D2E1F0;
    c->totalLen = 0;
    c->bufLen = 0;
}

static void sha1_process(sha1_ctx *c, const uint8_t *blk)
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)blk[i * 4] << 24) | ((uint32_t)blk[i * 4 + 1] << 16) |
               ((uint32_t)blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
    for (int i = 16; i < 80; i++)
        w[i] = _rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++)
    {
        uint32_t f, k;
        if (i < 20)      { f = (b & cc) | ((~b) & d);        k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;                   k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else              { f = b ^ cc ^ d;                   k = 0xCA62C1D6; }
        uint32_t t = _rotl(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = _rotl(b, 30); b = a; a = t;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void sha1_update(sha1_ctx *c, const uint8_t *data, int len)
{
    c->totalLen += len;
    while (len > 0)
    {
        int space = 64 - c->bufLen;
        int take = (len < space) ? len : space;
        memcpy(c->buf + c->bufLen, data, take);
        c->bufLen += take;
        data += take;
        len -= take;
        if (c->bufLen == 64)
        {
            sha1_process(c, c->buf);
            c->bufLen = 0;
        }
    }
}

static void sha1_final(sha1_ctx *c, uint8_t digest[20])
{
    uint64_t bits = c->totalLen * 8;
    uint8_t pad = 0x80;
    sha1_update(c, &pad, 1);
    pad = 0;
    while (c->bufLen != 56)
        sha1_update(c, &pad, 1);
    uint8_t lenBytes[8];
    for (int i = 7; i >= 0; i--)
    {
        lenBytes[i] = (uint8_t)(bits & 0xFF);
        bits >>= 8;
    }
    sha1_update(c, lenBytes, 8);
    for (int i = 0; i < 5; i++)
    {
        digest[i * 4]     = (uint8_t)(c->h[i] >> 24);
        digest[i * 4 + 1] = (uint8_t)(c->h[i] >> 16);
        digest[i * 4 + 2] = (uint8_t)(c->h[i] >> 8);
        digest[i * 4 + 3] = (uint8_t)(c->h[i]);
    }
}

/** HMAC-SHA1 (RFC 2104) — fully self-contained. */
static void hmac_sha1(const uint8_t *key, int keyLen,
                      const uint8_t *msg, int msgLen,
                      uint8_t out[20])
{
    uint8_t k[64];
    memset(k, 0, 64);

    if (keyLen > 64)
    {
        sha1_ctx kc;
        sha1_init(&kc);
        sha1_update(&kc, key, keyLen);
        sha1_final(&kc, k);
    }
    else
    {
        memcpy(k, key, keyLen);
    }

    uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; i++)
    {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5C;
    }

    /* inner = SHA1(ipad || msg) */
    uint8_t inner[20];
    sha1_ctx c;
    sha1_init(&c);
    sha1_update(&c, ipad, 64);
    sha1_update(&c, msg, msgLen);
    sha1_final(&c, inner);

    /* result = SHA1(opad || inner) */
    sha1_init(&c);
    sha1_update(&c, opad, 64);
    sha1_update(&c, inner, 20);
    sha1_final(&c, out);
}

/* ════════════════════════════════════════════════════════════════════════
 * TOTP (RFC 6238 / RFC 4226)
 * ════════════════════════════════════════════════════════════════════════ */

int totp_base32_decode(const char *encoded, uint8_t *result, int bufSize)
{
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int buffer = 0, bitsLeft = 0, count = 0;

    for (const char *ptr = encoded; *ptr && count < bufSize; ++ptr)
    {
        char ch = *ptr;
        if (isspace(ch) || ch == '-')
            continue;
            
        ch = toupper(ch);
        if (ch == '=')
            break;

        const char *p = strchr(base32_chars, ch);
        if (!p)
            continue;

        buffer <<= 5;
        buffer |= (p - base32_chars);
        bitsLeft += 5;

        if (bitsLeft >= 8)
        {
            result[count++] = (uint8_t)((buffer >> (bitsLeft - 8)) & 0xFF);
            bitsLeft -= 8;
        }
    }
    return count;
}

String totp_generate(const TOTPCredential &cred, uint32_t timestamp)
{
    if (timestamp == 0)
        return "RTC Err";

    uint8_t key[64];
    int keyLen = totp_base32_decode(cred.secret.c_str(), key, sizeof(key));
    if (keyLen <= 0)
        return "Bad Key";

    int period = cred.period > 0 ? cred.period : 30;
    int digits = (cred.digits >= 6 && cred.digits <= 8) ? cred.digits : 6;

    /* Counter = floor(timestamp / period), big-endian 8 bytes (RFC 6238 §4) */
    uint64_t counter = (uint64_t)timestamp / (uint64_t)period;
    uint8_t msg[8];
    for (int i = 7; i >= 0; i--)
    {
        msg[i] = (uint8_t)(counter & 0xFF);
        counter >>= 8;
    }

    /* HMAC-SHA1 */
    uint8_t hash[20];
    hmac_sha1(key, keyLen, msg, 8, hash);

    /* Dynamic truncation (RFC 4226 §5.3) */
    int offset = hash[19] & 0x0F;
    uint32_t code = ((uint32_t)(hash[offset]     & 0x7F) << 24)
                  | ((uint32_t)(hash[offset + 1]       ) << 16)
                  | ((uint32_t)(hash[offset + 2]       ) <<  8)
                  | ((uint32_t)(hash[offset + 3]       )      );

    /* Modulo 10^digits */
    static const uint32_t pow10[] = { 1, 10, 100, 1000, 10000, 100000,
                                      1000000, 10000000, 100000000 };
    code %= pow10[digits];

    /* Format with leading zeros */
    char buf[12];
    switch (digits)
    {
    case 7:  snprintf(buf, sizeof(buf), "%07u", (unsigned)code); break;
    case 8:  snprintf(buf, sizeof(buf), "%08u", (unsigned)code); break;
    default: snprintf(buf, sizeof(buf), "%06u", (unsigned)code); break;
    }
    return String(buf);
}
