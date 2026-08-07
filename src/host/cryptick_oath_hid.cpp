/**
 * Cryptick OATH over CTAPHID — YKOATH-inspired INS + TLV on HID body.
 * Transport is CTAPHID_CRYPTICK_OATH (0xE3), not CCID OATH class.
 */
#include "cryptick_oath_hid.h"
#include "totp_storage.h"
#include "totp.h"
#include "device.h"
#include <RTClib.h>
#include <string.h>
#include <vector>
#include <Arduino.h>

/* YKOATH instruction set (subset) + Cryptick extensions */
#define OATH_INS_PUT          0x01
#define OATH_INS_DELETE       0x02
#define OATH_INS_SET_TIME     0x04
#define OATH_INS_LIST         0xa1
#define OATH_INS_CALCULATE    0xa2
#define OATH_INS_PUT_OTPAUTH  0x40

/* TLV tags */
#define OATH_TAG_NAME         0x71
#define OATH_TAG_KEY          0x73
#define OATH_TAG_CHALLENGE    0x74
#define OATH_TAG_RESPONSE     0x75

/* ISO 7816-ish status */
#define SW_OK                 0x9000
#define SW_WRONG_DATA         0x6A80
#define SW_NOT_FOUND          0x6A82
#define SW_WRONG_LENGTH       0x6700
#define SW_INS_NOT_SUPPORTED  0x6D00
#define SW_CONDITIONS         0x6985
#define SW_NO_SPACE           0x6A84

#define OATH_MAX_NAME 64
#define OATH_MAX_SECRET 64
#define OATH_MAX_CREDS 32

static void write_sw(uint8_t *resp, uint16_t *rlen, uint16_t sw)
{
    resp[0] = (uint8_t)(sw >> 8);
    resp[1] = (uint8_t)(sw & 0xFF);
    *rlen = 2;
}

static void append_sw(uint8_t *resp, uint16_t *rlen, uint16_t sw, uint16_t max)
{
    if (*rlen + 2 > max) {
        write_sw(resp, rlen, 0x6F00);
        return;
    }
    resp[(*rlen)++] = (uint8_t)(sw >> 8);
    resp[(*rlen)++] = (uint8_t)(sw & 0xFF);
}

/** Find TLV tag; returns payload pointer or NULL. */
static const uint8_t *tlv_find(const uint8_t *data, uint16_t len, uint8_t tag,
                               uint8_t *out_len)
{
    uint16_t i = 0;
    while (i + 2 <= len) {
        uint8_t t = data[i++];
        uint8_t l = data[i++];
        if (i + l > len)
            return NULL;
        if (t == tag) {
            *out_len = l;
            return data + i;
        }
        i = (uint16_t)(i + l);
    }
    return NULL;
}

static int find_by_name(const std::vector<TOTPCredential> &creds, const char *name)
{
    for (size_t i = 0; i < creds.size(); i++) {
        String display = creds[i].issuer.length()
            ? (creds[i].issuer + ":" + creds[i].label)
            : creds[i].label;
        if (display == name || creds[i].label == name)
            return (int)i;
    }
    return -1;
}

static String url_decode(const String &s)
{
    String out;
    for (int i = 0; i < (int)s.length(); i++) {
        char c = s[i];
        if (c == '+')
            out += ' ';
        else if (c == '%' && i + 2 < (int)s.length()) {
            auto hex = [](char ch) -> int {
                if (ch >= '0' && ch <= '9') return ch - '0';
                if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
                if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
                return 0;
            };
            out += (char)((hex(s[i + 1]) << 4) | hex(s[i + 2]));
            i += 2;
        } else
            out += c;
    }
    return out;
}

static bool parse_otpauth(const char *uri, size_t uri_len, TOTPCredential &out)
{
    String u;
    for (size_t i = 0; i < uri_len; i++)
        u += uri[i];
    u.trim();
    if (u.startsWith("otp://"))
        u = "otpauth://" + u.substring(6);
    if (!u.startsWith("otpauth://totp/"))
        return false;
    int pathStart = 14;
    int q = u.indexOf('?');
    String path = (q >= 0) ? u.substring(pathStart, q) : u.substring(pathStart);
    String query = (q >= 0) ? u.substring(q + 1) : "";
    path = url_decode(path);
    int colon = path.indexOf(':');
    if (colon >= 0) {
        out.issuer = path.substring(0, colon);
        out.label = path.substring(colon + 1);
    } else {
        out.issuer = "";
        out.label = path;
    }
    out.secret = "";
    out.digits = 6;
    out.period = 30;
    out.algorithm = "SHA1";
    for (int i = 0; i < (int)query.length();) {
        int amp = query.indexOf('&', i);
        String pair = (amp >= 0) ? query.substring(i, amp) : query.substring(i);
        i = (amp >= 0) ? amp + 1 : query.length();
        int eq = pair.indexOf('=');
        if (eq < 0) continue;
        String key = pair.substring(0, eq);
        String val = url_decode(pair.substring(eq + 1));
        if (key == "secret") out.secret = val;
        else if (key == "issuer" && val.length()) out.issuer = val;
        else if (key == "digits") out.digits = val.toInt() ? val.toInt() : 6;
        else if (key == "period") out.period = val.toInt() ? val.toInt() : 30;
        else if (key == "algorithm" && val.length()) out.algorithm = val;
    }
    out.algorithm.toUpperCase();
    if (out.algorithm != "SHA1")
        return false;
    if (out.digits != 6 || out.period != 30)
        return false;
    uint8_t tmp[64];
    return totp_base32_decode(out.secret.c_str(), tmp, sizeof(tmp)) > 0;
}

/** Binary secret → base32 for storage (uppercase, no padding). */
static String secret_to_base32(const uint8_t *sec, uint8_t seclen)
{
    static const char *alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    String out;
    int buffer = 0, bitsLeft = 0;
    for (uint8_t i = 0; i < seclen; i++) {
        buffer = (buffer << 8) | sec[i];
        bitsLeft += 8;
        while (bitsLeft >= 5) {
            out += alphabet[(buffer >> (bitsLeft - 5)) & 0x1F];
            bitsLeft -= 5;
        }
    }
    if (bitsLeft > 0)
        out += alphabet[(buffer << (5 - bitsLeft)) & 0x1F];
    return out;
}

extern std::vector<TOTPCredential> credentials;
extern RTC_DS3231 rtc;

int cryptick_oath_hid_handle(const uint8_t *req, uint16_t req_len,
                             uint8_t *resp, uint16_t *resp_len)
{
    const uint16_t max_resp = 7600;
    *resp_len = 0;
    if (!req || !resp || !resp_len)
        return -1;
    if (req_len < 4) {
        write_sw(resp, resp_len, SW_WRONG_LENGTH);
        return 0;
    }

    uint8_t cla = req[0];
    uint8_t ins = req[1];
    /* P1, P2 reserved; MVP ignores values if zero-ish */
    (void)req[2];
    (void)req[3];
    if (cla != 0x00) {
        write_sw(resp, resp_len, SW_INS_NOT_SUPPORTED);
        return 0;
    }

    uint16_t data_off = 4;
    uint16_t data_len = 0;
    if (req_len >= 5) {
        data_len = req[4];
        data_off = 5;
        if ((uint16_t)(data_off + data_len) > req_len) {
            write_sw(resp, resp_len, SW_WRONG_LENGTH);
            return 0;
        }
    }
    const uint8_t *tlv = req + data_off;

    switch (ins) {
    case OATH_INS_PUT: {
        uint8_t nlen = 0, klen = 0;
        const uint8_t *name = tlv_find(tlv, data_len, OATH_TAG_NAME, &nlen);
        const uint8_t *key = tlv_find(tlv, data_len, OATH_TAG_KEY, &klen);
        if (!name || nlen == 0 || nlen > OATH_MAX_NAME || !key || klen < 3) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        /* key: type|algo (0x21 = TOTP|SHA1), digits, secret… */
        uint8_t type_algo = key[0];
        uint8_t digits = key[1];
        if ((type_algo & 0x0F) != 0x01 || (type_algo & 0xF0) != 0x20) {
            write_sw(resp, resp_len, SW_CONDITIONS); /* SHA1 TOTP only */
            return 0;
        }
        if (digits != 6) {
            write_sw(resp, resp_len, SW_CONDITIONS);
            return 0;
        }
        uint8_t seclen = (uint8_t)(klen - 2);
        if (seclen == 0 || seclen > OATH_MAX_SECRET) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        char namebuf[OATH_MAX_NAME + 1];
        memcpy(namebuf, name, nlen);
        namebuf[nlen] = 0;

        TOTPCredential cred;
        cred.algorithm = "SHA1";
        cred.digits = 6;
        cred.period = 30;
        cred.secret = secret_to_base32(key + 2, seclen);
        /* Name may be "issuer:label" */
        const char *colon = strchr(namebuf, ':');
        if (colon) {
            cred.issuer = String(namebuf).substring(0, (int)(colon - namebuf));
            cred.label = String(colon + 1);
        } else {
            cred.issuer = "";
            cred.label = namebuf;
        }

        int idx = find_by_name(credentials, namebuf);
        if (idx >= 0)
            credentials[idx] = cred;
        else {
            if (credentials.size() >= OATH_MAX_CREDS) {
                write_sw(resp, resp_len, SW_NO_SPACE);
                return 0;
            }
            credentials.push_back(cred);
        }
        saveConfiguration(credentials);
        write_sw(resp, resp_len, SW_OK);
        return 0;
    }

    case OATH_INS_DELETE: {
        uint8_t nlen = 0;
        const uint8_t *name = tlv_find(tlv, data_len, OATH_TAG_NAME, &nlen);
        if (!name || nlen == 0 || nlen > OATH_MAX_NAME) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        char namebuf[OATH_MAX_NAME + 1];
        memcpy(namebuf, name, nlen);
        namebuf[nlen] = 0;
        int idx = find_by_name(credentials, namebuf);
        if (idx < 0) {
            write_sw(resp, resp_len, SW_NOT_FOUND);
            return 0;
        }
        credentials.erase(credentials.begin() + idx);
        saveConfiguration(credentials);
        write_sw(resp, resp_len, SW_OK);
        return 0;
    }

    case OATH_INS_LIST: {
        uint16_t off = 0;
        for (size_t i = 0; i < credentials.size(); i++) {
            String display = credentials[i].issuer.length()
                ? (credentials[i].issuer + ":" + credentials[i].label)
                : credentials[i].label;
            uint8_t nlen = (uint8_t)constrain((int)display.length(), 0, OATH_MAX_NAME);
            if (off + 3 + nlen + 2 > max_resp)
                break;
            resp[off++] = OATH_TAG_NAME;
            resp[off++] = (uint8_t)(nlen + 1);
            resp[off++] = 0x21; /* TOTP SHA1 name list byte */
            memcpy(resp + off, display.c_str(), nlen);
            off = (uint16_t)(off + nlen);
        }
        *resp_len = off;
        append_sw(resp, resp_len, SW_OK, max_resp);
        return 0;
    }

    case OATH_INS_CALCULATE: {
        uint8_t nlen = 0, clen = 0;
        const uint8_t *name = tlv_find(tlv, data_len, OATH_TAG_NAME, &nlen);
        const uint8_t *chal = tlv_find(tlv, data_len, OATH_TAG_CHALLENGE, &clen);
        if (!name || nlen == 0 || !chal || clen != 8) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        char namebuf[OATH_MAX_NAME + 1];
        memcpy(namebuf, name, nlen);
        namebuf[nlen] = 0;
        int idx = find_by_name(credentials, namebuf);
        if (idx < 0) {
            write_sw(resp, resp_len, SW_NOT_FOUND);
            return 0;
        }
        /* Challenge is time counter BE; convert to unix-ish via * period for our gen */
        uint64_t counter = 0;
        for (int i = 0; i < 8; i++)
            counter = (counter << 8) | chal[i];
        uint32_t ts = (uint32_t)(counter * (uint64_t)credentials[idx].period);
        String code = totp_generate(credentials[idx], ts);
        if (code.length() < 6 || code == "Bad Key") {
            write_sw(resp, resp_len, SW_CONDITIONS);
            return 0;
        }
        /* Response TLV: digits + 4-byte truncated code (or ASCII); YKOATH uses
         * 0x75 len digits | fullcode. Use digits + uint32 BE. */
        uint32_t code_n = (uint32_t)code.toInt();
        resp[0] = OATH_TAG_RESPONSE;
        resp[1] = 5;
        resp[2] = 6; /* digits */
        resp[3] = (uint8_t)(code_n >> 24);
        resp[4] = (uint8_t)(code_n >> 16);
        resp[5] = (uint8_t)(code_n >> 8);
        resp[6] = (uint8_t)(code_n);
        *resp_len = 7;
        append_sw(resp, resp_len, SW_OK, max_resp);
        return 0;
    }

    case OATH_INS_SET_TIME: {
        if (data_len < 4) {
            write_sw(resp, resp_len, SW_WRONG_LENGTH);
            return 0;
        }
        uint32_t ts = ((uint32_t)tlv[0] << 24) | ((uint32_t)tlv[1] << 16) |
                      ((uint32_t)tlv[2] << 8) | tlv[3];
        if (ts == 0) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        DateTime dt(ts);
        rtc.adjust(dt);
        write_sw(resp, resp_len, SW_OK);
        return 0;
    }

    case OATH_INS_PUT_OTPAUTH: {
        if (data_len == 0 || data_len > 400) {
            write_sw(resp, resp_len, SW_WRONG_LENGTH);
            return 0;
        }
        TOTPCredential cred;
        if (!parse_otpauth((const char *)tlv, data_len, cred)) {
            write_sw(resp, resp_len, SW_WRONG_DATA);
            return 0;
        }
        String display = cred.issuer.length() ? (cred.issuer + ":" + cred.label) : cred.label;
        int idx = find_by_name(credentials, display.c_str());
        if (idx >= 0)
            credentials[idx] = cred;
        else {
            if (credentials.size() >= OATH_MAX_CREDS) {
                write_sw(resp, resp_len, SW_NO_SPACE);
                return 0;
            }
            credentials.push_back(cred);
        }
        saveConfiguration(credentials);
        write_sw(resp, resp_len, SW_OK);
        return 0;
    }

    default:
        write_sw(resp, resp_len, SW_INS_NOT_SUPPORTED);
        return 0;
    }
}
