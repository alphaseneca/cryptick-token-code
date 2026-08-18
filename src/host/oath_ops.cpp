/**
 * Shared OATH/TOTP ops for HID + CDC (UV, otpauth, store).
 */
#include "oath_ops.h"
#include "totp_storage.h"
#include "auth_system.h"
#include "fp_system.h"
#include "nav_system.h"
#include <board_config.h>
#include <cryptick_log.h>
#include "ctaphid.h"
#include "device.h"
#include <string.h>

extern "C" int ctap_user_presence_test(uint32_t delay_ms);

String oath_display_name(const TOTPCredential &cred)
{
    if (cred.issuer.length())
        return cred.issuer + ":" + cred.label;
    return cred.label;
}

int oath_find_by_name(const std::vector<TOTPCredential> &creds, const char *name)
{
    if (!name || !name[0])
        return -1;
    for (size_t i = 0; i < creds.size(); i++) {
        String display = oath_display_name(creds[i]);
        if (display == name || creds[i].label == name)
            return (int)i;
    }
    return -1;
}

bool oath_ensure_uv(const char *prompt)
{
#if !CRYPTICK_OATH_REQUIRE_FP
    (void)prompt;
    CLOG_T("OATH", "UV skipped (REQUIRE_FP=0)");
    return true;
#else
    if (!fp_system_ready() || fp_system_template_count() == 0) {
        CLOG_D("OATH", "UV bootstrap (no FP templates)");
        return true; /* no FP library yet — bootstrap */
    }

    if (auth_system_is_authenticated()) {
        CLOG_D("OATH", "UV satisfied (auth session)");
        auth_system_record_activity(millis());
        return true;
    }

    CLOG_I("OATH", "UV wait prompt=%s timeout_ms=%u",
           prompt ? prompt : "Confirm", (unsigned)CRYPTICK_OATH_UV_TIMEOUT_MS);

    /*
     * nav_system belongs to the Arduino loop. On the HID path we run on the
     * core-0 FIDO task, so we only publish the caption and the UP status and
     * let the loop's _fido_ui_request poll drive nav. On the CDC path we *are*
     * the loop and it is blocked inside the presence test below, so nothing
     * would drive nav unless we call it ourselves.
     */
    const bool drive_nav_directly = !device_on_fido_task();
    device_set_ui_label(prompt ? prompt : "Confirm");
    if (drive_nav_directly) {
        nav_system_set_fido_label(prompt ? prompt : "Confirm");
        nav_system_set_fido_ui(1);
    }

    device_set_status(CTAPHID_STATUS_UPNEEDED);
    int up = ctap_user_presence_test(CRYPTICK_OATH_UV_TIMEOUT_MS);
    device_set_status(CTAPHID_STATUS_IDLE);
    if (drive_nav_directly)
        nav_system_set_fido_ui(up == 1 ? 2 : 0);
    if (up == 1) {
        CLOG_I("OATH", "UV ok");
        auth_system_on_match();
        auth_system_record_activity(millis());
        return true;
    }
    CLOG_W("OATH", "UV fail/timeout up=%d", up);
    return false;
#endif
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

bool oath_parse_otpauth(const char *uri, size_t uri_len, TOTPCredential &out)
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
    if (out.label.length() == 0 && out.issuer.length() == 0)
        return false;
    uint8_t tmp[OATH_MAX_SECRET];
    return totp_base32_decode(out.secret.c_str(), tmp, sizeof(tmp)) > 0;
}

bool oath_parse_put_args(const String &args_in, TOTPCredential &out, const char **err)
{
    if (err)
        *err = nullptr;
    String args = args_in;
    args.trim();
    if (args.length() == 0) {
        if (err) *err = "missing args";
        return false;
    }

    String low = args;
    low.toLowerCase();
    if (low.startsWith("otpauth://") || low.startsWith("otp://")) {
        if (!oath_parse_otpauth(args.c_str(), (size_t)args.length(), out)) {
            if (err) *err = "bad otpauth (need totp SHA1 6d/30s + secret)";
            return false;
        }
        return true;
    }

    /* name <base32>  or  issuer:label <base32> */
    int sp = args.indexOf(' ');
    if (sp < 0) {
        if (err) *err = "usage: OATH PUT otpauth://… | name base32secret";
        return false;
    }
    String name = args.substring(0, sp);
    String rest = args.substring(sp + 1);
    rest.trim();
    if (rest.length() == 0) {
        if (err) *err = "missing base32 secret";
        return false;
    }
    /* optional trailing digits/period ignored if present for forward compat */
    int sp2 = rest.indexOf(' ');
    String secret = (sp2 >= 0) ? rest.substring(0, sp2) : rest;
    secret.trim();
    secret.toUpperCase();

    out.digits = 6;
    out.period = 30;
    out.algorithm = "SHA1";
    out.secret = secret;
    int colon = name.indexOf(':');
    if (colon >= 0) {
        out.issuer = name.substring(0, colon);
        out.label = name.substring(colon + 1);
    } else {
        out.issuer = "";
        out.label = name;
    }
    if (out.label.length() == 0) {
        if (err) *err = "empty name";
        return false;
    }
    uint8_t tmp[OATH_MAX_SECRET];
    if (totp_base32_decode(out.secret.c_str(), tmp, sizeof(tmp)) <= 0) {
        if (err) *err = "bad base32 secret";
        return false;
    }
    return true;
}

bool oath_put_credential(std::vector<TOTPCredential> &creds, const TOTPCredential &cred,
                         bool *replaced)
{
    if (replaced)
        *replaced = false;
    String display = oath_display_name(cred);
    int idx = oath_find_by_name(creds, display.c_str());
    if (idx >= 0) {
        creds[idx] = cred;
        if (replaced)
            *replaced = true;
    } else {
        if (creds.size() >= OATH_MAX_CREDS)
            return false;
        creds.push_back(cred);
    }
    saveConfiguration(creds);
    return true;
}

bool oath_delete_credential(std::vector<TOTPCredential> &creds, const char *name)
{
    int idx = oath_find_by_name(creds, name);
    if (idx < 0)
        return false;
    creds.erase(creds.begin() + idx);
    saveConfiguration(creds);
    return true;
}

String oath_secret_to_base32(const uint8_t *sec, uint8_t seclen)
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
