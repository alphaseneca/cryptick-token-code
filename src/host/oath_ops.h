#ifndef OATH_OPS_H
#define OATH_OPS_H

/**
 * Shared OATH/TOTP helpers for HID (CTAPHID 0xE3) and CDC serial CLI.
 * Same UV policy, otpauth parse, store limits as product HID OATH.
 */
#include "totp.h"
#include <stddef.h>
#include <vector>

/*
 * Single source of truth for the credential store size. `totp_storage` sizes
 * its load buffer from this too — when the two disagreed, LittleFS could hold
 * more entries than PUT would ever accept, and the extra ones silently
 * vanished on the next save.
 */
#ifndef OATH_MAX_CREDS
#define OATH_MAX_CREDS 32
#endif
#ifndef OATH_MAX_NAME
#define OATH_MAX_NAME 64
#endif
/** Largest raw (decoded) TOTP secret accepted by PUT and by the store. */
#ifndef OATH_MAX_SECRET
#define OATH_MAX_SECRET 64
#endif

/** Display name: "issuer:label" or just label. */
String oath_display_name(const TOTPCredential &cred);

/** Match label or full issuer:label. */
int oath_find_by_name(const std::vector<TOTPCredential> &creds, const char *name);

/**
 * Product UV for sensitive OATH (PUT/DELETE/CALCULATE).
 * Bootstrap if no FP templates; uses auth session or live fingerprint.
 */
bool oath_ensure_uv(const char *prompt);

/** Parse otpauth://totp/… (and otp:// shorthand). Product: SHA1, 6 digits, 30s. */
bool oath_parse_otpauth(const char *uri, size_t uri_len, TOTPCredential &out);

/**
 * Parse CLI put args:
 *   otpauth://… | otp://…
 *   name <base32> [digits] [period]
 *   issuer:account <base32>
 * Returns false and sets err (may be nullptr) on failure.
 */
bool oath_parse_put_args(const String &args, TOTPCredential &out, const char **err);

/** Insert or replace credential; save LittleFS. Returns false if full / save issue. */
bool oath_put_credential(std::vector<TOTPCredential> &creds, const TOTPCredential &cred,
                         bool *replaced);

/** Delete by name (label or issuer:label). false if not found. */
bool oath_delete_credential(std::vector<TOTPCredential> &creds, const char *name);

/** Binary secret → uppercase base32 (no padding). */
String oath_secret_to_base32(const uint8_t *sec, uint8_t seclen);

#endif
