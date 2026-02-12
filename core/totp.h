#ifndef CORE_TOTP_H
#define CORE_TOTP_H

#include <Arduino.h>
#include <stddef.h>

/**
 * TOTP credential (otpauth Key URI Format).
 * LABEL = account name; secret (Base32); issuer; digits (default 6); period (default 30); algorithm (default SHA1).
 */
struct TOTPCredential
{
    String label;    /* account label (otpauth path / display name) */
    String secret;   /* Base32-encoded shared secret */
    String issuer;   /* issuer name */
    int digits;      /* 6, 7, or 8 */
    int period;      /* time step in seconds (default 30) */
    String algorithm;/* e.g. SHA1 */
};

/** Decode Base32 string into bytes. Returns number of bytes decoded, or <=0 on error. */
int totp_base32_decode(const char *encoded, uint8_t *result, int bufSize);

/** Generate TOTP for credential at given Unix timestamp (RFC 6238). Returns 6-digit code or error string. */
String totp_generate(const TOTPCredential &cred, uint32_t timestamp);

#endif
