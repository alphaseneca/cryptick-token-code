#include "totp_core.h"
#include <TOTP.h>

int base32_decode(const char *encoded, uint8_t *result, int bufSize)
{
    const char *base32_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    int buffer = 0, bitsLeft = 0, count = 0;

    for (const char *ptr = encoded; *ptr && count < bufSize; ++ptr)
    {
        char ch = toupper(*ptr);
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
            result[count++] = (buffer >> (bitsLeft - 8)) & 0xFF;
            bitsLeft -= 8;
        }
    }
    return count;
}

String generateTOTP(const TOTPAccount &account, time_t timestamp)
{
    if (timestamp == 0)
        return "RTC Error";

    uint8_t key[32];
    int keyLen = base32_decode(account.secret.c_str(), key, sizeof(key));

    if (keyLen == 0)
        return "Invalid Secret";

    TOTP totp(key, keyLen);
    char *code = totp.getCode(timestamp);
    return String(code);
}