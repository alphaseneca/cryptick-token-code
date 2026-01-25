#ifndef TOTP_CORE_H
#define TOTP_CORE_H

#include <Arduino.h>
#include "types.h"

int base32_decode(const char *encoded, uint8_t *result, int bufSize);
String generateTOTP(const TOTPAccount &account, time_t timestamp);

#endif