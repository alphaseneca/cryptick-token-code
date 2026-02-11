#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <Arduino.h>
#include <vector>
#include <RTClib.h>
#include "types.h"

// Optional: pass finger (void* to R558SFingerprint*) and fingerprintReady for FINGER_* commands
void processSerialCommands(Stream &serial, RTC_DS3231 &rtc, std::vector<TOTPAccount> &accounts,
    void* finger = nullptr, bool fingerprintReady = false);

#endif
