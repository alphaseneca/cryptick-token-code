#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <Arduino.h>
#include <vector>
#include "totp.h"

/**
 * USB CDC handler — logs, recovery, and TOTP/OATH CLI (same LittleFS as HID OATH).
 *
 * Always: BOOTLOADER / REBOOT / HELP / LOGLEVEL / ATTEST /
 *         TOTP_LIST|ADD|DEL, OATH LIST|PUT|DELETE|SET_TIME, DATE|SETTIME
 * Optional (CRYPTICK_SERIAL_DEBUG_CMDS): FINGER_*, FIDO_RESET
 *
 * Put/delete UV matches HID when CRYPTICK_OATH_REQUIRE_FP (bootstrap if no FP templates).
 * HID OATH: docs/HID_HOST.md
 */
void processSerialCommands(Stream &serial, std::vector<TOTPCredential> &credentials,
    void *finger = nullptr, bool fingerprintReady = false);

#endif
