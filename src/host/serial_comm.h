#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <Arduino.h>
#include <vector>
#include "totp.h"

/**
 * USB CDC handler — product path is logs + reflash only.
 *
 * Always: BOOTLOADER / DFU / DOWNLOAD → ROM USB download; HELP
 * Optional (CRYPTICK_SERIAL_DEBUG_CMDS): DATE/SETTIME, TOTP_*, FINGER_*, FIDO_RESET
 *
 * Product TOTP secret manage / clock set over HID: docs/HID_HOST.md
 */
void processSerialCommands(Stream &serial, std::vector<TOTPCredential> &credentials,
    void *finger = nullptr, bool fingerprintReady = false);

#endif
