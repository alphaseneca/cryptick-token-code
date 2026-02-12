#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <Arduino.h>
#include <vector>
#include "../core/totp.h"

/**
 * Serial commands (line-based, one command per line). Time = Unix/POSIX seconds (UTC).
 *
 * DATE              Show current date/time and Unix timestamp.
 * DATE <unix_ts>    Set RTC from Unix timestamp (alias for SETTIME).
 * SETTIME <unix_ts> Set RTC from Unix timestamp.
 * TOTP_ADD <otpauth_uri>  Add TOTP credential (otpauth://totp/... or otp://totp/...).
 * TOTP_LIST        List credentials (index, label, issuer, digits, period).
 * TOTP <index>     Generate current TOTP code for credential at index.
 * TOTP_DELETE <index>  Delete credential at index and save.
 * HELP, ?          Show commands.
 * FINGER_ENROLL [id], FINGER_DELETE <id>, FINGER_COUNT, FINGER_CLEAR  (if ENABLE_FINGERPRINT).
 */
void processSerialCommands(Stream &serial, std::vector<TOTPCredential> &credentials,
    void *finger = nullptr, bool fingerprintReady = false);

#endif
