#ifndef SERIAL_COMM_H
#define SERIAL_COMM_H

#include <Arduino.h>
#include <vector>
#include <RTClib.h>
#include "types.h"

void processSerialCommands(Stream &serial, RTC_DS3231 &rtc, std::vector<TOTPAccount> &accounts);

#endif
