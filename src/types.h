#ifndef TYPES_H
#define TYPES_H

#include <Arduino.h>
#include <RTClib.h>

enum PageType
{
    PAGE_CLOCK = 0,
    PAGE_TOTP = 1,
    PAGE_COUNT = 2
};

struct TOTPAccount
{
    String name;
    String secret;
    String issuer;
    int digits;
    int period;
    String algorithm;
};

struct DeviceStatus
{
    bool wifiConnected;
    int batteryLevel;
    String username;
    DateTime currentTime;
};

#endif