#ifndef DISPLAY_H
#define DISPLAY_H

#include <Adafruit_SSD1306.h>
#include <RTClib.h>
#include "types.h"

bool initDisplay(Adafruit_SSD1306 &display);

void renderClockPage(Adafruit_SSD1306 &display, const DeviceStatus &status);
void renderTOTPPage(Adafruit_SSD1306 &display, const DeviceStatus &status,
                    const std::vector<TOTPAccount> &accounts, int accountIndex,
                    RTC_DS3231 &rtc);

void drawBatteryIndicator(Adafruit_SSD1306 &display, int x, int y, int level);
void drawWiFiIcon(Adafruit_SSD1306 &display, int x, int y, bool connected);

#endif