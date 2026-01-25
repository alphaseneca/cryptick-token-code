#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include <ESP8266WebServer.h>
#include <RTClib.h>
#include "types.h"

void setupWebServer(ESP8266WebServer &server, std::vector<TOTPAccount> &accounts,
                    RTC_DS3231 &rtc);

#endif