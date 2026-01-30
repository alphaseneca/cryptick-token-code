#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#ifdef ENABLE_WEBSERVER
#include <ESP8266WebServer.h>
#include <RTClib.h>
#include "types.h"

void setupWebServer(ESP8266WebServer &server, std::vector<TOTPAccount> &accounts,
                    RTC_DS3231 &rtc);
#else
// When web server is disabled at build time, provide no-op declaration
// so other code can be compiled without linking the web server.
#include <RTClib.h>
#include "types.h"
inline void setupWebServer(void * /*server*/, std::vector<TOTPAccount> & /*accounts*/, RTC_DS3231 & /*rtc*/) {}
#endif

#endif