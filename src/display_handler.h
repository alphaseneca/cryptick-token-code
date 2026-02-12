#ifndef SRC_DISPLAY_HANDLER_H
#define SRC_DISPLAY_HANDLER_H

#include <Adafruit_SSD1306.h>
#include "../core/totp.h"
#include <vector>

bool display_handler_init(Adafruit_SSD1306 &display);
void display_handler_clock(Adafruit_SSD1306 &display, uint32_t current_utc,
    const char *username, int battery_pct, bool link_connected);
void display_handler_totp(Adafruit_SSD1306 &display,
    const std::vector<TOTPCredential> &credentials, size_t index);
void display_handler_message(Adafruit_SSD1306 &display, const char *line1, const char *line2);
/** Shown when waiting for fingerprint: place finger on sensor. */
void display_handler_auth_prompt(Adafruit_SSD1306 &display);
/** Shown when fingerprint verification failed (wrong finger, etc.). */
void display_handler_auth_error(Adafruit_SSD1306 &display);

#endif
