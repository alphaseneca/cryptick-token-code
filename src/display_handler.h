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

/** Render page menu with highlighted selection. */
void display_handler_menu(Adafruit_SSD1306 &display,
    const char **items, int itemCount, int selectedIndex);

void display_handler_message(Adafruit_SSD1306 &display, const char *line1, const char *line2);

/** Shown when waiting for fingerprint: place finger on sensor. */
void display_handler_auth_prompt(Adafruit_SSD1306 &display);

/** Shown when fingerprint verification failed (wrong finger, etc.). */
void display_handler_auth_error(Adafruit_SSD1306 &display);

/** Shown when FIDO2 requests user presence. */
void display_handler_fido_prompt(Adafruit_SSD1306 &display, const char *site);

/** Shown during heavy FIDO2 cryptographic operations. */
void display_handler_fido_processing(Adafruit_SSD1306 &display);

/** Shown after successful FIDO2 operation. */
void display_handler_fido_success(Adafruit_SSD1306 &display);

#endif
