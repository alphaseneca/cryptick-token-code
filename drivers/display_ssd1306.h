#ifndef DRIVERS_DISPLAY_SSD1306_H
#define DRIVERS_DISPLAY_SSD1306_H

#include <Adafruit_SSD1306.h>

/** Initialize OLED. Return true on success. */
bool display_ssd1306_init(Adafruit_SSD1306 &display, uint8_t i2c_addr, int width, int height);

/** Draw clock page: date_str, time_str, username, battery 0-100, link_connected (e.g. BLE). */
void display_ssd1306_clock(Adafruit_SSD1306 &display, int width, int height,
    const char *date_str, const char *time_str, const char *username, int battery_pct, bool link_connected);

/** Draw TOTP page: account header (name + index), time_str, code (6-8 digits), issuer, countdown. */
void display_ssd1306_totp(Adafruit_SSD1306 &display, int width, int height,
    const char *account_header, const char *time_str, const char *code,
    const char *issuer, const char *countdown_str);

/** Draw page menu with selection indicator. items = array of page names, selectedIndex = highlighted. */
void display_ssd1306_menu(Adafruit_SSD1306 &display, int width, int height,
    const char **items, int itemCount, int selectedIndex);

/** Draw generic two-line message. */
void display_ssd1306_message(Adafruit_SSD1306 &display, int width, int height,
    const char *line1, const char *line2);

#endif
