#include "display_handler.h"
#include "config.h"
#include "../core/device.h"
#include "../drivers/display_ssd1306.h"

/** Convert Unix seconds (from RTC) to date/time strings. No C time library. */
static void format_date_time(uint32_t t, char *date_str, size_t date_size, char *time_str, size_t time_size)
{
    unsigned long sec = (unsigned long)t;
    unsigned long min = sec / 60; sec %= 60;
    unsigned long hour = min / 60; min %= 60;
    unsigned long days = hour / 24; hour %= 24;

    if (time_str && time_size)
        snprintf(time_str, time_size, "%02lu:%02lu:%02lu", hour, min, sec);

    if (!(date_str && date_size)) return;

    int year = 1970;
    int month_days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    while (days >= 365)
    {
        int dpy = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        if (days < (unsigned long)dpy) break;
        days -= dpy;
        year++;
    }
    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
        month_days[1] = 29;
    int month = 0;
    while (month < 12 && days >= (unsigned long)month_days[month])
    {
        days -= month_days[month];
        month++;
    }
    int day = (int)days + 1;
    month++;
    snprintf(date_str, date_size, "%02d/%02d/%04d", day, month, year);
}

bool display_handler_init(Adafruit_SSD1306 &display)
{
    return display_ssd1306_init(display, OLED_ADDRESS, SCREEN_WIDTH, SCREEN_HEIGHT);
}

void display_handler_clock(Adafruit_SSD1306 &display, uint32_t current_utc,
    const char *username, int battery_pct, bool link_connected)
{
    char date_str[16], time_str[10];
    format_date_time(current_utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    display_ssd1306_clock(display, SCREEN_WIDTH, SCREEN_HEIGHT,
        date_str, time_str, username, battery_pct, link_connected);
}

void display_handler_totp(Adafruit_SSD1306 &display,
    const std::vector<TOTPCredential> &credentials, size_t index)
{
    if (credentials.empty())
    {
        display_handler_message(display, "No TOTP credentials", "Add via serial");
        return;
    }
    const TOTPCredential &cred = credentials[index];
    uint32_t ts = device_get_time_utc();
    String code = totp_generate(cred, ts);
    char time_str[10], countdown[8];
    format_date_time(ts, nullptr, 0, time_str, sizeof(time_str));
    unsigned long rem = cred.period - (ts % (unsigned long)cred.period);
    snprintf(countdown, sizeof(countdown), "%lus", (unsigned long)rem);
    const char *label = cred.label.length() ? cred.label.c_str() : "(no name)";
    const char *issuer = cred.issuer.length() ? cred.issuer.c_str() : "-";
    display_ssd1306_totp(display, SCREEN_WIDTH, SCREEN_HEIGHT,
        label, time_str, code.c_str(), issuer, countdown);
}

void display_handler_message(Adafruit_SSD1306 &display, const char *line1, const char *line2)
{
    display_ssd1306_message(display, SCREEN_WIDTH, SCREEN_HEIGHT, line1, line2);
}

void display_handler_auth_prompt(Adafruit_SSD1306 &display)
{
    display_ssd1306_message(display, SCREEN_WIDTH, SCREEN_HEIGHT, "Place your finger", "on sensor");
}

void display_handler_auth_error(Adafruit_SSD1306 &display)
{
    display_ssd1306_message(display, SCREEN_WIDTH, SCREEN_HEIGHT, "Fingerprint could", "not be verified");
}
