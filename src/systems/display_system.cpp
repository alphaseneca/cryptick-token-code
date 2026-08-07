#include "display_system.h"
#include "nav_system.h"
#include "battery_system.h"
#include "fp_system.h"
#include "auth_system.h"
#include <board_config.h>
#include "device.h"
#include <U8g2lib.h>
#include <Wire.h>
#include <stdio.h>
#include <string.h>

/* Pass clock/data so U8g2 does not re-begin Wire on wrong pins. */
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/U8X8_PIN_NONE,
                                                /* clock=*/OLED_SCL, /* data=*/OLED_SDA);
static ChargeState _charge = CHARGE_IDLE;
static const std::vector<TOTPCredential> *_creds = nullptr;
static char _user[32] = "User";
static unsigned long _lastDraw = 0;
static bool _dirty = true;
static bool _oled_ok = false;

static void format_time(uint32_t t, char *date_str, size_t ds, char *time_str, size_t ts)
{
    unsigned long sec = (unsigned long)t;
    unsigned long min = sec / 60; sec %= 60;
    unsigned long hour = min / 60; min %= 60;
    unsigned long days = hour / 24; hour %= 24;

    if (time_str && ts)
        snprintf(time_str, ts, "%02lu:%02lu:%02lu", hour, min, sec);
    if (!(date_str && ds)) return;

    int year = 1970;
    int month_days[] = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    while (days >= 365) {
        int dpy = (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)) ? 366 : 365;
        if (days < (unsigned long)dpy) break;
        days -= dpy;
        year++;
    }
    if (year % 4 == 0 && (year % 100 != 0 || year % 400 == 0))
        month_days[1] = 29;
    int month = 0;
    while (month < 12 && days >= (unsigned long)month_days[month]) {
        days -= month_days[month];
        month++;
    }
    int day = (int)days + 1;
    month++;
    snprintf(date_str, ds, "%02d/%02d/%04d", day, month, year);
}

static void draw_charge_icon(int x, int y)
{
    /* Battery shell */
    u8g2.drawFrame(x, y, 18, 9);
    u8g2.drawBox(x + 18, y + 2, 2, 5);

    switch (_charge) {
    case CHARGE_CHARGING: {
        /* Animated fill: 3 phases */
        int phase = (int)((millis() / 350) % 4);
        int fill = 3 + phase * 3;
        if (fill > 14) fill = 14;
        u8g2.drawBox(x + 2, y + 2, fill, 5);
        /* lightning */
        u8g2.drawLine(x + 8, y + 1, x + 11, y + 4);
        u8g2.drawLine(x + 11, y + 4, x + 9, y + 4);
        u8g2.drawLine(x + 9, y + 4, x + 12, y + 8);
        break;
    }
    case CHARGE_DONE:
        u8g2.drawBox(x + 2, y + 2, 14, 5);
        break;
    case CHARGE_FAULT:
        u8g2.drawLine(x + 3, y + 1, x + 15, y + 7);
        u8g2.drawLine(x + 15, y + 1, x + 3, y + 7);
        break;
    default:
        u8g2.drawBox(x + 2, y + 2, 7, 5);
        break;
    }

    /* Text tag left of icon */
    u8g2.setFont(u8g2_font_5x7_tr);
    const char *lab = battery_system_label();
    int lw = u8g2.getStrWidth(lab);
    u8g2.drawStr(x - lw - 2, y + 7, lab);
}

static void draw_status_bar(uint32_t utc)
{
    char date_str[16], time_str[10];
    format_time(utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 7, date_str);
    draw_charge_icon(108, 0);
}

static void draw_title(const char *title)
{
    u8g2.setFont(u8g2_font_6x12_tr);
    u8g2.drawStr(0, 20, title);
    u8g2.drawHLine(0, 22, 128);
}

static void draw_menu_list(const char **items, int count, int selected)
{
    draw_title("Menu");
    u8g2.setFont(u8g2_font_6x12_tr);
    for (int i = 0; i < count; i++) {
        int y = 36 + i * 12;
        if (i == selected) {
            u8g2.drawBox(0, y - 9, 128, 11);
            u8g2.setDrawColor(0);
            u8g2.drawStr(4, y, items[i]);
            u8g2.setDrawColor(1);
        } else {
            u8g2.drawStr(4, y, items[i]);
        }
    }
}

static void draw_settings(void)
{
    static const char *items[] = { "Enroll finger", "Clear fingers", "Templates" };
    draw_title("Settings");
    u8g2.setFont(u8g2_font_6x12_tr);
    int sel = nav_system_settings_index();
    char line[32];
    for (int i = 0; i < 3; i++) {
        int y = 36 + i * 12;
        if (i == 2) {
            snprintf(line, sizeof(line), "Templates: %u", (unsigned)fp_system_template_count());
        } else {
            strncpy(line, items[i], sizeof(line) - 1);
            line[sizeof(line) - 1] = 0;
        }
        if (i == sel) {
            u8g2.drawBox(0, y - 9, 128, 11);
            u8g2.setDrawColor(0);
            u8g2.drawStr(4, y, line);
            u8g2.setDrawColor(1);
        } else {
            u8g2.drawStr(4, y, line);
        }
    }
}

static void draw_clock(uint32_t utc)
{
    char date_str[16], time_str[10];
    format_time(utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 7, date_str);
    draw_charge_icon(108, 0);

    u8g2.setFont(u8g2_font_logisoso22_tn);
    int tw = u8g2.getStrWidth(time_str);
    u8g2.drawStr((128 - tw) / 2, 42, time_str);

    u8g2.setFont(u8g2_font_6x12_tr);
    u8g2.drawStr(0, 60, _user);
    if (fp_system_ready())
        u8g2.drawStr(90, 60, "FP");
}

static void draw_totp(uint32_t utc)
{
    draw_status_bar(utc);
    if (!_creds || _creds->empty()) {
        draw_title("TOTP");
        u8g2.setFont(u8g2_font_6x12_tr);
        u8g2.drawStr(0, 40, "No accounts");
        u8g2.drawStr(0, 54, "Add via serial");
        return;
    }
    int idx = nav_system_account_index();
    if (idx < 0 || idx >= (int)_creds->size()) idx = 0;
    const TOTPCredential &c = (*_creds)[idx];
    String code = totp_generate(c, utc);

    char header[48];
    snprintf(header, sizeof(header), "%s %d/%d",
             c.label.length() ? c.label.c_str() : "Account",
             idx + 1, (int)_creds->size());
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 18, header);

    const char *issuer = c.issuer.length() ? c.issuer.c_str() : "-";
    u8g2.drawStr(0, 28, issuer);

    u8g2.setFont(u8g2_font_logisoso22_tn);
    int cw = u8g2.getStrWidth(code.c_str());
    u8g2.drawStr((128 - cw) / 2, 54, code.c_str());

    int period = c.period > 0 ? c.period : 30;
    unsigned long rem = period - (utc % (unsigned long)period);
    int barW = (int)((128 * rem) / period);
    u8g2.drawBox(0, 60, barW, 3);
}

static void draw_message(const char *t1, const char *t2)
{
    u8g2.setFont(u8g2_font_6x12_tr);
    int w1 = u8g2.getStrWidth(t1);
    u8g2.drawStr((128 - w1) / 2, 28, t1);
    if (t2) {
        int w2 = u8g2.getStrWidth(t2);
        u8g2.drawStr((128 - w2) / 2, 44, t2);
    }
}

static void draw_enroll(void)
{
    draw_title("Enroll finger");
    u8g2.setFont(u8g2_font_6x12_tr);
    char line[40];
    uint8_t step = nav_system_enroll_step();
    if (nav_system_enroll_remove()) {
        snprintf(line, sizeof(line), "Step %u/2 - remove", (unsigned)step);
        u8g2.drawStr(0, 40, line);
        u8g2.drawStr(0, 54, "Lift finger");
    } else {
        snprintf(line, sizeof(line), "Step %u/2 - place", (unsigned)step);
        u8g2.drawStr(0, 40, line);
        u8g2.drawStr(0, 54, "Press finger on sensor");
    }
    /* progress */
    u8g2.drawFrame(0, 58, 128, 5);
    int fill = (step >= 2 && !nav_system_enroll_remove()) ? 128 : (step == 1 ? 40 : 80);
    if (nav_system_enroll_remove() && step == 1) fill = 64;
    u8g2.drawBox(0, 58, fill, 5);
}

static void render(void)
{
    if (!_oled_ok)
        return;

    uint32_t utc = get_synced_utc();
    UiState st = nav_system_state();

    i2c_lock();
    u8g2.clearBuffer();

    switch (st) {
    case UI_CLOCK:
        draw_clock(utc);
        break;
    case UI_MENU: {
        static const char *items[] = { "TOTP", "Settings" };
        draw_menu_list(items, 2, nav_system_menu_index());
        break;
    }
    case UI_TOTP:
        draw_totp(utc);
        break;
    case UI_SETTINGS:
        draw_settings();
        break;
    case UI_AUTH_PROMPT:
        draw_message("Place finger", "to unlock TOTP");
        break;
    case UI_AUTH_ERROR:
        draw_message("Fingerprint", "not verified");
        break;
    case UI_FP_ENROLL:
        draw_enroll();
        break;
    case UI_FP_CLEAR_CONFIRM:
        draw_message("Clear all fingers?", "Center=Yes  Left=No");
        break;
    case UI_FIDO_PROMPT:
        draw_message(nav_system_fido_label(), "Place finger to confirm");
        break;
    case UI_FIDO_PROCESSING:
        draw_message("Working...", "Please wait");
        break;
    case UI_FIDO_SUCCESS:
        draw_message("Authenticated", "Success");
        break;
    }

    u8g2.sendBuffer();
    i2c_unlock();
}

void display_system_init(void)
{
    i2c_lock();
    Wire.begin(OLED_SDA, OLED_SCL);
    Wire.setTimeOut(50);
    Wire.setClock(100000);

    /* Log who is on the bus (0x3C OLED, often 0x68 RTC) */
    uint8_t found = 0;
    for (uint8_t a = 1; a < 127; a++) {
        Wire.beginTransmission(a);
        if (Wire.endTransmission() == 0) {
            Serial.printf("[I2C] device 0x%02X\n", a);
            found++;
        }
    }
    if (!found)
        Serial.println(F("[I2C] no devices — check SDA/SCL / power / OLED soldering"));

    u8g2.setI2CAddress(OLED_ADDRESS << 1);
    _oled_ok = u8g2.begin();
    if (!_oled_ok) {
        Serial.println(F("[DISP] SSD1306 begin FAILED (addr 0x3C)"));
        i2c_unlock();
        return;
    }

    u8g2.setBusClock(400000);
    Wire.setClock(400000);
    u8g2.setContrast(255);
    u8g2.clearBuffer();
    u8g2.setFont(u8g2_font_6x12_tr);
    u8g2.drawStr(12, 28, "Cryptick Token");
    u8g2.drawStr(28, 44, "booting...");
    u8g2.sendBuffer();
    i2c_unlock();

    Serial.printf("[DISP] OK  SSD1306 @0x%02X  SDA=%d SCL=%d\n",
                  OLED_ADDRESS, OLED_SDA, OLED_SCL);
    _dirty = true;
}

void display_system_set_credentials(const std::vector<TOTPCredential> *creds)
{
    _creds = creds;
    _dirty = true;
}

void display_system_set_user(const char *name)
{
    if (!name) return;
    strncpy(_user, name, sizeof(_user) - 1);
    _user[sizeof(_user) - 1] = 0;
    _dirty = true;
}

void display_system_force_redraw(void)
{
    _dirty = true;
}

void display_system_on_event(const BusEvent &e)
{
    if (e.type == EVT_UI_STATE || e.type == EVT_BATTERY || e.type == EVT_FP ||
        e.type == EVT_AUTH || e.type == EVT_INPUT)
        _dirty = true;
    if (e.type == EVT_BATTERY)
        _charge = (ChargeState)e.kind;
}

void display_system_tick(unsigned long nowMs)
{
    UiState st = nav_system_state();
    _charge = battery_system_state(); /* always stay in sync */

    bool urgent = (st == UI_FIDO_PROMPT || st == UI_FIDO_PROCESSING || st == UI_FP_ENROLL ||
                   st == UI_AUTH_PROMPT || _charge == CHARGE_CHARGING);
    unsigned long interval = urgent ? 350UL : (unsigned long)DISPLAY_UPDATE_INTERVAL;
    if (st == UI_TOTP || st == UI_CLOCK)
        interval = (_charge == CHARGE_CHARGING) ? 350UL : 1000UL;

    bool due = (nowMs - _lastDraw >= interval);
    if (!_dirty && !due) return;
    render();
    _lastDraw = nowMs;
    _dirty = false;
}
