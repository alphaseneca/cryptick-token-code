#include "display_system.h"
#include "nav_system.h"
#include "battery_system.h"
#include "fp_system.h"
#include "auth_system.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include "credential_store.h"
#include "device.h"
#include "usb_device.h"
#if CRYPTICK_BLE_FIDO
#include "ble_fido.h"
#include "ble_hid_keyboard.h"
#endif
#include <U8g2lib.h>
#include <Wire.h>
#include <stdio.h>
#include <string.h>
#include "display_icons.h"

/* Use HW I2C without clock/data args — Wire.begin(SDA,SCL) owns the pins.
 * Passing SCL/SDA into the U8g2 HW constructor can re-init Wire and hang
 * on ESP32-S3 after a manual bus scan. */
static U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/U8X8_PIN_NONE);

static ChargeState _charge = CHARGE_IDLE;
static const std::vector<TOTPCredential> *_creds = nullptr;
static char _user[32] = "User";
static unsigned long _lastDraw = 0;
static unsigned long _lastReinit = 0;
#define DISPLAY_REINIT_MIN_MS 2000UL
#define DISPLAY_REINIT_MAX_MS 30000UL
static unsigned long _reinitBackoffMs = DISPLAY_REINIT_MIN_MS;
static bool _dirty = true;
static bool _oled_ok = false;
static bool _asleep = false;
static uint8_t _oled_addr = OLED_ADDRESS;

/*
 * Truncation marker. Every font this file uses (u8g2_font_*_tr/_tn) is built
 * with "Glyphs: 95/N" in its own header comment in U8g2's font table — the
 * 95 printable ASCII characters, 0x20-0x7E, and nothing else. u8g2.drawStr()
 * draws via u8x8_ascii_next (one input *byte* = one glyph lookup, no UTF-8
 * decoding — that path only exists in u8g2.drawUTF8()), so a real ellipsis
 * character ('…', UTF-8 bytes E2 80 A6) used to turn into three
 * out-of-range glyph lookups per truncated string: this file's single most
 * common rendering call. Two ASCII periods read clearly at this pixel size
 * and cost less width than three.
 */
static const char *const kEllipsis = "..";

static void draw_str_ellipsis(int x, int y, const char *s, int maxW)
{
    if (!s) s = "";
    int w = u8g2.getStrWidth(s);
    if (w <= maxW) {
        u8g2.drawStr(x, y, s);
        return;
    }
    char buf[40];
    size_t n = strlen(s);
    if (n >= sizeof(buf)) n = sizeof(buf) - 1;
    memcpy(buf, s, n);
    buf[n] = 0;
    while (n > 1) {
        n--;
        buf[n] = 0;
        char tmp[44];
        snprintf(tmp, sizeof(tmp), "%s%s", buf, kEllipsis);
        if (u8g2.getStrWidth(tmp) <= maxW) {
            u8g2.drawStr(x, y, tmp);
            return;
        }
    }
    u8g2.drawStr(x, y, kEllipsis);
}

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

/*
 * Shared status-icon cluster, right-aligned, reused by every screen that
 * shows a title row or a home/TOTP status bar (draw_title / draw_status_bar
 * / draw_clock below) — one fixed layout instead of each screen placing its
 * own battery glyph at its own x, which is how the old draw_charge_icon(108,
 * ...) and draw_title's 90px title budget ended up able to collide: a long
 * title plus a battery *label* (see draw_battery_icon) floating further
 * left than either side accounted for. Reserving this zone, and clipping
 * title text to end before it (TITLE_SAFE_W), removes that class of bug by
 * construction instead of by tuning more magic numbers.
 */
#if CRYPTICK_BLE_FIDO
static const int STATUS_BLE_X = 90;
static const int STATUS_BATTERY_X = 104;
static const int TITLE_SAFE_W = 86;
#else
static const int STATUS_BATTERY_X = 104;
static const int TITLE_SAFE_W = 100;
#endif

/** Draw an XBM glyph; strike it diagonally when `ok` is false. One shape per
 *  concept, told apart by the strike-through rather than a second bitmap —
 *  reused for BLE connected/disconnected and fingerprint ready/absent. */
static void draw_icon_state(int x, int y, const unsigned char *bits, int w, int h, bool ok)
{
    u8g2.drawXBMP(x, y, w, h, bits);
    if (!ok)
        u8g2.drawLine(x, y, x + w - 1, y + h - 1);
}

static void draw_ble_icon(int x, int y)
{
#if CRYPTICK_BLE_FIDO
    draw_icon_state(x, y, icon_ble_bits, ICON_BLE_W, ICON_BLE_H,
                    ble_fido_is_connected() != 0);
#else
    (void)x; (void)y;
#endif
}

/**
 * Battery glyph: the XBM shell (see display_icons.h for why — no fuel-gauge
 * ADC on this board, so there is no "level" to show, only the charger's
 * idle/charging/done/fault state) plus a fill drawn at the same relative
 * offsets the old hand-drawn frame used, so the charging animation and fault
 * mark are unchanged, just built on the shared glyph instead of one-off
 * vector calls. `with_label` adds the short CHG/FULL/FLT text to its left —
 * left on for the home/TOTP status bar, which has room; left off for the
 * title-bar usage, which must stay a fixed width for TITLE_SAFE_W to hold.
 */
static void draw_battery_icon(int x, int y, bool with_label)
{
    u8g2.drawXBMP(x, y, ICON_BATTERY_W, ICON_BATTERY_H, icon_battery_shell_bits);

    switch (_charge) {
    case CHARGE_CHARGING: {
        int phase = (int)((millis() / 350) % 4);
        int fill = 3 + phase * 3;
        if (fill > 14) fill = 14;
        u8g2.drawBox(x + 2, y + 2, fill, 5);
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

    if (with_label) {
        u8g2.setFont(u8g2_font_5x7_tr);
        const char *lab = battery_system_label();
        if (lab && lab[0]) {
            int lw = u8g2.getStrWidth(lab);
            u8g2.drawStr(x - lw - 2, y + 7, lab);
        }
    }
}

static void draw_status_bar(uint32_t utc)
{
    char date_str[16], time_str[10];
    format_time(utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 7, date_str);
    draw_ble_icon(STATUS_BLE_X, 0);
    draw_battery_icon(STATUS_BATTERY_X, 0, true);
}

static void draw_title(const char *title)
{
    u8g2.setFont(u8g2_font_6x12_tr);
    draw_str_ellipsis(0, 12, title, TITLE_SAFE_W);
    u8g2.drawHLine(0, 14, 128);
    draw_ble_icon(STATUS_BLE_X, 2);
    draw_battery_icon(STATUS_BATTERY_X, 2, false);
}

/** Rows that fit under the title bar. */
#define LIST_ROWS 3

static void draw_list_row(int row, const char *text, bool selected, int maxW)
{
    int y = 27 + row * 15;
    int boxW = (maxW < 120) ? 122 : 128;
    if (selected) {
        u8g2.drawBox(0, y - 10, boxW, 13);
        u8g2.setDrawColor(0);
        draw_str_ellipsis(4, y, text, maxW);
        u8g2.setDrawColor(1);
    } else {
        draw_str_ellipsis(4, y, text, maxW);
    }
}

/**
 * Scroll indicator for lists longer than LIST_ROWS.
 */
static void draw_scrollbar(int count, int first)
{
    if (count <= LIST_ROWS)
        return;
    const int trackY = 17, trackH = 44;
    int thumbH = trackH * LIST_ROWS / count;
    if (thumbH < 5) thumbH = 5;
    int thumbY = trackY + ((trackH - thumbH) * first) / (count - LIST_ROWS);
    u8g2.drawVLine(126, trackY, trackH);
    u8g2.drawBox(124, thumbY, 4, thumbH);
}

/** Window start that keeps `selected` on screen. */
static int list_first_row(int count, int selected)
{
    if (count <= LIST_ROWS)
        return 0;
    int first = selected - LIST_ROWS / 2;
    if (first < 0) first = 0;
    if (first > count - LIST_ROWS) first = count - LIST_ROWS;
    return first;
}

static void draw_menu_list(const char **items, int count, int selected)
{
    draw_title("Menu");
    u8g2.setFont(u8g2_font_6x12_tr);
    int first = list_first_row(count, selected);
    for (int r = 0; r < LIST_ROWS && (first + r) < count; r++)
        draw_list_row(r, items[first + r], (first + r) == selected, 120);
    draw_scrollbar(count, first);
}

static void draw_settings(void)
{
    draw_title("Settings");
    u8g2.setFont(u8g2_font_6x12_tr);

    int count = nav_system_settings_count();
    int sel = nav_system_settings_index();
    int first = list_first_row(count, sel);
    const char *msg = nav_system_enroll_message();
    int maxW = (count > LIST_ROWS) ? 114 : 120;

    for (int r = 0; r < LIST_ROWS && (first + r) < count; r++) {
        char line[32];
        nav_system_settings_label(first + r, line, sizeof(line));
        draw_list_row(r, line, (first + r) == sel, maxW);
    }
    draw_scrollbar(count, first);

    if (msg && msg[0]) {
        u8g2.setDrawColor(0);
        u8g2.drawBox(12, 20, 104, 25);
        u8g2.setDrawColor(1);
        u8g2.drawFrame(12, 20, 104, 25);
        u8g2.setFont(u8g2_font_6x12_tr);
        int mw = u8g2.getStrWidth(msg);
        u8g2.drawStr((128 - mw) / 2, 36, msg);
    }
}

static void draw_ble_menu(void)
{
    draw_title("Bluetooth");
    u8g2.setFont(u8g2_font_5x7_tr);

#if CRYPTICK_BLE_FIDO
    bool connected = (ble_fido_is_connected() != 0);
    bool advertising = (ble_fido_is_advertising() != 0);
    size_t bonds = ble_fido_bond_count();

    /*
     * Status line sits in list-grid "row 0" (draw_list_row's y=27, box
     * 17-30) with its own icon instead of the word "Status:" — the action
     * items below reuse rows 1-2 of the exact same grid draw_settings and
     * draw_menu_list use, which is what makes this screen stop having its
     * own layout. draw_str_ellipsis bounds it against the icon's right
     * edge, since a bond count is runtime data and this file's fonts have
     * no slack to eyeball widths by hand (see draw_str_ellipsis's comment).
     */
    draw_icon_state(0, 17, icon_ble_bits, ICON_BLE_W, ICON_BLE_H, connected);
    char line[36];
    if (connected)
        snprintf(line, sizeof(line), "Connected - %u bond%s", (unsigned)bonds,
                 bonds == 1 ? "" : "s");
    else if (advertising)
        snprintf(line, sizeof(line), "Advertising - %u/4 bond%s", (unsigned)bonds,
                 bonds == 1 ? "" : "s");
    else
        snprintf(line, sizeof(line), "Offline");
    draw_str_ellipsis(15, 25, line, 113);

    u8g2.drawHLine(0, 30, 128);

    int count = nav_system_ble_menu_count();
    int sel = nav_system_ble_menu_index();
    int first = list_first_row(count, sel);

    u8g2.setFont(u8g2_font_6x12_tr);
    /* Row 0 is the status line above; action items start at row 1. */
    for (int r = 0; r < LIST_ROWS - 1 && (first + r) < count; r++) {
        char act_label[32];
        nav_system_ble_menu_label(first + r, act_label, sizeof(act_label));
        draw_list_row(r + 1, act_label, (first + r) == sel, 120);
    }
    draw_scrollbar(count, first);
#else
    u8g2.drawStr(0, 35, "BLE not supported");
#endif

    const char *msg = nav_system_enroll_message();
    if (msg && msg[0]) {
        u8g2.setDrawColor(0);
        u8g2.drawBox(12, 20, 104, 25);
        u8g2.setDrawColor(1);
        u8g2.drawFrame(12, 20, 104, 25);
        u8g2.setFont(u8g2_font_6x12_tr);
        int mw = u8g2.getStrWidth(msg);
        u8g2.drawStr((128 - mw) / 2, 36, msg);
    }
}

static void draw_device_info(void)
{
    draw_title("Device info");
    u8g2.setFont(u8g2_font_5x7_tr);

    char line[36];
    int y = 25;

    /*
     * Every line here carries at least one runtime value (template/account
     * counts, uptime), so each goes through draw_str_ellipsis rather than a
     * bare drawStr: this is the one screen where uptime in particular grows
     * without bound (weeks of uptime widen "Up NNNNm59s"), and nothing here
     * is worth a hard clip at the 128px edge over a two-char "..".
     */
    snprintf(line, sizeof(line), "USB  %s",
             usb_device_mounted() ? "1209:BEEE host" : "not mounted");
    draw_str_ellipsis(0, y, line, 128);

    y += 10;
    snprintf(line, sizeof(line), "FP   %s  %u tpl",
             fp_system_ready() ? "ready" : "absent",
             (unsigned)fp_system_template_count());
    draw_str_ellipsis(0, y, line, 128);

    y += 10;
    snprintf(line, sizeof(line), "OATH %d accounts", nav_system_account_count());
    draw_str_ellipsis(0, y, line, 128);

    y += 10;
    unsigned long up = millis() / 1000UL;
    uint16_t slp = nav_system_sleep_timeout_sec();
    if (slp)
        snprintf(line, sizeof(line), "Up %lum%02lus   Slp %us",
                 up / 60UL, up % 60UL, (unsigned)slp);
    else
        snprintf(line, sizeof(line), "Up %lum%02lus   Slp off", up / 60UL, up % 60UL);
    draw_str_ellipsis(0, y, line, 128);
}

static void draw_clock(uint32_t utc)
{
    char date_str[16], time_str[10];
    format_time(utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 7, date_str);
    draw_ble_icon(STATUS_BLE_X, 0);
    draw_battery_icon(STATUS_BATTERY_X, 0, true);

    u8g2.setFont(u8g2_font_logisoso22_tn);
    int tw = u8g2.getStrWidth(time_str);
    u8g2.drawStr((128 - tw) / 2, 42, time_str);

    u8g2.setFont(u8g2_font_6x12_tr);
    draw_str_ellipsis(0, 60, _user, 80);
    /* A real glyph, struck through when absent, in place of "FP" / "-" text. */
    draw_icon_state(112, 50, icon_fingerprint_bits, ICON_FINGERPRINT_W,
                    ICON_FINGERPRINT_H, fp_system_ready());
}

static void draw_home(uint32_t utc)
{
    int card = nav_system_home_card();
    if (card == 1) {
        /* Quick PIV PIN Card */
        draw_title("Quick PIV Login");
        draw_icon_state(0, 19, icon_lock_bits, ICON_LOCK_W, ICON_LOCK_H, true);
        u8g2.setFont(u8g2_font_6x12_tr);
        u8g2.drawStr(16, 28, "PIN  123456");
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(16, 38, "Slot 9A - NIST PIV");
#if CRYPTICK_BLE_FIDO
        bool hidc = ble_hid_keyboard_is_connected();
        if (hidc) {
            u8g2.drawBox(0, 41, 128, 11);
            u8g2.setDrawColor(0);
            u8g2.drawStr(4, 49, "[OK] Auto-type PIN");
            u8g2.setDrawColor(1);
        } else {
            u8g2.drawFrame(0, 41, 128, 11);
            u8g2.drawStr(4, 49, "[OK] Auto-type PIN");
        }
        draw_icon_state(0, 52, icon_ble_bits, ICON_BLE_W, ICON_BLE_H, hidc);
        draw_str_ellipsis(15, 61, hidc ? "Connected" : "Offline - pair to use", 113);
#else
        u8g2.drawStr(0, 50, "[OK] Type PIN");
#endif
    } else if (card == 2) {
        /* Quick TOTP Card */
        draw_status_bar(utc);
        if (!_creds || _creds->empty()) {
            u8g2.setFont(u8g2_font_6x12_tr);
            u8g2.drawStr(0, 30, "No TOTP accounts");
            u8g2.setFont(u8g2_font_5x7_tr);
            u8g2.drawStr(0, 44, "Add via Extension");
        } else {
            int idx = nav_system_account_index();
            if (idx < 0 || idx >= (int)_creds->size()) idx = 0;
            const TOTPCredential &c = (*_creds)[idx];
            String code = totp_generate(c, utc);

            char hdr[32];
            snprintf(hdr, sizeof(hdr), "TOTP %d/%d", idx + 1, (int)_creds->size());
            u8g2.setFont(u8g2_font_5x7_tr);
            u8g2.drawStr(0, 18, hdr);
            int hx = u8g2.getStrWidth(hdr);
            draw_str_ellipsis(hx + 4, 18, c.label.length() ? c.label.c_str() : "Account", 124 - hx);

            u8g2.setFont(u8g2_font_logisoso22_tn);
            int cw = u8g2.getStrWidth(code.c_str());
            u8g2.drawStr((128 - cw) / 2, 46, code.c_str());

            u8g2.setFont(u8g2_font_5x7_tr);
            u8g2.drawStr(0, 58, "[OK] Type code");
            int rem = 30 - (int)(utc % 30);
            char rem_s[12];
            snprintf(rem_s, sizeof(rem_s), "%02ds", rem);
            int rw = u8g2.getStrWidth(rem_s);
            u8g2.drawStr(128 - rw, 58, rem_s);
        }
    } else {
        draw_clock(utc);
    }

    const char *msg = nav_system_enroll_message();
    if (msg && msg[0]) {
        u8g2.setDrawColor(0);
        u8g2.drawBox(10, 20, 108, 26);
        u8g2.setDrawColor(1);
        u8g2.drawFrame(10, 20, 108, 26);
        u8g2.setFont(u8g2_font_6x12_tr);
        int mw = u8g2.getStrWidth(msg);
        u8g2.drawStr((128 - mw) / 2, 37, msg);
    }
}

static void draw_totp(uint32_t utc)
{
    draw_status_bar(utc);
    if (!_creds || _creds->empty()) {
        draw_title("TOTP");
        u8g2.setFont(u8g2_font_6x12_tr);
        u8g2.drawStr(0, 40, "No accounts");
        u8g2.drawStr(0, 54, "Add via HID app");
        return;
    }
    int idx = nav_system_account_index();
    if (idx < 0 || idx >= (int)_creds->size()) idx = 0;
    const TOTPCredential &c = (*_creds)[idx];
    String code = totp_generate(c, utc);

    char header[48];
    snprintf(header, sizeof(header), "%d/%d ",
             idx + 1, (int)_creds->size());
    u8g2.setFont(u8g2_font_5x7_tr);
    u8g2.drawStr(0, 18, header);
    int hx = u8g2.getStrWidth(header);
    draw_str_ellipsis(hx, 18,
                      c.label.length() ? c.label.c_str() : "Account",
                      128 - hx);

    const char *issuer = c.issuer.length() ? c.issuer.c_str() : "-";
    draw_str_ellipsis(0, 28, issuer, 128);

    u8g2.setFont(u8g2_font_logisoso22_tn);
    int cw = u8g2.getStrWidth(code.c_str());
    u8g2.drawStr((128 - cw) / 2, 54, code.c_str());

    int period = c.period > 0 ? c.period : 30;
    unsigned long rem = period - (utc % (unsigned long)period);
    int barW = (int)((128 * rem) / period);
    u8g2.drawBox(0, 60, barW, 3);
}

/**
 * Generic two-line message screen. `icon`, when given, is centered above
 * the text (used for the fingerprint prompt and the auth-error warning) —
 * optional and defaulted so the plain BLE-pairing / clear-confirm callers
 * below are unaffected.
 */
static void draw_message(const char *t1, const char *t2,
                         const unsigned char *icon = nullptr,
                         int icon_w = 0, int icon_h = 0)
{
    if (!t1) t1 = "";
    draw_ble_icon(STATUS_BLE_X, 0);
    draw_battery_icon(STATUS_BATTERY_X, 0, false);
    if (icon)
        u8g2.drawXBMP((128 - icon_w) / 2, 2, icon_w, icon_h, icon);
    u8g2.setFont(u8g2_font_6x12_tr);
    int w1 = u8g2.getStrWidth(t1);
    if (w1 > 120)
        draw_str_ellipsis(0, 28, t1, 128);
    else
        u8g2.drawStr((128 - w1) / 2, 28, t1);
    if (t2) {
        int w2 = u8g2.getStrWidth(t2);
        if (w2 > 120)
            draw_str_ellipsis(0, 44, t2, 128);
        else
            u8g2.drawStr((128 - w2) / 2, 44, t2);
    }
}

static void draw_enroll(void)
{
    draw_title("Enroll");
    u8g2.setFont(u8g2_font_6x12_tr);
    char line[40];
    uint8_t step = nav_system_enroll_step();
    if (nav_system_enroll_remove()) {
        snprintf(line, sizeof(line), "%u/2 lift", (unsigned)step);
        u8g2.drawStr(0, 40, line);
        u8g2.drawStr(0, 54, "Lift finger");
    } else {
        snprintf(line, sizeof(line), "%u/2 place", (unsigned)step);
        u8g2.drawStr(0, 40, line);
        u8g2.drawStr(0, 54, "Press firmly");
    }
    u8g2.drawFrame(0, 58, 128, 5);
    int fill = (step >= 2 && !nav_system_enroll_remove()) ? 128 : (step == 1 ? 40 : 80);
    if (nav_system_enroll_remove() && step == 1) fill = 64;
    u8g2.drawBox(0, 58, fill, 5);
}

static void draw_piv_pin(void)
{
    draw_title("PIV Login PIN");
    draw_icon_state(0, 18, icon_lock_bits, ICON_LOCK_W, ICON_LOCK_H, true);
    u8g2.setFont(u8g2_font_6x12_tr);
    u8g2.drawStr(16, 27, "PIN  123456");

    u8g2.setFont(u8g2_font_5x7_tr);
#if CRYPTICK_BLE_FIDO
    bool hidc = ble_hid_keyboard_is_connected();
    draw_icon_state(0, 36, icon_ble_bits, ICON_BLE_W, ICON_BLE_H, hidc);
    draw_str_ellipsis(15, 44, hidc ? "Connected" : "Offline", 113);
    draw_str_ellipsis(0, 58,
                      hidc ? "[OK] Auto-type into host" : "Pair, or type 123456 by hand",
                      128);
#else
    u8g2.drawStr(0, 40, "NIST default - Slot 9A");
    u8g2.drawStr(0, 54, "Enter manually on host");
#endif
}

static void draw_fido_prompt(void)
{
    const char *label = nav_system_fido_label();
    draw_title("Confirm");
    u8g2.setFont(u8g2_font_6x12_tr);
    if (label && label[0] && strcmp(label, "FIDO") != 0) {
        int lw = u8g2.getStrWidth(label);
        if (lw > 120)
            draw_str_ellipsis(4, 32, label, 120);
        else
            u8g2.drawStr((128 - lw) / 2, 32, label);

        u8g2.setFont(u8g2_font_5x7_tr);
        const char *sub = "Touch sensor to confirm";
        int sw = u8g2.getStrWidth(sub);
        u8g2.drawStr((128 - sw) / 2, 48, sub);

        const char *hint = "Left = Cancel";
        int hw = u8g2.getStrWidth(hint);
        u8g2.drawStr((128 - hw) / 2, 58, hint);
    } else {
        const char *m = "WebAuthn / FIDO";
        int mw = u8g2.getStrWidth(m);
        u8g2.drawStr((128 - mw) / 2, 32, m);

        u8g2.setFont(u8g2_font_5x7_tr);
        const char *sub = "Place finger on sensor";
        int sw = u8g2.getStrWidth(sub);
        u8g2.drawStr((128 - sw) / 2, 48, sub);

        const char *hint = "Left = Cancel";
        int hw = u8g2.getStrWidth(hint);
        u8g2.drawStr((128 - hw) / 2, 58, hint);
    }
}

static void draw_fido_processing(void)
{
    const char *label = nav_system_fido_label();
    if (label && label[0] && strcmp(label, "FIDO") != 0) {
        draw_title("Processing");
        u8g2.setFont(u8g2_font_6x12_tr);
        int lw = u8g2.getStrWidth(label);
        if (lw > 120)
            draw_str_ellipsis(4, 32, label, 120);
        else
            u8g2.drawStr((128 - lw) / 2, 32, label);

        u8g2.setFont(u8g2_font_5x7_tr);
        const char *sub = "Working... please wait";
        int sw = u8g2.getStrWidth(sub);
        u8g2.drawStr((128 - sw) / 2, 48, sub);
    } else {
        draw_message("Working...", "Please wait");
    }
}

static void draw_fido_success(void)
{
    const char *label = nav_system_fido_label();
    if (!label || !label[0] || strcmp(label, "FIDO") == 0) {
        draw_title("Success");
        u8g2.setFont(u8g2_font_6x12_tr);
        const char *m = "OK";
        int mw = u8g2.getStrWidth(m);
        u8g2.drawStr((128 - mw) / 2, 36, m);
        u8g2.setFont(u8g2_font_5x7_tr);
        const char *sub = "Success";
        int sw = u8g2.getStrWidth(sub);
        u8g2.drawStr((128 - sw) / 2, 50, sub);
        return;
    }

    const char *sep = strchr(label, '|');
    if (sep) {
        /* OATH confirmation: shows account label and 6-digit TOTP code */
        char account[48];
        size_t alen = (size_t)(sep - label);
        if (alen >= sizeof(account)) alen = sizeof(account) - 1;
        memcpy(account, label, alen);
        account[alen] = 0;
        const char *code = sep + 1;

        draw_title("TOTP Code");
        u8g2.setFont(u8g2_font_5x7_tr);
        int aw = u8g2.getStrWidth(account);
        if (aw > 120)
            draw_str_ellipsis(4, 25, account, 120);
        else
            u8g2.drawStr((128 - aw) / 2, 25, account);

        u8g2.setFont(u8g2_font_logisoso22_tn);
        int cw = u8g2.getStrWidth(code);
        u8g2.drawStr((128 - cw) / 2, 52, code);
        return;
    }

    /* WebAuthn confirmation: shows relying party ID */
    draw_title("Authorized");
    u8g2.setFont(u8g2_font_6x12_tr);
    int lw = u8g2.getStrWidth(label);
    if (lw > 120)
        draw_str_ellipsis(4, 34, label, 120);
    else
        u8g2.drawStr((128 - lw) / 2, 34, label);

    u8g2.setFont(u8g2_font_5x7_tr);
    const char *sub = "Transaction Confirmed";
    int sw = u8g2.getStrWidth(sub);
    u8g2.drawStr((128 - sw) / 2, 50, sub);
}

static void render(void)
{
    if (!_oled_ok)
        return;

    uint32_t utc = get_synced_utc();
    UiState st = nav_system_state();

    /* draw_totp() walks the shared credential vector; keep core 0 out of it. */
    CredentialLock creds_guard;
    i2c_lock();
    u8g2.clearBuffer();

    switch (st) {
    case UI_CLOCK:
        draw_home(utc);
        break;
    case UI_MENU: {
        static const char *items[] = { "TOTP", "PIV Login PIN", "Bluetooth", "Settings" };
        draw_menu_list(items, 4, nav_system_menu_index());
        break;
    }
    case UI_PIV_PIN:
        draw_piv_pin();
        break;
    case UI_BLE_MENU:
        draw_ble_menu();
        break;
    case UI_TOTP:
        draw_totp(utc);
        break;
    case UI_SETTINGS:
        draw_settings();
        break;
    case UI_AUTH_PROMPT:
        draw_message("Place finger", "to unlock", icon_fingerprint_bits,
                     ICON_FINGERPRINT_W, ICON_FINGERPRINT_H);
        break;
    case UI_AUTH_ERROR: {
        const char *m = nav_system_enroll_message();
        draw_message(m && m[0] ? m : "Fingerprint",
                     m && m[0] && strcmp(m, "No match") == 0 ? "try again" : "",
                     icon_warning_bits, ICON_WARNING_W, ICON_WARNING_H);
        break;
    }
    case UI_FP_ENROLL:
        draw_enroll();
        break;
    case UI_FP_CLEAR_CONFIRM:
        draw_message("Clear all FP?", "OK=Yes  Left=No");
        break;
    case UI_FIDO_PROMPT:
        draw_fido_prompt();
        break;
    case UI_BLE_PAIRING:
        /* Caption carries the 6 digits; the host prompts for them. */
        draw_message(nav_system_fido_label(), "Type on host");
        break;
    case UI_FIDO_PROCESSING:
        draw_fido_processing();
        break;
    case UI_FIDO_SUCCESS:
        draw_fido_success();
        break;
    case UI_DEVICE_INFO:
        draw_device_info();
        break;
    case UI_SLEEP:
        /* Panel is powered down; display_system_tick() never gets us here. */
        break;
    }

    u8g2.sendBuffer();
    i2c_unlock();
}

static bool oled_try_begin(uint8_t addr7)
{
    CLOG_D("DISP", "begin SSD1306 @0x%02X…", addr7);
    CryptickLog.flush();
    u8g2.setI2CAddress(addr7 << 1);
    u8g2.setBusClock(100000);
    for (int attempt = 0; attempt < 3; attempt++) {
        CLOG_D("DISP", "u8g2.begin attempt %d", attempt + 1);
        CryptickLog.flush();
        if (u8g2.begin()) {
            u8g2.setPowerSave(0);
            u8g2.setContrast(255);
            u8g2.clearBuffer();
            u8g2.sendBuffer();
            _oled_addr = addr7;
            CLOG_I("DISP", "u8g2.begin OK");
            CryptickLog.flush();
            return true;
        }
        CLOG_D("DISP", "u8g2.begin returned false");
        CryptickLog.flush();
        delay(40);
        Wire.begin(OLED_SDA, OLED_SCL);
        Wire.setClock(100000);
        Wire.setTimeOut(100);
        yield();
    }
    return false;
}

/**
 * Bring the panel up. `splash` runs the cosmetic white-flash + boot text, which
 * costs ~280 ms and is only wanted on the first attempt — the retry path in
 * display_system_tick() runs from the main loop and must stay cheap.
 */
static void display_bring_up(bool splash)
{
    i2c_lock();
    /* Soft bus recovery (do not leave pins as hard GPIO after) */
    pinMode(OLED_SCL, OUTPUT_OPEN_DRAIN);
    pinMode(OLED_SDA, INPUT_PULLUP);
    for (int i = 0; i < 9; i++) {
        digitalWrite(OLED_SCL, HIGH);
        delayMicroseconds(5);
        digitalWrite(OLED_SCL, LOW);
        delayMicroseconds(5);
    }
    digitalWrite(OLED_SCL, HIGH);
    delayMicroseconds(5);

    Wire.begin(OLED_SDA, OLED_SCL);
    Wire.setTimeOut(100);
    Wire.setClock(100000);
    delay(20);

    uint8_t found = 0;
    bool saw_3c = false, saw_3d = false;
    bool saw_68 = false;
    for (uint8_t a = 1; a < 127; a++) {
        Wire.beginTransmission(a);
        uint8_t err = Wire.endTransmission();
        if (err == 0) {
            CLOG_D("I2C", "device 0x%02X", a);
            found++;
            if (a == 0x3C) saw_3c = true;
            if (a == 0x3D) saw_3d = true;
            if (a == 0x68) saw_68 = true;
        }
        if ((a & 0x1f) == 0)
            yield();
    }
    CryptickLog.flush();
    if (!found)
        CLOG_D("I2C", "no devices — check SDA/SCL / 3V3 / OLED solder");
    else
        CLOG_D("I2C", "%u device(s) OLED3C=%d OLED3D=%d RTC68=%d",
                           (unsigned)found, (int)saw_3c, (int)saw_3d, (int)saw_68);
    CryptickLog.flush();

    /* Release mutex for u8g2 init (Wire calls can yield); re-take after */
    i2c_unlock();

    _oled_ok = false;
    if (saw_3c && oled_try_begin(0x3C))
        _oled_ok = true;
    else if (saw_3d && oled_try_begin(0x3D))
        _oled_ok = true;
    else if (oled_try_begin(0x3C))
        _oled_ok = true;
    else if (oled_try_begin(0x3D))
        _oled_ok = true;

    if (!_oled_ok) {
        CLOG_E("DISP", "FAIL SDA=%d SCL=%d (no SSD1306 ACK)",
                           OLED_SDA, OLED_SCL);
        CryptickLog.flush();
        return;
    }

    i2c_lock();
    Wire.setClock(100000);
    u8g2.setBusClock(100000);
    u8g2.setPowerSave(0);
    u8g2.setContrast(255);
    if (splash) {
        /*
         * Brief all-white frame. This is a panel test, not decoration: if the
         * glass is alive but the content is wrong you still see this flash.
         * The actual intro is display_system_boot_animation().
         */
        u8g2.clearBuffer();
        u8g2.drawBox(0, 0, 128, 64);
        u8g2.sendBuffer();
        delay(60);
        u8g2.clearBuffer();
        u8g2.sendBuffer();
    }
    i2c_unlock();

    CLOG_I("DISP", "OK  SSD1306 @0x%02X  SDA=%d SCL=%d",
                       _oled_addr, OLED_SDA, OLED_SCL);
    CryptickLog.flush();
    _dirty = true;
}

void display_system_init(void)
{
    display_bring_up(true);
}

/*
 * Opening animation. A seam of light opens, unfolds into a badge, the wordmark
 * wipes in, then a rule fills while the rest of setup() is still ahead.
 *
 * Deliberately built from primitives (lines, frames, a clip window) instead of
 * a bitmap: it costs no flash for assets, and every delay is derived from
 * BOOT_ANIM_MS so the whole thing stays inside its stated budget.
 */
void display_system_boot_animation(void)
{
#if BOOT_ANIM_MS > 0
    if (!_oled_ok)
        return;

    const int cx = 64, cy = 32;
    const int fw = 116, fh = 40;
    const int fx = cx - fw / 2, fy = cy - fh / 2;
    const int frames = 46;
    const int unit = BOOT_ANIM_MS / frames;

    const char *word = "CRYPTICK";
    const char *sub = "TOKEN";

    i2c_lock();

    /* 1 — a seam opens along the centre line. */
    for (int i = 1; i <= 12; i++) {
        int w = (fw * i) / 12;
        u8g2.clearBuffer();
        u8g2.drawHLine(cx - w / 2, cy, w);
        u8g2.sendBuffer();
        delay(unit);
    }

    /* 2 — the seam unfolds into the badge outline. */
    for (int i = 1; i <= 8; i++) {
        int h = (fh * i) / 8;
        u8g2.clearBuffer();
        u8g2.drawFrame(fx, cy - h / 2, fw, h);
        u8g2.sendBuffer();
        delay(unit);
    }

    u8g2.setFont(u8g2_font_7x14B_tr);
    int ww = u8g2.getStrWidth(word);
    int wx = cx - ww / 2;

    /* 3 — wordmark wipes in left to right. */
    for (int i = 1; i <= 14; i++) {
        u8g2.clearBuffer();
        u8g2.drawFrame(fx, fy, fw, fh);
        u8g2.setClipWindow(wx, cy - 14, wx + (ww * i) / 14, cy + 2);
        u8g2.setFont(u8g2_font_7x14B_tr);
        u8g2.drawStr(wx, cy, word);
        u8g2.setMaxClipWindow();
        u8g2.sendBuffer();
        delay(unit);
    }

    /* 4 — subtitle holds while a rule fills underneath. */
    u8g2.setFont(u8g2_font_5x7_tr);
    int sw = u8g2.getStrWidth(sub);
    for (int i = 0; i <= 12; i++) {
        u8g2.clearBuffer();
        u8g2.drawFrame(fx, fy, fw, fh);
        u8g2.setFont(u8g2_font_7x14B_tr);
        u8g2.drawStr(wx, cy, word);
        u8g2.setFont(u8g2_font_5x7_tr);
        u8g2.drawStr(cx - sw / 2, cy + 14, sub);
        u8g2.drawBox(fx, fy + fh + 4, (fw * i) / 12, 2);
        u8g2.sendBuffer();
        delay(unit);
    }

    i2c_unlock();
    _dirty = true;
#endif
}

void display_system_set_credentials(const std::vector<TOTPCredential> *creds)
{
    if (_creds != creds) {
        _creds = creds;
        _dirty = true;
    }
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
    /*
     * Track the sleep edge before anything else. Entering UI_SLEEP powers the
     * panel down and then we do no work at all — no redraws, and no I2C
     * rescans, which is the whole point of sleeping.
     */
    bool want_sleep = (nav_system_state() == UI_SLEEP);
    if (want_sleep != _asleep) {
        _asleep = want_sleep;
        if (_oled_ok) {
            i2c_lock();
            u8g2.setPowerSave(_asleep ? 1 : 0);
            i2c_unlock();
        }
        CLOG_I("DISP", _asleep ? "panel off (sleep)" : "panel on (wake)");
        if (!_asleep) {
            _dirty = true;
            _lastDraw = 0;
        }
    }
    if (_asleep)
        return;

    /*
     * Soft retry if begin failed (loose cable / power). Each attempt scans the
     * whole I2C bus, so back off towards 30 s: with a permanently absent panel
     * a fixed 2 s retry burned ~15% of every loop iteration forever.
     */
    if (!_oled_ok && nowMs - _lastReinit >= _reinitBackoffMs) {
        _lastReinit = nowMs;
        CLOG_W("DISP", "no panel SDA=%d SCL=%d — retry in %lus",
               OLED_SDA, OLED_SCL, _reinitBackoffMs / 1000UL);
        display_bring_up(false);
        if (_oled_ok)
            _reinitBackoffMs = DISPLAY_REINIT_MIN_MS;
        else if (_reinitBackoffMs < DISPLAY_REINIT_MAX_MS)
            _reinitBackoffMs *= 2;
    }

    UiState st = nav_system_state();
    _charge = battery_system_state();

    bool urgent = (st == UI_FIDO_PROMPT || st == UI_FIDO_PROCESSING || st == UI_FP_ENROLL ||
                   st == UI_AUTH_PROMPT || st == UI_BLE_PAIRING ||
                   _charge == CHARGE_CHARGING);
    unsigned long interval = urgent ? 350UL : (unsigned long)DISPLAY_UPDATE_INTERVAL;
    if (st == UI_TOTP || st == UI_CLOCK)
        interval = (_charge == CHARGE_CHARGING) ? 350UL : 1000UL;

    bool due = (nowMs - _lastDraw >= interval);
    if (!_dirty && !due) return;
    CLOG_T("DISP", "render ui=%u dirty=%d due=%d charge=%u",
           (unsigned)st, _dirty ? 1 : 0, due ? 1 : 0, (unsigned)_charge);
    render();
    _lastDraw = nowMs;
    _dirty = false;
}
