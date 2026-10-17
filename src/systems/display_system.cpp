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
#endif
#include <stdio.h>
#include <string.h>
#include "display_icons.h"
#include "display_driver.h"
#include "display_driver_u8g2.h"

/*
 * This file used to call U8g2's own API (u8g2.drawStr/drawBox/setFont/...)
 * directly from every screen-drawing function below. It now goes through
 * the DisplayDriver interface (display_driver.h) instead — `gfx` is the
 * only handle to the display this file uses. The current small OLED is
 * still the only thing on the other end of it (U8g2DisplayDriver, in
 * display_driver_u8g2.cpp/.h, which owns the U8g2 object and all of its
 * I2C bring-up/retry detail), but nothing below this line knows that: a
 * future larger-panel/LVGL backend is a second DisplayDriver
 * implementation, swapped in here, with none of the screens below needing
 * to change. See NOTES.md for the interface shape and what a new backend
 * would need to cover.
 */
static U8g2DisplayDriver g_driverImpl;
static DisplayDriver &gfx = g_driverImpl;

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

/*
 * Truncation marker. Every font this file uses (u8g2_font_*_tr/_tn) is built
 * with "Glyphs: 95/N" in its own header comment in U8g2's font table — the
 * 95 printable ASCII characters, 0x20-0x7E, and nothing else. gfx.drawText()
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
    int w = gfx.textWidth(s);
    if (w <= maxW) {
        gfx.drawText(x, y, s);
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
        if (gfx.textWidth(tmp) <= maxW) {
            gfx.drawText(x, y, tmp);
            return;
        }
    }
    gfx.drawText(x, y, kEllipsis);
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
    gfx.drawBitmap(x, y, w, h, bits);
    if (!ok)
        gfx.drawLine(x, y, x + w - 1, y + h - 1);
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
    gfx.drawBitmap(x, y, ICON_BATTERY_W, ICON_BATTERY_H, icon_battery_shell_bits);

    switch (_charge) {
    case CHARGE_CHARGING: {
        int phase = (int)((millis() / 350) % 4);
        int fill = 3 + phase * 3;
        if (fill > 14) fill = 14;
        gfx.fillRect(x + 2, y + 2, fill, 5);
        gfx.drawLine(x + 8, y + 1, x + 11, y + 4);
        gfx.drawLine(x + 11, y + 4, x + 9, y + 4);
        gfx.drawLine(x + 9, y + 4, x + 12, y + 8);
        break;
    }
    case CHARGE_DONE:
        gfx.fillRect(x + 2, y + 2, 14, 5);
        break;
    case CHARGE_FAULT:
        gfx.drawLine(x + 3, y + 1, x + 15, y + 7);
        gfx.drawLine(x + 15, y + 1, x + 3, y + 7);
        break;
    default:
        gfx.fillRect(x + 2, y + 2, 7, 5);
        break;
    }

    if (with_label) {
        gfx.setFont(DisplayFont::Small);
        const char *lab = battery_system_label();
        if (lab && lab[0]) {
            int lw = gfx.textWidth(lab);
            gfx.drawText(x - lw - 2, y + 7, lab);
        }
    }
}

static void draw_status_bar(uint32_t utc)
{
    char date_str[16], time_str[10];
    format_time(utc, date_str, sizeof(date_str), time_str, sizeof(time_str));
    gfx.setFont(DisplayFont::Small);
    gfx.drawText(0, 7, date_str);
    draw_ble_icon(STATUS_BLE_X, 0);
    draw_battery_icon(STATUS_BATTERY_X, 0, true);
}

static void draw_title(const char *title)
{
    gfx.setFont(DisplayFont::Medium);
    draw_str_ellipsis(0, 12, title, TITLE_SAFE_W);
    gfx.drawHLine(0, 14, 128);
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
        gfx.fillRect(0, y - 10, boxW, 13);
        gfx.setInverted(true);
        draw_str_ellipsis(4, y, text, maxW);
        gfx.setInverted(false);
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
    gfx.drawVLine(126, trackY, trackH);
    gfx.fillRect(124, thumbY, 4, thumbH);
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
    gfx.setFont(DisplayFont::Medium);
    int first = list_first_row(count, selected);
    for (int r = 0; r < LIST_ROWS && (first + r) < count; r++)
        draw_list_row(r, items[first + r], (first + r) == selected, 120);
    draw_scrollbar(count, first);
}

static void draw_settings(void)
{
    draw_title("Settings");
    gfx.setFont(DisplayFont::Medium);

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
        gfx.setInverted(true);
        gfx.fillRect(12, 20, 104, 25);
        gfx.setInverted(false);
        gfx.drawRect(12, 20, 104, 25);
        gfx.setFont(DisplayFont::Medium);
        int mw = gfx.textWidth(msg);
        gfx.drawText((128 - mw) / 2, 36, msg);
    }
}

static void draw_ble_menu(void)
{
    draw_title("Bluetooth");
    gfx.setFont(DisplayFont::Small);

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

    gfx.drawHLine(0, 30, 128);

    int count = nav_system_ble_menu_count();
    int sel = nav_system_ble_menu_index();
    int first = list_first_row(count, sel);

    gfx.setFont(DisplayFont::Medium);
    /* Row 0 is the status line above; action items start at row 1. */
    for (int r = 0; r < LIST_ROWS - 1 && (first + r) < count; r++) {
        char act_label[32];
        nav_system_ble_menu_label(first + r, act_label, sizeof(act_label));
        draw_list_row(r + 1, act_label, (first + r) == sel, 120);
    }
    draw_scrollbar(count, first);
#else
    gfx.drawText(0, 35, "BLE not supported");
#endif

    const char *msg = nav_system_enroll_message();
    if (msg && msg[0]) {
        gfx.setInverted(true);
        gfx.fillRect(12, 20, 104, 25);
        gfx.setInverted(false);
        gfx.drawRect(12, 20, 104, 25);
        gfx.setFont(DisplayFont::Medium);
        int mw = gfx.textWidth(msg);
        gfx.drawText((128 - mw) / 2, 36, msg);
    }
}

static void draw_device_info(void)
{
    draw_title("Device info");
    gfx.setFont(DisplayFont::Small);

    char line[36];
    /* 5 rows now fit under the title bar (y=14) with a 9px pitch — a 10px
     * pitch starting at 25 (the 4-row layout) would push the 5th row past
     * the 64px panel height. */
    int y = 23;
    const int step = 9;

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

    y += step;
    snprintf(line, sizeof(line), "FP   %s  %u tpl",
             fp_system_ready() ? "ready" : "absent",
             (unsigned)fp_system_template_count());
    draw_str_ellipsis(0, y, line, 128);

    y += step;
    snprintf(line, sizeof(line), "OATH %d accounts", nav_system_account_count());
    draw_str_ellipsis(0, y, line, 128);

    /*
     * Settings used to have a separate "Clock: RTC OK / Soft (Sync!)" row,
     * but it pointed at this same screen, which never showed any clock
     * content — folded in here instead of leaving that row's label
     * pointing at nothing (see the SettingsItem comment in nav_system.cpp).
     * There is no on-device sync action: SETTIME / OATH SET_TIME only come
     * from the USB console (src/host/serial_comm.cpp).
     */
    y += step;
    extern bool g_rtc_ok __attribute__((weak));
    bool rtc_ok = (&g_rtc_ok != nullptr) ? g_rtc_ok : false;
    snprintf(line, sizeof(line), "Clk  %s", rtc_ok ? "RTC OK" : "Soft (SETTIME/USB)");
    gfx.drawText(0, y, line);

    y += step;
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
    gfx.setFont(DisplayFont::Small);
    gfx.drawText(0, 7, date_str);
    draw_ble_icon(STATUS_BLE_X, 0);
    draw_battery_icon(STATUS_BATTERY_X, 0, true);

    gfx.setFont(DisplayFont::LargeDigits);
    int tw = gfx.textWidth(time_str);
    gfx.drawText((128 - tw) / 2, 42, time_str);

    gfx.setFont(DisplayFont::Medium);
    draw_str_ellipsis(0, 60, _user, 80);
    /* A real glyph, struck through when absent, in place of "FP" / "-" text. */
    draw_icon_state(112, 50, icon_fingerprint_bits, ICON_FINGERPRINT_W,
                    ICON_FINGERPRINT_H, fp_system_ready());
}

/**
 * Home "Quick PIV Login" card: launches the same PIV PIN entry ceremony
 * (UI_PIV_PIN_ENTRY — draw_piv_pin_entry() below, nav_system.cpp's
 * enter_piv_pin_entry()) as Menu -> PIV Login PIN. There used to be a fixed
 * demo PIN here that a single CENTER press auto-typed with no confirmation
 * at all (draw_piv_pin_screen, shared verbatim with the Menu screen — see
 * NOTES.md); replaced because the PIN is now chosen by hand on the entry
 * screen, not fixed in advance, so there is no code value left to preview
 * the way the Quick-TOTP card previews a live one. This is just a launcher.
 */
static void draw_piv_pin_launch_card(void)
{
    draw_title("Quick PIV Login");
    gfx.setFont(DisplayFont::Medium);
    gfx.drawText(0, 30, "Press OK to enter PIN");
    gfx.setFont(DisplayFont::Small);
    gfx.drawText(0, 48, "Then confirm with your");
    gfx.drawText(0, 58, "fingerprint to send it");
}

/**
 * PIV PIN entry (UI_PIV_PIN_ENTRY) — see nav_system.cpp's
 * enter_piv_pin_entry() / commit_piv_pin_type(). Digit boxes reuse
 * draw_list_row()'s selected-row look (filled box, inverted text) for the
 * one currently being set, the same inversion idiom this file already uses
 * for every other kind of selection instead of inventing a caret or
 * underline just for this screen. The encoder is remapped to KEY_UP/
 * KEY_DOWN by nav_system.cpp's global remap, so "Scroll" below is literally
 * true for both the encoder and the 5-way UP/DOWN.
 */
static void draw_piv_pin_entry(void)
{
    draw_title("Enter PIV PIN");

    int len = nav_system_piv_pin_len();
    int pos = nav_system_piv_pin_pos();
    const int boxW = 16, boxH = 20, y0 = 18;
    int x0 = (128 - boxW * len) / 2;

    gfx.setFont(DisplayFont::Medium);
    for (int i = 0; i < len; i++) {
        int x = x0 + i * boxW;
        char ch[2] = { (char)('0' + nav_system_piv_pin_digit(i)), 0 };
        int cw = gfx.textWidth(ch);
        int tx = x + (boxW - cw) / 2;
        int ty = y0 + boxH - 6;
        if (i == pos) {
            gfx.fillRect(x + 1, y0, boxW - 2, boxH);
            gfx.setInverted(true);
            gfx.drawText(tx, ty, ch);
            gfx.setInverted(false);
        } else {
            gfx.drawRect(x + 1, y0, boxW - 2, boxH);
            gfx.drawText(tx, ty, ch);
        }
    }

    gfx.setFont(DisplayFont::Small);
    const char *hint1 = "Scroll = digit  Left = back";
    gfx.drawText((128 - gfx.textWidth(hint1)) / 2, 50, hint1);
    const char *hint2 = (pos + 1 < len) ? "OK = next digit"
                                        : "OK = confirm + touch";
    gfx.drawText((128 - gfx.textWidth(hint2)) / 2, 60, hint2);
}

/**
 * Bottom row shared by the Home "Quick TOTP" card and the Menu → TOTP list
 * screen (draw_totp below) — see finding #9: draw_totp had no button hint
 * at all even though its KEY_CENTER does the same BLE-type action as the
 * card, and the two disagreed on text-countdown vs progress-bar. Standardizing
 * on the bar: it already existed on draw_totp, and a right-aligned "NNs"
 * string has to fight the hint text for the same 128px-wide row, which the
 * bar does not.
 */
static void draw_totp_bottom_row(uint32_t utc, int period)
{
    if (period <= 0) period = 30;
    gfx.setFont(DisplayFont::Small);
    gfx.drawText(0, 58, "[OK] Type Code");
    unsigned long rem = (unsigned long)period - (utc % (unsigned long)period);
    int barW = (int)((128UL * rem) / (unsigned long)period);
    gfx.fillRect(0, 60, barW, 3);
}

/**
 * Minimal page indicator for the 3-card Home carousel (finding #7): a
 * filled square for the current card, hollow for the others. There is no
 * row free across all three card layouts at the full screen width — card
 * 1's button-hint box and card 2's bottom row both already span edge to
 * edge — so this lives in the gap between the status/title bar and each
 * card's own content, right of where the Quick-TOTP header is capped (see
 * the narrowed ellipsis width below) to guarantee the column stays clear.
 */
static void draw_home_dots(int card)
{
    const int y = 15, x0 = 116, step = 4, size = 3;
    for (int i = 0; i < 3; i++) {
        int x = x0 + i * step;
        if (i == card)
            gfx.fillRect(x, y, size, size);
        else
            gfx.drawRect(x, y, size, size);
    }
}

static void draw_home(uint32_t utc)
{
    int card = nav_system_home_card();
    if (card == 1) {
        draw_piv_pin_launch_card();
    } else if (card == 2) {
        /* Quick TOTP Card */
        draw_status_bar(utc);
        if (!_creds || _creds->empty()) {
            gfx.setFont(DisplayFont::Medium);
            gfx.drawText(0, 30, "No TOTP accounts");
            gfx.setFont(DisplayFont::Small);
            gfx.drawText(0, 44, "Add via Extension");
        } else {
            int idx = nav_system_account_index();
            if (idx < 0 || idx >= (int)_creds->size()) idx = 0;
            const TOTPCredential &c = (*_creds)[idx];
            String code = totp_generate(c, utc);

            char hdr[32];
            snprintf(hdr, sizeof(hdr), "TOTP %d/%d", idx + 1, (int)_creds->size());
            gfx.setFont(DisplayFont::Small);
            gfx.drawText(0, 18, hdr);
            int hx = gfx.textWidth(hdr);
            /* Capped short of 128 (not the 124 draw_totp's own header
             * allows) so a long account label can't paint into the page
             * dots' column at x>=116. */
            draw_str_ellipsis(hx + 4, 18, c.label.length() ? c.label.c_str() : "Account", 112 - hx);

            gfx.setFont(DisplayFont::LargeDigits);
            int cw = gfx.textWidth(code.c_str());
            gfx.drawText((128 - cw) / 2, 46, code.c_str());

            draw_totp_bottom_row(utc, c.period);
        }
    } else {
        draw_clock(utc);
    }

    draw_home_dots(card);

    const char *msg = nav_system_enroll_message();
    if (msg && msg[0]) {
        gfx.setInverted(true);
        gfx.fillRect(10, 20, 108, 26);
        gfx.setInverted(false);
        gfx.drawRect(10, 20, 108, 26);
        gfx.setFont(DisplayFont::Medium);
        int mw = gfx.textWidth(msg);
        gfx.drawText((128 - mw) / 2, 37, msg);
    }
}

static void draw_totp(uint32_t utc)
{
    draw_status_bar(utc);
    if (!_creds || _creds->empty()) {
        draw_title("TOTP");
        gfx.setFont(DisplayFont::Medium);
        gfx.drawText(0, 40, "No accounts");
        gfx.drawText(0, 54, "Add via HID app");
        return;
    }
    int idx = nav_system_account_index();
    if (idx < 0 || idx >= (int)_creds->size()) idx = 0;
    const TOTPCredential &c = (*_creds)[idx];
    String code = totp_generate(c, utc);

    char header[48];
    snprintf(header, sizeof(header), "%d/%d ",
             idx + 1, (int)_creds->size());
    gfx.setFont(DisplayFont::Small);
    gfx.drawText(0, 16, header);
    int hx = gfx.textWidth(header);
    draw_str_ellipsis(hx, 16,
                      c.label.length() ? c.label.c_str() : "Account",
                      128 - hx);

    const char *issuer = c.issuer.length() ? c.issuer.c_str() : "-";
    draw_str_ellipsis(0, 25, issuer, 128);

    /*
     * Shifted up from the old baseline (54 → 48) to leave room below for
     * the bottom-row hint added by finding #9 — draw_totp has an issuer
     * line the Home quick-card doesn't, so it can't reuse the card's exact
     * y-coordinates and still clear its own code digits.
     */
    gfx.setFont(DisplayFont::LargeDigits);
    int cw = gfx.textWidth(code.c_str());
    gfx.drawText((128 - cw) / 2, 48, code.c_str());

    draw_totp_bottom_row(utc, c.period);
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
        gfx.drawBitmap((128 - icon_w) / 2, 2, icon_w, icon_h, icon);
    gfx.setFont(DisplayFont::Medium);
    int w1 = gfx.textWidth(t1);
    if (w1 > 120)
        draw_str_ellipsis(0, 28, t1, 128);
    else
        gfx.drawText((128 - w1) / 2, 28, t1);
    if (t2) {
        int w2 = gfx.textWidth(t2);
        if (w2 > 120)
            draw_str_ellipsis(0, 44, t2, 128);
        else
            gfx.drawText((128 - w2) / 2, 44, t2);
    }
}

static void draw_enroll(void)
{
    draw_title("Enroll");
    gfx.setFont(DisplayFont::Medium);
    char line[40];
    uint8_t step = nav_system_enroll_step();
    if (nav_system_enroll_remove()) {
        snprintf(line, sizeof(line), "%u/2 lift", (unsigned)step);
        gfx.drawText(0, 40, line);
        gfx.drawText(0, 54, "Lift finger");
    } else {
        snprintf(line, sizeof(line), "%u/2 place", (unsigned)step);
        gfx.drawText(0, 40, line);
        gfx.drawText(0, 54, "Press firmly");
    }
    gfx.drawRect(0, 58, 128, 5);
    int fill = (step >= 2 && !nav_system_enroll_remove()) ? 128 : (step == 1 ? 40 : 80);
    if (nav_system_enroll_remove() && step == 1) fill = 64;
    gfx.fillRect(0, 58, fill, 5);
}

/*
 * draw_fido_prompt / draw_fido_processing below both name the CENTER button
 * "OK" (finding #12 — "OK" is the majority usage elsewhere, so it is the
 * one picked; the physical silkscreen/board_config.h name "CENTER" never
 * appears on screen anywhere, including here).
 */
static void draw_fido_prompt(void)
{
    const char *label = nav_system_fido_label();
    bool custom = (label && label[0] && strcmp(label, "FIDO") != 0);
    const char *headline = custom ? label : "WebAuthn / FIDO";
    const char *sub = custom ? "Touch sensor to confirm" : "Place finger on sensor";

    draw_title("Confirm");
    gfx.setFont(DisplayFont::Medium);
    int lw = gfx.textWidth(headline);
    if (lw > 120)
        draw_str_ellipsis(4, 28, headline, 120);
    else
        gfx.drawText((128 - lw) / 2, 28, headline);

    gfx.setFont(DisplayFont::Small);
    int sw = gfx.textWidth(sub);
    gfx.drawText((128 - sw) / 2, 40, sub);

    /*
     * CENTER now also confirms presence (nav_system.cpp UI_FIDO_PROMPT
     * KEY_CENTER), the same ceremony a fingerprint match triggers — this
     * hint used to show only "Left = Cancel", the one place on this screen
     * that never mentioned the OK/CENTER button at all (finding #12).
     */
    const char *hint1 = "OK = Confirm";
    int h1w = gfx.textWidth(hint1);
    gfx.drawText((128 - h1w) / 2, 50, hint1);

    const char *hint2 = "Left = Cancel";
    int h2w = gfx.textWidth(hint2);
    gfx.drawText((128 - h2w) / 2, 60, hint2);
}

static void draw_fido_processing(void)
{
    /*
     * Always draw_title(...) now (finding #10) — this used to switch to the
     * no-title-bar draw_message() chrome whenever the default "FIDO" label
     * was active, so the exact same UiState rendered two different frames
     * depending on data content instead of state. Sibling UI_FIDO_PROMPT /
     * UI_FIDO_SUCCESS both always use draw_title(), so this now matches.
     */
    const char *label = nav_system_fido_label();
    bool custom = (label && label[0] && strcmp(label, "FIDO") != 0);
    const char *headline = custom ? label : "Working…";
    const char *sub = custom ? "Working… Please wait" : "Please wait";

    draw_title("Processing");
    gfx.setFont(DisplayFont::Medium);
    int lw = gfx.textWidth(headline);
    if (lw > 120)
        draw_str_ellipsis(4, 32, headline, 120);
    else
        gfx.drawText((128 - lw) / 2, 32, headline);

    gfx.setFont(DisplayFont::Small);
    int sw = gfx.textWidth(sub);
    gfx.drawText((128 - sw) / 2, 48, sub);
}

static void draw_fido_success(void)
{
    const char *label = nav_system_fido_label();
    if (!label || !label[0] || strcmp(label, "FIDO") == 0) {
        draw_title("Success");
        gfx.setFont(DisplayFont::Medium);
        const char *m = "OK";
        int mw = gfx.textWidth(m);
        gfx.drawText((128 - mw) / 2, 36, m);
        gfx.setFont(DisplayFont::Small);
        const char *sub = "Success";
        int sw = gfx.textWidth(sub);
        gfx.drawText((128 - sw) / 2, 50, sub);
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
        gfx.setFont(DisplayFont::Small);
        int aw = gfx.textWidth(account);
        if (aw > 120)
            draw_str_ellipsis(4, 25, account, 120);
        else
            gfx.drawText((128 - aw) / 2, 25, account);

        gfx.setFont(DisplayFont::LargeDigits);
        int cw = gfx.textWidth(code);
        gfx.drawText((128 - cw) / 2, 52, code);
        return;
    }

    /* WebAuthn confirmation: shows relying party ID */
    draw_title("Authorized");
    gfx.setFont(DisplayFont::Medium);
    int lw = gfx.textWidth(label);
    if (lw > 120)
        draw_str_ellipsis(4, 34, label, 120);
    else
        gfx.drawText((128 - lw) / 2, 34, label);

    gfx.setFont(DisplayFont::Small);
    const char *sub = "Transaction Confirmed";
    int sw = gfx.textWidth(sub);
    gfx.drawText((128 - sw) / 2, 50, sub);
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
    gfx.clear();

    switch (st) {
    case UI_CLOCK:
        draw_home(utc);
        break;
    case UI_MENU: {
        static const char *items[] = { "TOTP", "PIV Login PIN", "Bluetooth", "Settings" };
        draw_menu_list(items, 4, nav_system_menu_index());
        break;
    }
    case UI_PIV_PIN_ENTRY:
        draw_piv_pin_entry();
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

    gfx.flush();
    i2c_unlock();
}
/**
 * Bring the panel up. `splash` runs the cosmetic white-flash panel self-test,
 * which costs ~280 ms and is only wanted on the first attempt — the retry
 * path in display_system_tick() runs from the main loop and must stay cheap.
 * All of the I2C bus recovery / address scan / retry detail this used to do
 * directly now lives in U8g2DisplayDriver::begin() — see display_driver_u8g2.cpp.
 */
static void display_bring_up(bool splash)
{
    _oled_ok = gfx.begin(splash);
    if (_oled_ok)
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
        gfx.clear();
        gfx.drawHLine(cx - w / 2, cy, w);
        gfx.flush();
        delay(unit);
    }

    /* 2 — the seam unfolds into the badge outline. */
    for (int i = 1; i <= 8; i++) {
        int h = (fh * i) / 8;
        gfx.clear();
        gfx.drawRect(fx, cy - h / 2, fw, h);
        gfx.flush();
        delay(unit);
    }

    gfx.setFont(DisplayFont::Bold);
    int ww = gfx.textWidth(word);
    int wx = cx - ww / 2;

    /* 3 — wordmark wipes in left to right. */
    for (int i = 1; i <= 14; i++) {
        gfx.clear();
        gfx.drawRect(fx, fy, fw, fh);
        gfx.setClip(wx, cy - 14, wx + (ww * i) / 14, cy + 2);
        gfx.setFont(DisplayFont::Bold);
        gfx.drawText(wx, cy, word);
        gfx.clearClip();
        gfx.flush();
        delay(unit);
    }

    /* 4 — subtitle holds while a rule fills underneath. */
    gfx.setFont(DisplayFont::Small);
    int sw = gfx.textWidth(sub);
    for (int i = 0; i <= 12; i++) {
        gfx.clear();
        gfx.drawRect(fx, fy, fw, fh);
        gfx.setFont(DisplayFont::Bold);
        gfx.drawText(wx, cy, word);
        gfx.setFont(DisplayFont::Small);
        gfx.drawText(cx - sw / 2, cy + 14, sub);
        gfx.fillRect(fx, fy + fh + 4, (fw * i) / 12, 2);
        gfx.flush();
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
            gfx.sleep(_asleep);
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
