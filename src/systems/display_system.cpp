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
#include <U8g2lib.h>
#include <Wire.h>
#include <stdio.h>
#include <string.h>

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
        snprintf(tmp, sizeof(tmp), "%s…", buf);
        if (u8g2.getStrWidth(tmp) <= maxW) {
            u8g2.drawStr(x, y, tmp);
            return;
        }
    }
    u8g2.drawStr(x, y, "…");
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

static void draw_charge_icon(int x, int y)
{
    u8g2.drawFrame(x, y, 18, 9);
    u8g2.drawBox(x + 18, y + 2, 2, 5);

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

    u8g2.setFont(u8g2_font_5x7_tr);
    const char *lab = battery_system_label();
    if (lab && lab[0]) {
        int lw = u8g2.getStrWidth(lab);
        u8g2.drawStr(x - lw - 2, y + 7, lab);
    }
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
    draw_str_ellipsis(0, 20, title, 100);
    u8g2.drawHLine(0, 22, 128);
    draw_charge_icon(108, 0);
}

/** Rows that fit under the title bar. */
#define LIST_ROWS 3

static void draw_list_row(int row, const char *text, bool selected, int maxW)
{
    int y = 36 + row * 12;
    if (selected) {
        u8g2.drawBox(0, y - 9, 128, 11);
        u8g2.setDrawColor(0);
        draw_str_ellipsis(4, y, text, maxW);
        u8g2.setDrawColor(1);
    } else {
        draw_str_ellipsis(4, y, text, maxW);
    }
}

/**
 * Scroll indicator for lists longer than LIST_ROWS. Without it a fourth
 * settings entry is simply invisible with no hint that it exists.
 */
static void draw_scrollbar(int count, int first)
{
    if (count <= LIST_ROWS)
        return;
    const int trackY = 26, trackH = 38;
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
    int maxW = (count > LIST_ROWS) ? 116 : 120;

    for (int r = 0; r < LIST_ROWS && (first + r) < count; r++) {
        char line[32];
        nav_system_settings_label(first + r, line, sizeof(line));
        draw_list_row(r, line, (first + r) == sel, maxW);
    }
    draw_scrollbar(count, first);

	if (msg && msg[0]) {
		/*
		 * Wipe the whole third row — including its selection highlight, which
		 * spans y 51..61 — so the status never lands on top of half a glyph.
		 */
		u8g2.setDrawColor(0);
		u8g2.drawBox(0, 51, 128, 13);
		u8g2.setDrawColor(1);
		u8g2.setFont(u8g2_font_5x7_tr);
		draw_str_ellipsis(0, 62, msg, 128);
	}
}

static void draw_device_info(void)
{
    draw_title("Device info");
    u8g2.setFont(u8g2_font_5x7_tr);

    char line[36];
    int y = 33;

    snprintf(line, sizeof(line), "USB  %s",
             usb_device_mounted() ? "1209:BEEE host" : "not mounted");
    u8g2.drawStr(0, y, line);

    y += 9;
    snprintf(line, sizeof(line), "FP   %s  %u tpl",
             fp_system_ready() ? "ready" : "absent",
             (unsigned)fp_system_template_count());
    u8g2.drawStr(0, y, line);

    y += 9;
    snprintf(line, sizeof(line), "OATH %d accounts", nav_system_account_count());
    u8g2.drawStr(0, y, line);

    y += 9;
    unsigned long up = millis() / 1000UL;
    uint16_t slp = nav_system_sleep_timeout_sec();
    if (slp)
        snprintf(line, sizeof(line), "Up %lum%02lus   Slp %us",
                 up / 60UL, up % 60UL, (unsigned)slp);
    else
        snprintf(line, sizeof(line), "Up %lum%02lus   Slp off", up / 60UL, up % 60UL);
    u8g2.drawStr(0, y, line);
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
    draw_str_ellipsis(0, 60, _user, 80);
    if (fp_system_ready())
        u8g2.drawStr(90, 60, "FP");
    else
        u8g2.drawStr(90, 60, "—");
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

static void draw_message(const char *t1, const char *t2)
{
    draw_charge_icon(108, 0);
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
        draw_message("Place finger", "to unlock");
        break;
    case UI_AUTH_ERROR: {
        const char *m = nav_system_enroll_message();
        draw_message(m && m[0] ? m : "Fingerprint",
                     m && m[0] && strcmp(m, "No match") == 0 ? "try again" : "");
        break;
    }
    case UI_FP_ENROLL:
        draw_enroll();
        break;
    case UI_FP_CLEAR_CONFIRM:
        draw_message("Clear all FP?", "OK=Yes  Left=No");
        break;
    case UI_FIDO_PROMPT:
        draw_message(nav_system_fido_label(), "Place finger");
        break;
    case UI_FIDO_PROCESSING:
        draw_message("Working…", "Wait");
        break;
    case UI_FIDO_SUCCESS:
        draw_message("OK", "Success");
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
                   st == UI_AUTH_PROMPT || _charge == CHARGE_CHARGING);
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
