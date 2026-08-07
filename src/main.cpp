#include <Arduino.h>
#include <Wire.h>
#include <LittleFS.h>
#include <RTClib.h>

#include <board_config.h>
#include <device_hal.h>
#include "host/totp_storage.h"
#include "host/serial_comm.h"

#include "systems/event_bus.h"
#include "systems/input_system.h"
#include "systems/battery_system.h"
#include "systems/fp_system.h"
#include "systems/auth_system.h"
#include "systems/nav_system.h"
#include "systems/display_system.h"

#include "usb_device.h"
#include "ctaphid.h"
#include "crypto.h"

extern "C" {
    extern volatile int8_t _fido_ui_request;

    void fido_log_print(const char *msg)
    {
        Serial.print(msg);
    }
}

RTC_DS3231 rtc;
static bool g_rtc_ok = false;
std::vector<TOTPCredential> credentials;
bool g_setup_finished = false;

extern "C" uint32_t get_synced_utc()
{
    static uint32_t baseUtc = 0;
    static unsigned long baseMillis = 0;

    if (baseUtc == 0) {
        if (g_rtc_ok) {
            i2c_lock();
            baseUtc = rtc.now().unixtime();
            i2c_unlock();
        } else {
            /* Epoch fallback so TOTP/UI never touch a dead RTC bus. */
            baseUtc = 1700000000UL;
        }
        baseMillis = millis();
    }
    return baseUtc + (millis() - baseMillis) / 1000;
}

static void dispatch_event(const BusEvent &e)
{
    if (e.type == EVT_CMD)
        fp_system_on_cmd(e);
    nav_system_on_event(e);
    display_system_on_event(e);
}

static void banner(void)
{
    Serial.println();
    Serial.println(F("--- Cryptick Token ---"));
    Serial.printf("[USB] CDC ready  mounted=%d  VID=0x%04X PID=0x%04X\n",
                  usb_device_mounted() ? 1 : 0, 0x1209u, 0xBEEEu);
    Serial.println(F("[USB] CDC = logs; OATH/FIDO/ENTERBOOT on HID (docs/HID_HOST.md)"));
    Serial.println(F("[USB] reflash: 1200bps, HID ENTERBOOT, or type BOOTLOADER"));
    Serial.flush();
}

void setup()
{
    /*
     * Boot order: bring-up UI first, USB last-ish.
     * If TinyUSB or FP hang, OLED/buttons already work so the board is not a brick.
     */
    delay(100);
    i2c_mutex_init();
    bus_init();

    /* 1) OLED — first visible life sign (independent of USB/Serial) */
    display_system_init();

    /* 2) Inputs — buttons work even if USB stack fails */
    input_system_init();

    /* 3) USB CDC + FIDO (short mount wait; see usb_device.cpp) */
    usb_device_init();
    banner();
    /* Re-log pin map after Serial is up */
    input_system_init();

    if (!LittleFS.begin(true))
        Serial.println(F("[BOOT] LittleFS FAIL"));
    else
        Serial.println(F("[BOOT] LittleFS OK"));

    Wire.setTimeOut(50);
    i2c_lock();
    g_rtc_ok = rtc.begin();
    i2c_unlock();
    Serial.println(g_rtc_ok ? F("[BOOT] RTC OK") : F("[BOOT] RTC missing (millis time)"));

    battery_system_init();
    auth_system_init();
    nav_system_init();

    device_hal_init();
    Serial.println(F("[BOOT] FIDO HAL"));

    loadConfiguration(credentials);
    display_system_set_credentials(&credentials);
    display_system_set_user("User");

    fp_system_init();
    auth_system_set_fingerprint_enabled(fp_system_ready());

    crypto_ecc256_init();

    Serial.println(F("[BOOT] Ready — type HELP"));
    g_setup_finished = true;
    Serial.print(F("cryptick> "));
    Serial.flush();
    display_system_force_redraw();
}

void loop()
{
    unsigned long now = millis();

    usb_device_poll_bootloader();
    device_hal_heartbeat();

    /* Re-emit heartbeat so late monitor open still sees life */
    static uint32_t lastBeat = 0;
    if (now - lastBeat >= 5000) {
        lastBeat = now;
        if (g_setup_finished) {
            Serial.printf("[HB] up=%lus mounted=%d\n",
                          (unsigned long)(now / 1000),
                          usb_device_mounted() ? 1 : 0);
            Serial.flush();
        }
    }

    static int8_t lastUi = -1;
    if (_fido_ui_request != lastUi) {
        lastUi = _fido_ui_request;
        nav_system_set_fido_ui(_fido_ui_request);
        display_system_force_redraw();
    }

    uint8_t hid_report[64];
    if (usb_hid_read_report(hid_report))
        ctaphid_push_report(hid_report);

    processSerialCommands(Serial, credentials,
#ifdef ENABLE_FINGERPRINT
                          fp_system_driver(), fp_system_ready()
#else
                          nullptr, false
#endif
    );

    input_system_tick(now);
    battery_system_tick(now);
    fp_system_tick(now);
    auth_system_set_fingerprint_enabled(fp_system_ready());

    nav_system_set_account_count((int)credentials.size());
    display_system_set_credentials(&credentials);

    BusEvent e;
    int n = 0;
    while (bus_pop(e) && n++ < 64)
        dispatch_event(e);

    nav_system_tick(now);

    n = 0;
    while (bus_pop(e) && n++ < 32)
        dispatch_event(e);

    display_system_tick(now);
    yield();
}
