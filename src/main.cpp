#include <Arduino.h>
#include <Wire.h>
#include <LittleFS.h>
#include <RTClib.h>
#include <sys/time.h>
#include <time.h>

#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <device.h>
#include "host/credential_store.h"
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
#if CRYPTICK_BLE_FIDO
#include "ble_fido.h"
#endif
#include "piv.h"
#include "ctaphid.h"
#include "crypto.h"

extern "C" {
    extern volatile int8_t _fido_ui_request;

    void fido_log_print(const char *msg)
    {
        cryptick_log_raw(msg);
    }
}

RTC_DS3231 rtc;
static bool g_rtc_ok = false;
std::vector<TOTPCredential> credentials;
bool g_setup_finished = false;

/*
 * Soft clock: baseUnix + (millis - baseMillis)/1000.
 * First call seeds from HW RTC (if present) else a fixed lab epoch.
 * set_synced_utc() updates base immediately and writes RTC when present
 * so SETTIME / OATH SET_TIME apply without reboot.
 */
static uint32_t s_baseUtc = 0;
static unsigned long s_baseMillis = 0;
static bool s_time_seeded = false;

extern "C" uint32_t get_synced_utc(void)
{
    if (!s_time_seeded) {
        if (g_rtc_ok) {
            i2c_lock();
            s_baseUtc = rtc.now().unixtime();
            i2c_unlock();
        } else {
            s_baseUtc = 1700000000UL; /* soft-only bootstrap; use SETTIME */
        }
        s_baseMillis = millis();
        s_time_seeded = true;
    }
    return s_baseUtc + (uint32_t)((millis() - s_baseMillis) / 1000UL);
}

extern "C" void set_synced_utc(uint32_t utc)
{
    if (utc == 0)
        return;
    s_baseUtc = utc;
    s_baseMillis = millis();
    s_time_seeded = true;

    if (g_rtc_ok) {
        i2c_lock();
        rtc.adjust(DateTime(utc));
        i2c_unlock();
    }

    /* ESP system clock (time()/localtime for libs that use it) */
    struct timeval tv;
    tv.tv_sec = (time_t)utc;
    tv.tv_usec = 0;
    settimeofday(&tv, nullptr);

    CLOG_I("TIME", "set utc=%lu rtc=%d", (unsigned long)utc, g_rtc_ok ? 1 : 0);
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
    CryptickLog.println();
    CryptickLog.println(F("--- Cryptick Token ---"));
#if defined(ARDUINO_USB_MODE) && (ARDUINO_USB_MODE == 0)
    CLOG_I("USB", "TinyUSB CDC+HID mounted=%d VID=0x1209 PID=0xBEEE",
                       usb_device_mounted() ? 1 : 0);
    CLOG_I("USB", "reflash: 1200bps / HID ENTERBOOT / BOOTLOADER");
#elif defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK
    CLOG_I("USB", "Serial/JTAG CDC MODE=1 @115200 (bring-up)");
    CLOG_I("USB", "open this COM @115200 — type HELP");
#else
    CLOG_D("UART", "console @115200");
#endif
    CryptickLog.flush();
}

void setup()
{
    /*
     * 1) USB CDC first so all probe lines are visible on the host.
     * 2) OLED / buttons / FP after Serial is up (blank-screen diagnosis).
     */
    cryptick_log_init();
    i2c_mutex_init();
    credential_store_init();
    bus_init();

    usb_device_init();
    banner();
    CLOG_I("BOOT", "log_level=%d (%s)  set via LOGLEVEL 0..5",
           (int)cryptick_log_get_level(),
           cryptick_log_level_name(cryptick_log_get_level()));

    display_system_init();
    display_system_boot_animation();
    input_system_init();

    if (!LittleFS.begin(true))
        CLOG_E("BOOT", "LittleFS FAIL");
    else
        CLOG_I("BOOT", "LittleFS OK");

    Wire.setTimeOut(50);
    i2c_lock();
    g_rtc_ok = rtc.begin();
    i2c_unlock();
    CLOG_I("BOOT", "RTC %s", g_rtc_ok ? "OK" : "missing (millis time)");

    battery_system_init();
    auth_system_init();
    nav_system_init();

    device_hal_init();
    CLOG_D("BOOT", "FIDO HAL");

#if CRYPTICK_BLE_FIDO
    /*
     * After device_hal_init(): the GATT write callback posts to the FIDO
     * task's queue, which that call creates.
     */
    ble_fido_gatt_init();
    CLOG_D("BOOT", "FIDO BLE");
#endif

    loadConfiguration(credentials);
    display_system_set_credentials(&credentials);
    display_system_set_user("User");

    fp_system_init();
    auth_system_set_fingerprint_enabled(fp_system_ready());

    crypto_ecc256_init();

    /* After crypto: slot keys are derived from the master secret. */
    piv_hal_init();

    CLOG_I("BOOT", "Ready — type HELP");
    g_setup_finished = true;
    CryptickLog.print(F("cryptick> "));
    CryptickLog.flush();
    display_system_force_redraw();
}

void loop()
{
    unsigned long now = millis();

    /* Buttons are timer-scanned; drain queue first every loop */
    input_system_tick(now);

    usb_device_poll_bootloader();
    device_hal_heartbeat();

    static uint32_t lastBeat = 0;
    if (now - lastBeat >= 5000) {
        lastBeat = now;
        if (g_setup_finished) {
            CLOG_T("HB", "up=%lus mounted=%d",
                               (unsigned long)(now / 1000),
                               usb_device_mounted() ? 1 : 0);
            /* no flush — CDC flush can stall loop for tens of ms */
        }
    }

    /*
     * nav_system is loop-owned. The FIDO task signals it indirectly: a prompt
     * caption via device_take_ui_label() and the prompt/processing/success
     * state via _fido_ui_request. Apply the caption first so the prompt screen
     * draws with the right text on its very first frame.
     */
    char fido_label[64];
    if (device_take_ui_label(fido_label, sizeof(fido_label))) {
        nav_system_set_fido_label(fido_label);
        display_system_force_redraw();
    }

    static int8_t lastUi = -1;
    if (_fido_ui_request != lastUi) {
        lastUi = _fido_ui_request;
        nav_system_set_fido_ui(_fido_ui_request);
        display_system_force_redraw();
    }

#if defined(CRYPTICK_USB_STACK) && CRYPTICK_USB_STACK
    uint8_t hid_report[64];
    if (usb_hid_read_report(hid_report))
        ctaphid_push_report(hid_report);
#endif

    processSerialCommands(CryptickLog, credentials,
#ifdef ENABLE_FINGERPRINT
                          fp_system_driver(), fp_system_ready()
#else
                          nullptr, false
#endif
    );

    /*
     * Re-drain buttons after the serial CLI: an OATH command can block here
     * for the whole place-finger window, and the 2 ms scan queue is only 16
     * deep, so presses made during the wait would otherwise be lost.
     */
    input_system_tick(millis());

    battery_system_tick(now);
    fp_system_tick(now);

    auth_system_set_fingerprint_enabled(fp_system_ready());

    {
        CredentialLock guard;
        nav_system_set_account_count((int)credentials.size());
    }
    display_system_set_credentials(&credentials);

    BusEvent e;
    int n = 0;
    while (bus_pop(e) && n++ < 64)
        dispatch_event(e);

    now = millis();
    nav_system_tick(now);
    display_system_tick(now);
}
