#include "battery_system.h"
#include "usb_device.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <Arduino.h>
#if defined(ESP32)
#include "driver/gpio.h"
#endif

/*
 * BQ25185 Table 7-2 (open-drain; after pull-up: HIGH = released, LOW = asserted):
 *
 *   STAT1   STAT2   Meaning
 *   HIGH    HIGH    Charge done / sleep / charge disabled
 *   HIGH    LOW     Normal charging
 *   LOW     HIGH    Recoverable fault
 *   LOW     LOW     Non-recoverable / latch fault
 *
 * HIGH/HIGH is both "battery full, VIN present" and "unplugged / sleep".
 * This PCB has no dedicated VBUS pin, so USB enumeration is the VIN proxy:
 * while the host is mounted, HIGH/HIGH means FULL. Unplug → idle half-bar.
 *
 * `_saw_charging` covers the gap before TinyUSB mounts and charge-only cables
 * that never enumerate. It is cleared on USB unmount so a finished charge does
 * not keep saying FULL after the cable is gone.
 */

static ChargeState _state = CHARGE_IDLE;
static unsigned long _lastPoll = 0;
static uint8_t _s1 = 1;
static uint8_t _s2 = 1;
static bool _use_stat1 = true;
static unsigned long _s2_last_edge = 0;
static bool _s2_blinks = false;
static int _stat1_stuck_low = 0;
static bool _saw_charging = false;
static bool _usb_was_mounted = false;

static void cfg_pin(int pin)
{
    if (pin < 0) return;
#if defined(ESP32)
    gpio_reset_pin((gpio_num_t)pin);
    gpio_hold_dis((gpio_num_t)pin);
    gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    gpio_set_pull_mode((gpio_num_t)pin, GPIO_PULLUP_ONLY);
#endif
    pinMode(pin, INPUT_PULLUP);
}

static uint8_t rd(int pin)
{
    if (pin < 0) return 1;
    return digitalRead(pin) == HIGH ? 1 : 0;
}

static bool charger_present(void)
{
    return usb_device_mounted() || _saw_charging;
}

static ChargeState decode(uint8_t s1, uint8_t s2)
{
    if (s1 && !s2) return CHARGE_CHARGING;
    if (s1 && s2) {
        if (_s2_blinks) return CHARGE_CHARGING;
        return charger_present() ? CHARGE_DONE : CHARGE_IDLE;
    }
    if (!s1 && s2) return CHARGE_FAULT;
    return CHARGE_FAULT;
}

static void publish(void)
{
    BusEvent e{};
    e.type = EVT_BATTERY;
    e.kind = (uint8_t)_state;
    e.a = _s1;
    e.b = _s2;
    bus_publish(e);
}

void battery_system_init(void)
{
#if STAT1_PIN >= 0
    cfg_pin(STAT1_PIN);
#else
    _use_stat1 = false;
#endif
#if STAT2_PIN >= 0
    cfg_pin(STAT2_PIN);
#endif

    delay(10);
    _s1 = _use_stat1 ? rd(STAT1_PIN) : 1;
    _s2 = rd(STAT2_PIN);
    _usb_was_mounted = usb_device_mounted();
    _state = decode(_s1, _s2);
    if (_state == CHARGE_CHARGING)
        _saw_charging = true;

    const char *lab = battery_system_label();
    CLOG_I("BAT", "init S1=%u S2=%u usb=%d → %s (STAT1_PIN=%d STAT2_PIN=%d)",
           (unsigned)_s1, (unsigned)_s2, _usb_was_mounted ? 1 : 0,
           lab[0] ? lab : "idle", STAT1_PIN, STAT2_PIN);

    publish();
}

void battery_system_tick(unsigned long nowMs)
{
    if (nowMs - _lastPoll < BATTERY_POLL_INTERVAL_MS) return;
    _lastPoll = nowMs;

    uint8_t s1 = _use_stat1 ? rd(STAT1_PIN) : 1;
    uint8_t s2 = rd(STAT2_PIN);

    if (s2 != _s2) {
        if (_s2_last_edge && (nowMs - _s2_last_edge) < 2500)
            _s2_blinks = true;
        _s2_last_edge = nowMs;
    } else if (_s2_last_edge && (nowMs - _s2_last_edge) > 5000) {
        _s2_blinks = false;
    }

    if (_use_stat1) {
        if (s1 == 0)
            _stat1_stuck_low++;
        else
            _stat1_stuck_low = 0;
        if (_stat1_stuck_low > 25) {
            _use_stat1 = false;
            s1 = 1;
            CLOG_E("BAT", "STAT1 stuck low — using STAT2-only mode");
        }
    } else {
        s1 = 1;
    }

    bool usb = usb_device_mounted();
    if (_usb_was_mounted && !usb)
        _saw_charging = false;
    _usb_was_mounted = usb;

    ChargeState next = decode(s1, s2);
    if (next == CHARGE_CHARGING)
        _saw_charging = true;
    /* Re-decode after the latch so a charge-complete edge becomes FULL even
     * before TinyUSB has mounted. */
    if (next == CHARGE_IDLE && charger_present())
        next = CHARGE_DONE;

    if (next == _state && s1 == _s1 && s2 == _s2)
        return;

    _s1 = s1;
    _s2 = s2;
    _state = next;
    const char *lab = battery_system_label();
    CLOG_D("BAT", "S1=%u S2=%u usb=%d → %s",
           (unsigned)_s1, (unsigned)_s2, usb ? 1 : 0,
           lab[0] ? lab : "idle");

    publish();
}

ChargeState battery_system_state(void) { return _state; }
uint8_t battery_system_stat1(void) { return _s1; }
uint8_t battery_system_stat2(void) { return _s2; }

bool battery_system_show_full(void)
{
    return _state == CHARGE_DONE;
}

const char *battery_system_label(void)
{
    switch (_state) {
    case CHARGE_CHARGING:
        return "CHG";
    case CHARGE_DONE:
        return "FULL";
    case CHARGE_FAULT:
        return "FLT";
    default:
        return "";
    }
}
