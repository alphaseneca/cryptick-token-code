#include "battery_system.h"
#include <board_config.h>
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
 * No battery: STAT2 toggles between charge and complete.
 * N16R8: GPIO33–37 reserved for Octal flash/PSRAM (IO37 NC). STAT1=38 STAT2=39 are free.
 */

static ChargeState _state = CHARGE_IDLE;
static unsigned long _lastPoll = 0;
static uint8_t _s1 = 1;
static uint8_t _s2 = 1;
static bool _use_stat1 = true;
static unsigned long _s2_last_edge = 0;
static bool _s2_blinks = false;
static int _stat1_stuck_low = 0;

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

static ChargeState decode(uint8_t s1, uint8_t s2)
{
    if (s1 && !s2) return CHARGE_CHARGING; /* H L */
    if (s1 && s2) {
        /* H H = done/sleep; if STAT2 was blinking (no cell), treat as charging/power present */
        return _s2_blinks ? CHARGE_CHARGING : CHARGE_DONE;
    }
    if (!s1 && s2) return CHARGE_FAULT;    /* L H */
    return CHARGE_FAULT;                   /* L L */
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
    _state = decode(_s1, _s2);

    Serial.printf("[BAT] init S1=%u S2=%u → %s (STAT1_PIN=%d STAT2_PIN=%d)\n",
                  (unsigned)_s1, (unsigned)_s2, battery_system_label(),
                  STAT1_PIN, STAT2_PIN);

    BusEvent e{};
    e.type = EVT_BATTERY;
    e.kind = (uint8_t)_state;
    e.a = _s1;
    e.b = _s2;
    bus_publish(e);
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

    /* Detect dead STAT1 (always asserted) — should not happen on IO38 */
    if (_use_stat1) {
        if (s1 == 0)
            _stat1_stuck_low++;
        else
            _stat1_stuck_low = 0;
        if (_stat1_stuck_low > 25) {
            _use_stat1 = false;
            s1 = 1;
            Serial.println("[BAT] STAT1 stuck low — using STAT2-only mode");
        }
    } else {
        s1 = 1;
    }

    ChargeState next = decode(s1, s2);
    if (next == _state && s1 == _s1 && s2 == _s2)
        return;

    _s1 = s1;
    _s2 = s2;
    _state = next;
    Serial.printf("[BAT] S1=%u S2=%u → %s\n",
                  (unsigned)_s1, (unsigned)_s2, battery_system_label());

    BusEvent e{};
    e.type = EVT_BATTERY;
    e.kind = (uint8_t)_state;
    e.a = _s1;
    e.b = _s2;
    bus_publish(e);
}

ChargeState battery_system_state(void) { return _state; }
uint8_t battery_system_stat1(void) { return _s1; }
uint8_t battery_system_stat2(void) { return _s2; }

const char *battery_system_label(void)
{
    switch (_state) {
    case CHARGE_CHARGING: return "CHG";
    case CHARGE_DONE:     return "OK";   /* done or sleep / not charging */
    case CHARGE_FAULT:    return "FLT";
    default:              return "BAT";
    }
}
