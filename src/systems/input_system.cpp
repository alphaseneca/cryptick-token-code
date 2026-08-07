#include "input_system.h"
#include "event_bus.h"
#include <board_config.h>
#include <Arduino.h>
#if defined(ESP32)
#include "driver/gpio.h"
#endif

struct Btn {
    int pin;
    InputKey key;
    const char *name;
    bool stable_low;
    bool raw_low;
    uint32_t change_ms;
    uint32_t last_emit_ms;
};

/* Order: name printed matches physical expectation after board_config pins fixed */
static Btn _btn[] = {
    { BUTTON_PIN, KEY_CENTER, "CENTER", false, false, 0, 0 },
    { LEFT_BUTTON_PIN, KEY_LEFT, "LEFT", false, false, 0, 0 },
    { RIGHT_BUTTON_PIN, KEY_RIGHT, "RIGHT", false, false, 0, 0 },
    { UP_BUTTON_PIN, KEY_UP, "UP", false, false, 0, 0 },
    { DOWN_BUTTON_PIN, KEY_DOWN, "DOWN", false, false, 0, 0 },
};
static constexpr int N = (int)(sizeof(_btn) / sizeof(_btn[0]));

static bool raw_low(int pin)
{
    if (pin < 0) return false;
#if defined(ESP32)
    return gpio_get_level((gpio_num_t)pin) == 0;
#else
    return digitalRead(pin) == LOW;
#endif
}

static void setup_pin(int pin)
{
    if (pin < 0) return;
#if defined(ESP32)
    gpio_reset_pin((gpio_num_t)pin);
    gpio_hold_dis((gpio_num_t)pin);
    gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    gpio_set_pull_mode((gpio_num_t)pin, GPIO_PULLUP_ONLY);
    gpio_set_intr_type((gpio_num_t)pin, GPIO_INTR_DISABLE);
#endif
    pinMode(pin, INPUT_PULLUP);
}

static void publish(Btn &b, unsigned long now)
{
    if (now - b.last_emit_ms < (uint32_t)BUTTON_DEBOUNCE_MS)
        return;
    b.last_emit_ms = now;

    BusEvent e{};
    e.type = EVT_INPUT;
    e.kind = (uint8_t)b.key;
    e.a = 1;
    if (!bus_publish(e)) {
        Serial.printf("[IN] bus full: %s\n", b.name);
        return;
    }
    Serial.printf("[IN] %s (GPIO%d)\n", b.name, b.pin);
    Serial.flush();
}

void input_system_init(void)
{
    /* Map text is always generated from macros — never a stale hardcode */
    Serial.printf("[IN] map  RIGHT=%d DOWN=%d UP=%d LEFT=%d CENTER=%d  (active-low)\n",
                  RIGHT_BUTTON_PIN, DOWN_BUTTON_PIN, UP_BUTTON_PIN,
                  LEFT_BUTTON_PIN, BUTTON_PIN);
    Serial.println(F("[IN] press each key once; log name must match physical key"));

    for (int i = 0; i < N; i++) {
        setup_pin(_btn[i].pin);
        delay(1);
        bool low = raw_low(_btn[i].pin);
        _btn[i].raw_low = low;
        _btn[i].stable_low = false;
        _btn[i].change_ms = 0;
        _btn[i].last_emit_ms = 0;
        Serial.printf("[IN]  %-6s GPIO%-2d idle=%s\n",
                      _btn[i].name, _btn[i].pin, low ? "LOW?" : "HIGH");
    }
    Serial.println(F("[IN] ready"));
    Serial.flush();
}

void input_system_tick(unsigned long nowMs)
{
    const uint32_t deb = (uint32_t)BUTTON_DEBOUNCE_MS;

    for (int i = 0; i < N; i++) {
        if (_btn[i].pin < 0) continue;

        bool low = raw_low(_btn[i].pin);

        if (low != _btn[i].raw_low) {
            _btn[i].raw_low = low;
            _btn[i].change_ms = nowMs ? nowMs : 1;
        }

        if (_btn[i].change_ms == 0)
            continue;
        if ((nowMs - _btn[i].change_ms) < deb)
            continue;

        _btn[i].change_ms = 0;
        if (low == _btn[i].stable_low)
            continue;

        _btn[i].stable_low = low;
        if (low)
            publish(_btn[i], nowMs);
    }
}
