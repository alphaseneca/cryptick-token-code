#include "input_system.h"
#include "event_bus.h"
#include <board_config.h>
#include <cryptick_console.h>
#include <cryptick_log.h>
#include <Arduino.h>
#if defined(ESP32)
#include "driver/gpio.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/portmacro.h"
#endif

/*
 * Buttons are sampled on a high-rate timer ISR so presses are never missed
 * when the main loop blocks on FP UART / OLED I2C / USB.
 * Active-low: press = pin grounded.
 */

#ifndef BUTTON_DEBOUNCE_MS
#define BUTTON_DEBOUNCE_MS 18
#endif

/* 2 ms sample → 18 ms ≈ 9 consecutive LOW samples before fire */
static constexpr uint32_t SAMPLE_US = 2000;
static constexpr uint8_t STABLE_NEED =
    (uint8_t)((BUTTON_DEBOUNCE_MS + 1) / 2); /* ~18ms → 9 */

struct Btn {
    int pin;
    InputKey key;
    const char *name;
    uint8_t low_streak;   /* ISR */
    uint8_t high_streak;  /* ISR */
    bool armed;           /* allow another fire after release (ISR) */
};

static Btn _btn[] = {
    { BUTTON_PIN, KEY_CENTER, "CENTER", 0, 0, true },
    { LEFT_BUTTON_PIN, KEY_LEFT, "LEFT", 0, 0, true },
    { RIGHT_BUTTON_PIN, KEY_RIGHT, "RIGHT", 0, 0, true },
    { UP_BUTTON_PIN, KEY_UP, "UP", 0, 0, true },
    { DOWN_BUTTON_PIN, KEY_DOWN, "DOWN", 0, 0, true },
};
static constexpr int N = (int)(sizeof(_btn) / sizeof(_btn[0]));

/* Lock-free press queue from ISR → main (key index 0..N-1) */
static volatile uint8_t _press_q[16];
static volatile uint8_t _press_head = 0;
static volatile uint8_t _press_tail = 0;
#if defined(ESP32)
static portMUX_TYPE _press_mux = portMUX_INITIALIZER_UNLOCKED;
static esp_timer_handle_t _timer = nullptr;
#endif

static bool raw_low(int pin)
{
    if (pin < 0)
        return false;
#if defined(ESP32)
    return gpio_get_level((gpio_num_t)pin) == 0;
#else
    return digitalRead(pin) == LOW;
#endif
}

static void setup_pin(int pin)
{
    if (pin < 0)
        return;
#if defined(ESP32)
    gpio_reset_pin((gpio_num_t)pin);
    gpio_hold_dis((gpio_num_t)pin);
    gpio_set_direction((gpio_num_t)pin, GPIO_MODE_INPUT);
    gpio_set_pull_mode((gpio_num_t)pin, GPIO_PULLUP_ONLY);
    gpio_set_intr_type((gpio_num_t)pin, GPIO_INTR_DISABLE);
#endif
    pinMode(pin, INPUT_PULLUP);
}

static void IRAM_ATTR push_press(uint8_t idx)
{
#if defined(ESP32)
    portENTER_CRITICAL_ISR(&_press_mux);
#endif
    uint8_t next = (uint8_t)((_press_head + 1) % sizeof(_press_q));
    if (next != _press_tail) {
        _press_q[_press_head] = idx;
        _press_head = next;
    }
#if defined(ESP32)
    portEXIT_CRITICAL_ISR(&_press_mux);
#endif
}

#if defined(ESP32)
static void IRAM_ATTR button_timer_cb(void *arg)
{
    (void)arg;
    for (int i = 0; i < N; i++) {
        if (_btn[i].pin < 0)
            continue;
        bool low = (gpio_get_level((gpio_num_t)_btn[i].pin) == 0);
        if (low) {
            _btn[i].high_streak = 0;
            if (_btn[i].low_streak < 255)
                _btn[i].low_streak++;
            if (_btn[i].armed && _btn[i].low_streak >= STABLE_NEED) {
                _btn[i].armed = false;
                push_press((uint8_t)i);
            }
        } else {
            _btn[i].low_streak = 0;
            if (_btn[i].high_streak < 255)
                _btn[i].high_streak++;
            /* re-arm after stable release (~same window) */
            if (!_btn[i].armed && _btn[i].high_streak >= STABLE_NEED)
                _btn[i].armed = true;
        }
    }
}
#endif

static void emit_key(int idx)
{
    if (idx < 0 || idx >= N)
        return;
    BusEvent e{};
    e.type = EVT_INPUT;
    e.kind = (uint8_t)_btn[idx].key;
    e.a = 1;
    if (!bus_publish(e)) {
        CLOG_D("IN", "bus full: %s", _btn[idx].name);
        return;
    }
    CLOG_D("IN", "%s (GPIO%d)", _btn[idx].name, _btn[idx].pin);
}

void input_system_init(void)
{
    CLOG_I("IN", "map  RIGHT=%d DOWN=%d UP=%d LEFT=%d CENTER=%d  (active-low)",
                       RIGHT_BUTTON_PIN, DOWN_BUTTON_PIN, UP_BUTTON_PIN,
                       LEFT_BUTTON_PIN, BUTTON_PIN);
    CLOG_D("IN", "timer-scanned @2ms (debounced, ISR)");

    for (int i = 0; i < N; i++) {
        setup_pin(_btn[i].pin);
        delay(1);
        bool low = raw_low(_btn[i].pin);
        _btn[i].low_streak = 0;
        _btn[i].high_streak = 0;
        _btn[i].armed = !low; /* if already pressed at boot, wait for release */
        CLOG_D("IN", "%-6s GPIO%-2d idle=%s",
                           _btn[i].name, _btn[i].pin, low ? "LOW?" : "HIGH");
    }

#if defined(ESP32)
    const esp_timer_create_args_t args = {
        .callback = &button_timer_cb,
        .arg = nullptr,
        .dispatch_method = ESP_TIMER_TASK, /* safer than ISR context for GPIO */
        .name = "btns",
        .skip_unhandled_events = true
    };
    /* ESP_TIMER_TASK still free of Arduino loop blocking */
    if (esp_timer_create(&args, &_timer) == ESP_OK) {
        esp_timer_start_periodic(_timer, SAMPLE_US);
        CLOG_I("IN", "scan timer start OK");
    } else {
        CLOG_E("IN", "scan timer FAIL — fallback in tick()");
    }
#endif
    CLOG_I("IN", "ready");
}

void input_system_tick(unsigned long nowMs)
{
    (void)nowMs;

    /* Drain ISR queue → event bus (and optional fallback poll) */
    for (;;) {
        int idx = -1;
#if defined(ESP32)
        portENTER_CRITICAL(&_press_mux);
#endif
        if (_press_tail != _press_head) {
            idx = (int)_press_q[_press_tail];
            _press_tail = (uint8_t)((_press_tail + 1) % sizeof(_press_q));
        }
#if defined(ESP32)
        portEXIT_CRITICAL(&_press_mux);
#endif
        if (idx < 0)
            break;
        emit_key(idx);
    }

#if defined(ESP32)
    if (_timer)
        return;
#endif
    /* Fallback if timer failed: still sample once per main-loop call */
    for (int i = 0; i < N; i++) {
        if (_btn[i].pin < 0)
            continue;
        bool low = raw_low(_btn[i].pin);
        if (low) {
            _btn[i].high_streak = 0;
            if (_btn[i].low_streak < 255)
                _btn[i].low_streak++;
            if (_btn[i].armed && _btn[i].low_streak >= 2) {
                _btn[i].armed = false;
                emit_key(i);
            }
        } else {
            _btn[i].low_streak = 0;
            if (_btn[i].high_streak < 255)
                _btn[i].high_streak++;
            if (!_btn[i].armed && _btn[i].high_streak >= 2)
                _btn[i].armed = true;
        }
    }
}
