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

/*
 * SW2 quadrature rotary encoder (GPIO40=CW/A, GPIO41=CCW/B — see
 * board_config.h for how that was verified against the PCB). Queue indices
 * N and N+1 are reserved for its two tick directions, past the 5-way slots.
 */
static constexpr int IDX_ENC_CW = N;
static constexpr int IDX_ENC_CCW = N + 1;
struct EncKeyInfo { InputKey key; const char *name; int pin; };
static const EncKeyInfo _enc_info[2] = {
    { KEY_ENCODER_CW, "ENC_CW", ENCODER_CW_PIN },
    { KEY_ENCODER_CCW, "ENC_CCW", ENCODER_CCW_PIN },
};
static constexpr bool ENCODER_PRESENT = (ENCODER_CW_PIN >= 0) && (ENCODER_CCW_PIN >= 0);

/*
 * Gray-code quadrature table: index = (previous AB << 2) | current AB,
 * value = +1 on a valid CW step, -1 on a valid CCW step, 0 on a repeat or an
 * illegal (bounce/skipped-state) transition. Four valid steps make one
 * mechanical detent on the EC05E1220401, so ticks accumulate in _enc_accum
 * and only fire an event (and reset) once |_enc_accum| reaches 4 — this is
 * what turns noisy quadrature edges into one event per physical click.
 */
static const int8_t ENC_QUAD_TABLE[16] = {
    0, -1, +1, 0,
   +1,  0,  0, -1,
   -1,  0,  0, +1,
    0, +1, -1, 0,
};
/* Debounced-settled AB state feeding the quadrature table (ISR-owned). */
static uint8_t _enc_settled_ab = 0;
static uint8_t _enc_raw_ab = 0;
static uint8_t _enc_streak = 0;
static int8_t _enc_accum = 0;
/* Same sample-rate math as STABLE_NEED below, against ENCODER_DEBOUNCE_MS. */
static constexpr uint8_t ENC_STABLE_NEED =
    (uint8_t)((ENCODER_DEBOUNCE_MS + 1) / 2);

/* Lock-free press queue from ISR → main (key index 0..N-1, or IDX_ENC_*) */
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

/*
 * One quadrature sample. Called from the same 2ms cadence as the button
 * scan so a single timer owns all physical-input timing. Debounces into
 * _enc_settled_ab, feeds genuinely-new settled states through the Gray-code
 * table, and queues one tick per 4 valid steps (one detent).
 *
 * CW/CCW direction here follows the PCB's own net names (`/CW`, `/CCW`
 * ending at GPIO40/GPIO41 — see board_config.h); it has not been confirmed
 * against a spinning physical knob. If a flashed unit scrolls backwards,
 * swap ENCODER_CW_PIN and ENCODER_CCW_PIN in board_config.h — the decode
 * logic itself does not need to change.
 */
static void IRAM_ATTR encoder_sample(void)
{
    if (!ENCODER_PRESENT)
        return;
    uint8_t a = raw_low(ENCODER_CW_PIN) ? 0 : 1;
    uint8_t b = raw_low(ENCODER_CCW_PIN) ? 0 : 1;
    uint8_t ab = (uint8_t)((a << 1) | b);

    if (ab == _enc_raw_ab) {
        if (_enc_streak < 255)
            _enc_streak++;
    } else {
        _enc_raw_ab = ab;
        _enc_streak = 1;
    }

    if (_enc_streak >= ENC_STABLE_NEED && ab != _enc_settled_ab) {
        int8_t step = ENC_QUAD_TABLE[(uint8_t)((_enc_settled_ab << 2) | ab)];
        _enc_settled_ab = ab;
        if (step != 0) {
            _enc_accum = (int8_t)(_enc_accum + step);
            if (_enc_accum >= 4) {
                _enc_accum = 0;
                push_press((uint8_t)IDX_ENC_CW);
            } else if (_enc_accum <= -4) {
                _enc_accum = 0;
                push_press((uint8_t)IDX_ENC_CCW);
            }
        }
    }
}

#if defined(ESP32)
static void IRAM_ATTR button_timer_cb(void *arg)
{
    (void)arg;
    encoder_sample();
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
    InputKey key;
    const char *name;
    int pin;
    if (idx >= 0 && idx < N) {
        key = _btn[idx].key;
        name = _btn[idx].name;
        pin = _btn[idx].pin;
    } else if (idx == IDX_ENC_CW || idx == IDX_ENC_CCW) {
        const EncKeyInfo &info = _enc_info[idx - IDX_ENC_CW];
        key = info.key;
        name = info.name;
        pin = info.pin;
    } else {
        return;
    }
    BusEvent e{};
    e.type = EVT_INPUT;
    e.kind = (uint8_t)key;
    e.a = 1;
    if (!bus_publish(e)) {
        CLOG_D("IN", "bus full: %s", name);
        return;
    }
    CLOG_D("IN", "%s (GPIO%d)", name, pin);
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

    if (ENCODER_PRESENT) {
        setup_pin(ENCODER_CW_PIN);
        setup_pin(ENCODER_CCW_PIN);
        delay(1);
        _enc_raw_ab = (uint8_t)(((raw_low(ENCODER_CW_PIN) ? 0 : 1) << 1) |
                                 (raw_low(ENCODER_CCW_PIN) ? 0 : 1));
        _enc_settled_ab = _enc_raw_ab;
        _enc_streak = 0;
        _enc_accum = 0;
        CLOG_I("IN", "encoder CW=GPIO%d CCW=GPIO%d (quadrature, %ums debounce)",
               ENCODER_CW_PIN, ENCODER_CCW_PIN, (unsigned)ENCODER_DEBOUNCE_MS);
    } else {
        CLOG_I("IN", "encoder not wired on this board rev (CW/CCW pin -1)");
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
    encoder_sample();
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
