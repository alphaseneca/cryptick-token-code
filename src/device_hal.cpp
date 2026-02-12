#include "device_hal.h"
#include "config.h"
#include <Arduino.h>
#include <RTClib.h>

extern RTC_DS3231 rtc;

static bool _hal_initialized = false;

void device_hal_init(void)
{
    _hal_initialized = true;
}

uint32_t device_get_time_utc(void)
{
    return (uint32_t)rtc.now().unixtime();
}

uint32_t device_millis(void)
{
    return (uint32_t)millis();
}

int device_button_state(void)
{
    static int last = 0;   /* 0 = not pressed, 1 = pressed */
    static uint32_t last_press = 0;
    int now = (digitalRead(BUTTON_PIN) == LOW) ? 1 : 0;

    if (last == 1 && now == 0)
    {
        last = 0;
        return 0;
    }
    if (last == 0 && now == 1)
    {
        uint32_t t = device_millis();
        if (t - last_press >= (uint32_t)BUTTON_DEBOUNCE_MS)
        {
            last_press = t;
            last = 1;
            return 1;
        }
    }
    last = now;
    return 0;
}

void device_reboot(void)
{
    ESP.restart();
}

int device_generate_rng(uint8_t *dst, size_t num)
{
    for (size_t i = 0; i < num; i++)
        dst[i] = (uint8_t)random(0, 256);
    return 1;
}
