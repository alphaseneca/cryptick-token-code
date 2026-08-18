#include "cryptick_log.h"
#include <Arduino.h>
#include <Preferences.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "usb_device.h"

static cryptick_log_level_t s_level = (cryptick_log_level_t)CRYPTICK_LOG_LEVEL_DEFAULT;
static bool s_inited = false;

/*
 * The FIDO task (core 0) and the Arduino loop (core 1) both log. Each call
 * formats into its own stack buffer, so the only shared resource is the CDC
 * stream: without serialisation two lines interleave mid-character.
 */
static SemaphoreHandle_t s_sink_mutex = NULL;

static bool sink_lock(void)
{
    if (!s_sink_mutex) {
        s_sink_mutex = xSemaphoreCreateMutex();
        if (!s_sink_mutex)
            return false;
    }
    /*
     * Bounded wait, and emit anyway on timeout: a garbled line is a better
     * failure mode than a dropped error during a hang.
     */
    return xSemaphoreTake(s_sink_mutex, pdMS_TO_TICKS(50)) == pdTRUE;
}

static void sink_unlock(bool held)
{
    if (held && s_sink_mutex)
        xSemaphoreGive(s_sink_mutex);
}

static void persist_level(cryptick_log_level_t level)
{
    Preferences prefs;
    if (!prefs.begin("cryptick", false))
        return;
    prefs.putUChar("loglvl", (uint8_t)level);
    prefs.end();
}

static bool load_persisted(cryptick_log_level_t *out)
{
    Preferences prefs;
    if (!prefs.begin("cryptick", true))
        return false;
    if (!prefs.isKey("loglvl")) {
        prefs.end();
        return false;
    }
    uint8_t v = prefs.getUChar("loglvl", 255);
    prefs.end();
    if (v > (uint8_t)CRYPTICK_LL_TRACE)
        return false;
    *out = (cryptick_log_level_t)v;
    return true;
}

void cryptick_log_init(void)
{
    if (!s_sink_mutex)
        s_sink_mutex = xSemaphoreCreateMutex();
    s_level = (cryptick_log_level_t)CRYPTICK_LOG_LEVEL_DEFAULT;
    if (s_level > CRYPTICK_LL_TRACE)
        s_level = CRYPTICK_LL_TRACE;
    cryptick_log_level_t persisted;
    if (load_persisted(&persisted))
        s_level = persisted;
    s_inited = true;
}

void cryptick_log_set_level(cryptick_log_level_t level)
{
    if ((int)level < 0)
        level = CRYPTICK_LL_NONE;
    if (level > CRYPTICK_LL_TRACE)
        level = CRYPTICK_LL_TRACE;
    s_level = level;
    if (s_inited)
        persist_level(level);
}

cryptick_log_level_t cryptick_log_get_level(void)
{
    return s_level;
}

const char *cryptick_log_level_name(cryptick_log_level_t level)
{
    switch (level) {
    case CRYPTICK_LL_NONE: return "NONE";
    case CRYPTICK_LL_ERROR: return "ERROR";
    case CRYPTICK_LL_WARN: return "WARN";
    case CRYPTICK_LL_INFO: return "INFO";
    case CRYPTICK_LL_DEBUG: return "DEBUG";
    case CRYPTICK_LL_TRACE: return "TRACE";
    default: return "?";
    }
}

static void sink_write(const char *s)
{
    if (!s)
        return;
    bool held = sink_lock();
    USBLog.print(s);
    sink_unlock(held);
}

void cryptick_log_raw(const char *msg)
{
    /* Solo FIDO printf1 / dump_hex → chatty; gate at DEBUG+. */
    if (s_level < CRYPTICK_LL_DEBUG)
        return;
    sink_write(msg);
}

void cryptick_log(cryptick_log_level_t level, const char *tag, const char *fmt, ...)
{
    if (level == CRYPTICK_LL_NONE || level > s_level || !fmt)
        return;

    char line[280];
    int n = 0;
    const char *lv =
        (level == CRYPTICK_LL_ERROR) ? "E" :
        (level == CRYPTICK_LL_WARN)  ? "W" :
        (level == CRYPTICK_LL_INFO)  ? "I" :
        (level == CRYPTICK_LL_DEBUG) ? "D" : "T";
    const char *t = tag ? tag : "?";

    n = snprintf(line, sizeof(line), "[%s][%s] ", lv, t);
    if (n < 0 || n >= (int)sizeof(line))
        return;

    va_list ap;
    va_start(ap, fmt);
    int m = vsnprintf(line + n, sizeof(line) - (size_t)n, fmt, ap);
    va_end(ap);
    if (m < 0)
        return;

    /* Always terminate with exactly one newline, even when the format truncated. */
    size_t len = strlen(line);
    if (len == 0 || line[len - 1] != '\n') {
        if (len + 1 >= sizeof(line))
            len = sizeof(line) - 2;
        line[len] = '\n';
        line[len + 1] = '\0';
    }
    sink_write(line);
}

void cryptick_log_hex(cryptick_log_level_t level, const char *tag,
                      const uint8_t *data, size_t len)
{
    if (level > s_level || !data || len == 0)
        return;
    char hex[3 * 32 + 4];
    size_t show = len > 32 ? 32 : len;
    size_t p = 0;
    for (size_t i = 0; i < show && p + 3 < sizeof(hex); i++) {
        p += (size_t)snprintf(hex + p, sizeof(hex) - p, "%02X", data[i]);
        if (i + 1 < show)
            hex[p++] = ' ';
    }
    hex[p] = '\0';
    if (len > show)
        cryptick_log(level, tag, "hex(%u): %s …", (unsigned)len, hex);
    else
        cryptick_log(level, tag, "hex(%u): %s", (unsigned)len, hex);
}
