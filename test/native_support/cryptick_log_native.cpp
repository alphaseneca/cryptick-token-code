/*
 * Host-side stand-in for core/cryptick_log.cpp, used only by the
 * `test_nav_native` PlatformIO environment.
 *
 * The real sink (core/cryptick_log.cpp) depends on a FreeRTOS mutex
 * (SemaphoreHandle_t) and the ESP32 TinyUSB CDC driver (usb_device.h), so it
 * cannot link into a native host binary. nav_system.cpp, event_bus.cpp and
 * auth_system.cpp only ever reach cryptick_log() through the CLOG_* macros,
 * so that is the only symbol this file needs to provide to let them link and
 * run unmodified on the host.
 */
#include "cryptick_log.h"

/*
 * nav_system.cpp reads this through a weak extern (`extern bool g_rtc_ok
 * __attribute__((weak))`) to label the clock source in Settings → Info; the
 * real definition lives in src/main.cpp, which no test env links. On the
 * GNU/Xtensa toolchain used for the on-device suites, an unresolved weak
 * extern simply reads as zero; macOS's native ld64 (used by this host env)
 * does not offer that guarantee for an undefined weak symbol, so provide the
 * same default `false` main.cpp would, to keep this portable across linkers.
 */
bool g_rtc_ok = false;

void cryptick_log_init(void) {}

void cryptick_log_set_level(cryptick_log_level_t) {}

cryptick_log_level_t cryptick_log_get_level(void)
{
    return (cryptick_log_level_t)CRYPTICK_LOG_LEVEL_DEFAULT;
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

/*
 * Deliberately silent: `pio test` output is Unity's PASS/FAIL summary, and
 * interleaving firmware log lines into that would just make CI output harder
 * to read. Nothing in test_nav asserts on log content.
 */
void cryptick_log(cryptick_log_level_t, const char *, const char *, ...) {}

void cryptick_log_hex(cryptick_log_level_t, const char *, const uint8_t *, size_t) {}

void cryptick_log_raw(const char *) {}
