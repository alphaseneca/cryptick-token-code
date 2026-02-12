#include "auth_handler.h"
#include "config.h"

static bool _authenticated = false;
static bool _fingerprint_enabled = false;
static unsigned long _lastActivityMs = 0;
static void (*_led_on_success)(void) = nullptr;
static void (*_led_on_fail)(void) = nullptr;
static void (*_led_on_clear)(void) = nullptr;

PageEnum auth_handler_page_to_show(PageEnum requested)
{
    if (requested == PAGE_CLOCK)
        return PAGE_CLOCK;
    if (!_fingerprint_enabled || _authenticated)
        return requested;
    return PAGE_AUTH_PROMPT;
}

void auth_handler_clear(void)
{
    _authenticated = false;
    _lastActivityMs = 0;
    if (_led_on_clear)
        _led_on_clear();
}

void auth_handler_set_authenticated(bool ok)
{
    _authenticated = ok;
    if (ok && _led_on_success)
        _led_on_success();
}

void auth_handler_verify_failed(void)
{
    if (_led_on_fail)
        _led_on_fail();
}

void auth_handler_set_fingerprint_enabled(bool enabled)
{
    _fingerprint_enabled = enabled;
}

void auth_handler_set_led_callbacks(void (*on_success)(void), void (*on_fail)(void), void (*on_clear)(void))
{
    _led_on_success = on_success;
    _led_on_fail = on_fail;
    _led_on_clear = on_clear;
}

void auth_handler_record_activity(unsigned long nowMs)
{
    _lastActivityMs = nowMs;
}

bool auth_handler_check_inactivity(unsigned long nowMs)
{
    if (_lastActivityMs == 0)
        return false;
    if (nowMs - _lastActivityMs >= (unsigned long)INACTIVITY_TIMEOUT_SEC * 1000)
    {
        auth_handler_clear();
        _lastActivityMs = 0;
        return true;
    }
    return false;
}
