#include "auth_system.h"
#include "event_bus.h"
#include <board_config.h>

static bool _authenticated = false;
static bool _fpEnabled = false;
static unsigned long _lastActivityMs = 0;

void auth_system_init(void)
{
    _authenticated = false;
    _lastActivityMs = 0;
}

void auth_system_set_fingerprint_enabled(bool enabled)
{
    _fpEnabled = enabled;
}

bool auth_system_needs_auth(void)
{
    return _fpEnabled && !_authenticated;
}

bool auth_system_is_authenticated(void)
{
    return _authenticated;
}

void auth_system_clear(void)
{
    _authenticated = false;
    _lastActivityMs = 0;
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_CLEARED;
    bus_publish(e);
}

void auth_system_on_match(void)
{
    _authenticated = true;
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_OK;
    bus_publish(e);
}

void auth_system_on_fail(void)
{
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_FAIL;
    bus_publish(e);
}

void auth_system_record_activity(unsigned long nowMs)
{
    _lastActivityMs = nowMs;
}

void auth_system_tick(unsigned long nowMs)
{
    if (_lastActivityMs == 0) return;
    if (!_authenticated) return;
    if (nowMs - _lastActivityMs >= (unsigned long)INACTIVITY_TIMEOUT_SEC * 1000UL) {
        auth_system_clear();
    }
}
