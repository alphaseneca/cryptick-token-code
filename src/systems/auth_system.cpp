#include "auth_system.h"
#include "event_bus.h"
#include <board_config.h>
#include <cryptick_log.h>

static bool _authenticated = false;
static bool _fpEnabled = false;
static unsigned long _lastActivityMs = 0;

void auth_system_init(void)
{
    _authenticated = false;
    _lastActivityMs = 0;
    CLOG_I("AUTH", "init");
}

void auth_system_set_fingerprint_enabled(bool enabled)
{
    if (_fpEnabled != enabled)
        CLOG_D("AUTH", "fp_enabled=%d", enabled ? 1 : 0);
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
    if (_authenticated)
        CLOG_I("AUTH", "session cleared");
    _authenticated = false;
    _lastActivityMs = 0;
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_CLEARED;
    bus_publish(e);
}

void auth_system_on_match(void)
{
    CLOG_I("AUTH", "session unlocked (fingerprint)");
    _authenticated = true;
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_OK;
    bus_publish(e);
}

void auth_system_on_fail(void)
{
    CLOG_W("AUTH", "fingerprint fail");
    BusEvent e{};
    e.type = EVT_AUTH;
    e.kind = AUTH_FAIL;
    bus_publish(e);
}

void auth_system_record_activity(unsigned long nowMs)
{
    _lastActivityMs = nowMs;
    CLOG_T("AUTH", "activity t=%lu", (unsigned long)nowMs);
}

void auth_system_tick(unsigned long nowMs)
{
    if (_lastActivityMs == 0) return;
    if (!_authenticated) return;
    if (nowMs - _lastActivityMs >= (unsigned long)INACTIVITY_TIMEOUT_SEC * 1000UL) {
        CLOG_D("AUTH", "inactivity timeout %us", (unsigned)INACTIVITY_TIMEOUT_SEC);
        auth_system_clear();
    }
}
