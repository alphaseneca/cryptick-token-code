#include "event_bus.h"
#include <cryptick_log.h>
#include <Arduino.h>

/*
 * Publishers run on both cores: most systems publish from the Arduino loop,
 * but the CTAPHID OATH handler reaches bus_publish() from the FIDO task
 * (core 0) via the user-verification path. head/tail/count must therefore be
 * updated as one indivisible step, which `volatile` alone does not give us.
 */
static constexpr int BUS_CAP = 48;
static BusEvent _q[BUS_CAP];
static int _head = 0;
static int _tail = 0;
static int _count = 0;
static portMUX_TYPE _bus_mux = portMUX_INITIALIZER_UNLOCKED;

static const char *evt_name(BusEventType t)
{
    switch (t) {
    case EVT_INPUT: return "INPUT";
    case EVT_FP: return "FP";
    case EVT_BATTERY: return "BAT";
    case EVT_AUTH: return "AUTH";
    case EVT_UI_STATE: return "UI";
    case EVT_CMD: return "CMD";
    default: return "?";
    }
}

void bus_init(void)
{
    portENTER_CRITICAL(&_bus_mux);
    _head = _tail = _count = 0;
    portEXIT_CRITICAL(&_bus_mux);
    CLOG_D("BUS", "init cap=%d", BUS_CAP);
}

void bus_clear(void)
{
    portENTER_CRITICAL(&_bus_mux);
    _head = _tail = _count = 0;
    portEXIT_CRITICAL(&_bus_mux);
    CLOG_D("BUS", "cleared");
}

bool bus_publish(const BusEvent &e)
{
    /* Log outside the critical section — cryptick_log() may block on the CDC. */
    int depth;
    portENTER_CRITICAL(&_bus_mux);
    if (_count >= BUS_CAP) {
        portEXIT_CRITICAL(&_bus_mux);
        CLOG_W("BUS", "full drop type=%s kind=%u a=%u b=%u",
               evt_name(e.type), (unsigned)e.kind, (unsigned)e.a, (unsigned)e.b);
        return false;
    }
    _q[_tail] = e;
    _tail = (_tail + 1) % BUS_CAP;
    depth = ++_count;
    portEXIT_CRITICAL(&_bus_mux);

    CLOG_T("BUS", "pub type=%s kind=%u a=%u b=%u n=%d",
           evt_name(e.type), (unsigned)e.kind, (unsigned)e.a, (unsigned)e.b, depth);
    return true;
}

bool bus_pop(BusEvent &out)
{
    int depth;
    portENTER_CRITICAL(&_bus_mux);
    if (_count == 0) {
        portEXIT_CRITICAL(&_bus_mux);
        return false;
    }
    out = _q[_head];
    _head = (_head + 1) % BUS_CAP;
    depth = --_count;
    portEXIT_CRITICAL(&_bus_mux);

    CLOG_T("BUS", "pop type=%s kind=%u a=%u b=%u n=%d",
           evt_name(out.type), (unsigned)out.kind, (unsigned)out.a, (unsigned)out.b, depth);
    return true;
}
