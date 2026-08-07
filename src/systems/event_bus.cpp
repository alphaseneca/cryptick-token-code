#include "event_bus.h"

static constexpr int BUS_CAP = 48;
static BusEvent _q[BUS_CAP];
static volatile int _head = 0;
static volatile int _tail = 0;
static volatile int _count = 0;

void bus_init(void)
{
    _head = _tail = _count = 0;
}

void bus_clear(void)
{
    _head = _tail = _count = 0;
}

bool bus_publish(const BusEvent &e)
{
    if (_count >= BUS_CAP)
        return false;
    _q[_tail] = e;
    _tail = (_tail + 1) % BUS_CAP;
    _count++;
    return true;
}

bool bus_pop(BusEvent &out)
{
    if (_count == 0)
        return false;
    out = _q[_head];
    _head = (_head + 1) % BUS_CAP;
    _count--;
    return true;
}
