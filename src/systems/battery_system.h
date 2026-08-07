#ifndef CRYPTICK_BATTERY_SYSTEM_H
#define CRYPTICK_BATTERY_SYSTEM_H

#include "event_bus.h"
#include <stdint.h>

void battery_system_init(void);
void battery_system_tick(unsigned long nowMs);
ChargeState battery_system_state(void);

/** Raw samples for debug / UI (1 = high / float, 0 = low / open-drain asserted). */
uint8_t battery_system_stat1(void);
uint8_t battery_system_stat2(void);

/** Short label for status bar: "   ", "CHG", "FULL", "FLT" */
const char *battery_system_label(void);

#endif
