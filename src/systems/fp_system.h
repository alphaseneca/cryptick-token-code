#ifndef CRYPTICK_FP_SYSTEM_H
#define CRYPTICK_FP_SYSTEM_H

#include <stdint.h>
#include <stdbool.h>

#include "event_bus.h"

void fp_system_init(void);
void fp_system_tick(unsigned long nowMs);
void fp_system_on_cmd(const BusEvent &e);
bool fp_system_ready(void);
uint16_t fp_system_template_count(void);
/** True while MATCH_AUTH or MATCH_FIDO GenImg poll is active. */
bool fp_system_match_active(void);

/** Raw sensor for serial commands only. May be null if disabled. */
void *fp_system_driver(void);

#endif
