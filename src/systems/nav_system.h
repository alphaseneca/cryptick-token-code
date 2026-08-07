#ifndef CRYPTICK_NAV_SYSTEM_H
#define CRYPTICK_NAV_SYSTEM_H

#include "event_bus.h"
#include <stdint.h>

void nav_system_init(void);
void nav_system_set_account_count(int n);
void nav_system_on_event(const BusEvent &e);
void nav_system_tick(unsigned long nowMs);

UiState nav_system_state(void);
int nav_system_menu_index(void);
int nav_system_settings_index(void);
int nav_system_account_index(void);
int nav_system_account_count(void);
uint8_t nav_system_enroll_step(void);     /* 1..2 */
bool nav_system_enroll_remove(void);      /* true = show remove finger */
const char *nav_system_fido_label(void);

/** Called from FIDO bridge outside the bus when HAL changes UI request */
void nav_system_set_fido_ui(int8_t req /* 0 idle, 1 prompt, 2 processing */);

#endif
