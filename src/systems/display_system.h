#ifndef CRYPTICK_DISPLAY_SYSTEM_H
#define CRYPTICK_DISPLAY_SYSTEM_H

#include "event_bus.h"
#include "totp.h"
#include <vector>

void display_system_init(void);
void display_system_tick(unsigned long nowMs);
void display_system_on_event(const BusEvent &e);
void display_system_set_credentials(const std::vector<TOTPCredential> *creds);
void display_system_set_user(const char *name);
void display_system_force_redraw(void);

/**
 * Opening animation, ~BOOT_ANIM_MS long and fully synchronous. Call once from
 * setup() after display_system_init(); the panel retry path never runs it.
 */
void display_system_boot_animation(void);

#endif
