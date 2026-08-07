#ifndef CRYPTICK_AUTH_SYSTEM_H
#define CRYPTICK_AUTH_SYSTEM_H

#include <stdbool.h>

void auth_system_init(void);
void auth_system_tick(unsigned long nowMs);
bool auth_system_needs_auth(void);
bool auth_system_is_authenticated(void);
void auth_system_set_fingerprint_enabled(bool enabled);
void auth_system_record_activity(unsigned long nowMs);
void auth_system_on_match(void);
void auth_system_on_fail(void);
void auth_system_clear(void);

#endif
