#ifndef CRYPTICK_INPUT_SYSTEM_H
#define CRYPTICK_INPUT_SYSTEM_H

/** Owns all physical input pins; publishes EVT_INPUT (key press edges). */
void input_system_init(void);
void input_system_tick(unsigned long nowMs);

#endif
