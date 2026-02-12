#ifndef CORE_DEVICE_H
#define CORE_DEVICE_H

#include <stddef.h>
#include <stdint.h>

/** Return current Unix time in seconds (from RTC). Required for TOTP and display. */
uint32_t device_get_time_utc(void);

/** Return milliseconds since boot. Optional; for debouncing and timeouts. */
uint32_t device_millis(void);

/** Return 1 once per debounced press, 0 otherwise. Hardware read and debounce in HAL. */
int device_button_state(void);

/** Reboot the device. Optional. */
void device_reboot(void);

/** Generate random bytes for keys/nonces. Return 1 on success. Optional. */
int device_generate_rng(uint8_t *dst, size_t num);

#endif
