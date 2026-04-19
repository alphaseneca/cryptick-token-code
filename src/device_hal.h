#ifndef SRC_DEVICE_HAL_H
#define SRC_DEVICE_HAL_H

#include "../core/fido2/device.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Call once at startup after Wire/RTC are initialized. */
void device_hal_init(void);
void i2c_lock();
void i2c_unlock();
void i2c_mutex_init();

#ifdef __cplusplus
}
#endif

#endif
