#ifndef HAL_DEVICE_HAL_H
#define HAL_DEVICE_HAL_H

/**
 * Platform HAL surface used by the application and core/fido2.
 * Implementation lives in core/fido2/hal_esp32.cpp.
 */
#include "device.h"

#ifdef __cplusplus
extern "C" {
#endif

void device_hal_init(void);
void i2c_lock(void);
void i2c_unlock(void);
void i2c_mutex_init(void);

#ifdef __cplusplus
}
#endif

#endif
