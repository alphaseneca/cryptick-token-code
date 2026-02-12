#ifndef SRC_DEVICE_HAL_H
#define SRC_DEVICE_HAL_H

#include "../core/device.h"

/** Call once at startup after Wire/RTC are initialized. */
void device_hal_init(void);

#endif
