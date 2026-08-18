#ifndef CRYPTICK_CONSOLE_H
#define CRYPTICK_CONSOLE_H

/**
 * Product console stream (CDC when USB product stack is on).
 * MODE=0 TinyUSB: USBLog is USBCDC (VID 0x1209 / PID 0xBEEE).
 * MODE=1 JTAG lab: USBLog is Serial (Espressif 303A).
 */
#include <Arduino.h>

#ifdef __cplusplus
#include "usb_device.h"
#define CryptickLog USBLog
#else
#define CryptickLog Serial
#endif

#endif /* CRYPTICK_CONSOLE_H */
