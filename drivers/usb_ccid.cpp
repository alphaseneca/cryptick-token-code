#include "usb_ccid.h"

/* Product build does not register a CCID interface yet (endpoint budget + CTK WIP). */
void usb_ccid_init(void) {}
void usb_ccid_poll(void) {}
bool usb_ccid_enabled(void) { return false; }
