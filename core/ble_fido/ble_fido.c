#include "ble_fido.h"
#include <string.h>

static bool _ble_active = false;

void ble_fido_init(void)
{
    _ble_active = false;
    /* Future: NimBLE GATT FIDO service UUID, MTU fragment reassembly → ctaphid. */
}

void ble_fido_poll(void) {}

bool ble_fido_active(void) { return _ble_active; }

void ble_fido_push_ctaphid_report(const uint8_t report[64])
{
    (void)report;
    /* When BLE is live: ctaphid_push_report(report); */
}
