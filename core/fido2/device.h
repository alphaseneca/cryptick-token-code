// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#ifndef _DEVICE_H
#define _DEVICE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "storage.h"

/** Millisecond timestamp. Solo C units map millis() → device_millis() under Arduino
 *  to avoid clashing with Arduino's unsigned long millis() in C++. */
uint32_t device_millis(void);
#if defined(ARDUINO)
#if !defined(__cplusplus)
#define millis() device_millis()
#endif
#else
uint32_t millis(void);
#endif

/** Handle one HID packet.
 * */
void usbhid_send(uint8_t * msg);

/** Reboot the device.
 * */
void device_reboot(void);

/** Load the shared auth state from non-volatile storage.
 * */
int authenticator_read_state(AuthenticatorState * s);

/** Save the shared auth state to non-volatile storage.
 * */
void authenticator_write_state(AuthenticatorState * s);

/** Not used.
 * */
void device_set_status(uint32_t status);

/** Standard button check.
 * */
int device_is_button_pressed(void);


/** Standard user presence check.  Should check for button press and return
 *  1 if confirmed, 0 if it times out.
 * */
int ctap_user_presence_test(uint32_t delay);

/** Standard user presence check.  Set whether it is always confirmed or not.
 * */
void device_disable_up(bool disable);

/** Use hardware to generate random number.
 * */
int ctap_generate_rng(uint8_t * dst, size_t num);

/** Efficient persistent counter increase.
 * */
uint32_t ctap_atomic_count(uint32_t amount);

/** Resident Secret (RK) management. 
 *  Stored separately from AuthenticatorState.
 * */
void ctap_reset_rk(void);
uint32_t ctap_rk_size(void);
void ctap_store_rk(int index, CTAP_residentKey * rk);
void ctap_delete_rk(int index);
void ctap_load_rk(int index, CTAP_residentKey * rk);
void ctap_overwrite_rk(int index, CTAP_residentKey * rk);

/** Not implemented yet.
 * */
void device_wink(void);

typedef enum {
    DEVICE_CLOCK_SLOW,
    DEVICE_CLOCK_FAST,
} DEVICE_CLOCK_RATE;

/** Set the device clock rate.
 * */
void device_set_clock_rate(DEVICE_CLOCK_RATE param);

/** Return true if NFC is used.
 * */
int device_is_nfc(void);

/** Return the device attestation key.
 * */
uint8_t * device_get_attestation_key(void);

/** Read the device attestation cert.
 * */
void device_attestation_read_cert_der(uint8_t * dst);

/** Get size of the attestation cert.
 * */
int device_attestation_cert_der_get_size(void);

/** Read the device AAGUID.
 * */
void device_read_aaguid(uint8_t * dst);

/** Enter ROM USB download mode (Cryptick product HAL). */
void cryptick_enter_bootloader(void);
/** Lock stubs (no product lock policy yet). */
uint8_t cryptick_is_locked(void);
void cryptick_lock_if_not_already(void);

/** Bridge functions for main application
 * */
typedef enum {
    BTN_CENTER = 0,
    BTN_LEFT   = 1,
    BTN_RIGHT  = 2,
    BTN_COUNT  = 3
} ButtonID;

void device_hal_init(void);
void device_hal_heartbeat(void);
int device_button_pressed(int btn);
uint32_t device_get_time_utc(void);
uint8_t ctaphid_is_processing(void);
void ctaphid_confirm_user_presence(void);
void ctaphid_cancel_request(void);
void ctaphid_push_report(const uint8_t *report);
void i2c_lock(void);
void i2c_unlock(void);
uint32_t get_synced_utc(void);

#ifdef __cplusplus
}
#endif

#endif
