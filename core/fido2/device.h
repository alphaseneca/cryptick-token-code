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

/** Handle one HID packet (reliable — waits for host to take the IN report).
 * */
void usbhid_send(uint8_t * msg);

/** Best-effort CTAPHID keepalive; may drop if IN endpoint busy. */
void usbhid_send_besteffort(uint8_t * msg);

/** Reboot the device.
 * */
void device_reboot(void);

/** Load the shared auth state from non-volatile storage.
 * */
int authenticator_read_state(AuthenticatorState * s);

/** Save the shared auth state to non-volatile storage.
 * */
void authenticator_write_state(AuthenticatorState * s);

/** Update CTAPHID UI/keepalive status (IDLE / PROCESSING / UPNEEDED). */
void device_set_status(uint32_t status);

/**
 * Which transport opened the transaction being processed.
 *
 * The keepalive emitted while waiting on the fingerprint has to leave by the
 * same door the request came in. It used to call ctaphid_update_status()
 * directly from the presence loop, which hardwired every keepalive onto USB
 * regardless of origin. A producer sets this before handing work to the FIDO
 * task; the presence loop only asks the HAL to send, and knows no transport.
 */
typedef enum {
    FIDO_TRANSPORT_NONE       = 0,
    FIDO_TRANSPORT_USB        = 1,
    FIDO_TRANSPORT_BLE        = 2,
    FIDO_TRANSPORT_DAEMON_BLE = 3,
} fido_transport_t;

/** Set by the producer before the FIDO task dispatches the request. */
void fido_transport_set_active(fido_transport_t t);
fido_transport_t fido_transport_active(void);

/** Emit a keepalive on whichever transport owns the current transaction. */
void fido_send_keepalive(int8_t status);

/**
 * Show / clear the BLE pairing passkey on the OLED.
 *
 * The NimBLE host task must not call nav_system_* or display_system_* (see
 * docs/ARCHITECTURE.md#threading-model). These park the caption and the UI
 * request for the Arduino loop to drain, exactly like the presence prompt.
 */
void device_show_pairing_passkey(const char *label);
void device_clear_pairing_passkey(void);

/**
 * Post a fully reassembled BLE request to the FIDO task.
 *
 * Called from the NimBLE host task. Returns 0 if the CTAP core is busy, in
 * which case the caller answers the peer with BLE_FIDO_ERR_OTHER rather than
 * queueing a transaction that would demand its own fingerprint later.
 * CMD_CANCEL is handled inline and always returns 1.
 */
int fido_ble_submit_request(uint8_t cmd, const uint8_t *msg, uint16_t len);

/** Connection state query and peer disconnect cleanup for FIDO BLE transport. */
int ble_fido_is_connected(void);
void fido_ble_on_disconnect(void);

/** After full CTAPHID writeback. allow_success_ui: only for MakeCredential/GetAssertion. */
void device_ctap_finished(uint8_t ctap_status, int allow_success_ui);

/** Millisecond sleep (used to pace CTAPHID multi-frame writeback). */
void device_delay_ms(uint32_t ms);

/** Standard button check.
 * */
int device_is_button_pressed(void);


/** Standard user presence check.  Should check for button press and return
 *  1 if confirmed, 0 if it times out.
 * */
int ctap_user_presence_test(uint32_t delay);

/** Same as ctap_user_presence_test. allow_uv_cache: consume a GetTouch credit
 *  (MakeCredential only). GetAssertion / U2F_AUTHENTICATE must pass 0.
 */
int ctap_user_presence_test_ex(uint32_t delay, int allow_uv_cache);

/** Arm a one-shot UV cache after Chrome's bogus U2F_REGISTER GetTouch. */
void ctap_uv_cache_arm_gettouch(void);

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
/** Bridge-only: host CTAPHID_CANCEL while UP is blocked on FIDO task. */
void ctaphid_cancel_request(void);
void ctaphid_push_report(const uint8_t *report);
/** OLED (display_system) and the RTC share one bus; serialise transactions. */
void i2c_mutex_init(void);
void i2c_lock(void);
void i2c_unlock(void);
uint32_t get_synced_utc(void);
/** Immediate soft-clock (and HW RTC if present). Used by SETTIME / OATH SET_TIME. */
void set_synced_utc(uint32_t utc);
void device_set_time_utc(uint32_t utc);

/**
 * Fingerprint presence when caller blocks the Arduino loop (CDC OATH UV).
 * FIDO task path leaves matching to main-loop nav; main-core path self-services.
 */
void device_presence_fp_begin(void);
void device_presence_fp_end(void);
int device_presence_fp_poll(void); /* 1=match, 0=wait */

/** 1 when the caller is the core-0 FIDO task, 0 on the Arduino loop. */
int device_on_fido_task(void);

/**
 * Hand a prompt caption ("Manage", "Code", …) to the UI.
 *
 * nav_system is owned by the Arduino loop, so the FIDO task may not call it.
 * Instead it parks the caption here and the loop drains it with
 * device_take_ui_label() alongside the _fido_ui_request poll.
 */
void device_set_ui_label(const char *label);
/** Main loop only: copy out a pending caption. 1 when one was waiting. */
int device_take_ui_label(char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
