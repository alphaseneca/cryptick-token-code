#ifndef CRYPTICK_NAV_SYSTEM_H
#define CRYPTICK_NAV_SYSTEM_H

#include "event_bus.h"
#include <stdint.h>
#include <stddef.h>

void nav_system_init(void);
void nav_system_set_account_count(int n);
void nav_system_on_event(const BusEvent &e);
void nav_system_tick(unsigned long nowMs);

UiState nav_system_state(void);
int nav_system_menu_index(void);
int nav_system_settings_index(void);
int nav_system_account_index(void);
int nav_system_account_count(void);
int nav_system_home_card(void);
void nav_system_set_home_card(int card);

/** Settings list, rendered by display_system (label depends on live state). */
int nav_system_settings_count(void);
void nav_system_settings_label(int idx, char *out, size_t cap);

/** Bluetooth menu list, rendered by display_system. */
int nav_system_ble_menu_index(void);
int nav_system_ble_menu_count(void);
void nav_system_ble_menu_label(int idx, char *out, size_t cap);

/**
 * PIV PIN entry (UI_PIV_PIN_ENTRY). Digit count, the position the encoder is
 * currently scrolling, and the value (0-9) at a given position — rendered by
 * display_system as a row of digit boxes, the one at nav_system_piv_pin_pos()
 * drawn selected the same way draw_list_row() draws a selected row.
 */
int nav_system_piv_pin_len(void);
int nav_system_piv_pin_pos(void);
uint8_t nav_system_piv_pin_digit(int i);

/*
 * Idle sleep. This powers the OLED down and drops the unlock session; the MCU
 * and USB stay up so the token keeps answering the host. See UI_SLEEP_TIMEOUT_SEC
 * in board_config.h for why it is not a real SoC sleep.
 */
bool nav_system_is_asleep(void);
/** Wake and reset the idle clock. Safe to call when already awake. */
void nav_system_wake(void);
/** Sleep immediately, ignoring the remaining idle time. */
void nav_system_sleep_now(void);
/** Reset the idle clock without changing state (host activity, console input). */
void nav_system_note_activity(unsigned long nowMs);
uint16_t nav_system_sleep_timeout_sec(void);
/** 0 disables sleep. `persist` writes it to NVS. Clamped to UI_SLEEP_MAX_SEC. */
void nav_system_set_sleep_timeout_sec(uint16_t sec, bool persist);
uint8_t nav_system_enroll_step(void);     /* 1..2 */
bool nav_system_enroll_remove(void);      /* true = show remove finger */
const char *nav_system_fido_label(void);
/** Short status after enroll fail/success (may be empty) */
const char *nav_system_enroll_message(void);

/** OLED first line during UV prompt (FIDO or host OATH management). */
void nav_system_set_fido_label(const char *label);

/** Called from FIDO bridge outside the bus when HAL changes UI request */
void nav_system_set_fido_ui(int8_t req /* 0 idle, 1 prompt, 2 processing */);

#endif
