#ifndef SRC_AUTH_HANDLER_H
#define SRC_AUTH_HANDLER_H

#include "navigation.h"

/**
 * Auth handler: owns authentication, inactivity timeout, and fingerprint LED feedback.
 * Only the clock page does not require fingerprint; other pages require verification when fingerprint is enabled.
 * Clear auth when user returns to clock (button) or on inactivity timeout. * *LED: green on success, red on fail, off when auth cleared.
 */

/** Which page to show when user requested a page. Clock always allowed; others require auth when fingerprint enabled. */
PageEnum auth_handler_page_to_show(PageEnum requested);

/** Clear auth (when returning to clock or on inactivity). Calls on_clear LED callback if set. */
void auth_handler_clear(void);

/** Call when verification succeeds (sets authenticated, calls on_success LED callback). */
void auth_handler_set_authenticated(bool ok);

/** Call when verification fails (wrong fingerprint; calls on_fail LED callback). */
void auth_handler_verify_failed(void);

/** Call when fingerprint is enabled and ready (or disabled). */
void auth_handler_set_fingerprint_enabled(bool enabled);

/** Register LED callbacks: on_success = green (auth success), on_fail = red (wrong finger), on_clear = LED off (auth cleared). Any may be NULL. */
void auth_handler_set_led_callbacks(void (*on_success)(void), void (*on_fail)(void), void (*on_clear)(void));

/** Call when user becomes active on a protected page (button press or entering page). Used for inactivity timeout. */
void auth_handler_record_activity(unsigned long nowMs);

/** If inactivity timeout reached, clears auth and returns true (caller should go to clock). Otherwise returns false. */
bool auth_handler_check_inactivity(unsigned long nowMs);

#endif
