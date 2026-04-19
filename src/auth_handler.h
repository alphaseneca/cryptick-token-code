#ifndef SRC_AUTH_HANDLER_H
#define SRC_AUTH_HANDLER_H

/**
 * Auth handler: owns authentication state, inactivity timeout, and
 * fingerprint LED feedback.
 *
 * Protected pages require fingerprint verification when fingerprint is
 * enabled.  Auth clears on inactivity timeout or when explicitly cleared.
 */

/** Returns true if authentication is required (fingerprint enabled and user not yet authenticated). */
bool auth_handler_needs_auth(void);

/** Clear auth state (on inactivity or returning to clock). Calls on_clear LED callback if set. */
void auth_handler_clear(void);

/** Call when verification succeeds (sets authenticated, calls on_success LED callback). */
void auth_handler_set_authenticated(bool ok);

/** Call when verification fails (wrong fingerprint; calls on_fail LED callback). */
void auth_handler_verify_failed(void);

/** Enable or disable fingerprint requirement. */
void auth_handler_set_fingerprint_enabled(bool enabled);

/** Register LED callbacks for auth events. Any may be NULL. */
void auth_handler_set_led_callbacks(void (*on_success)(void), void (*on_fail)(void), void (*on_clear)(void));

/** Record user activity for inactivity timeout tracking. */
void auth_handler_record_activity(unsigned long nowMs);

/** Check inactivity timeout. Returns true if timed out (caller should return to clock). Clears auth. */
bool auth_handler_check_inactivity(unsigned long nowMs);

#endif
