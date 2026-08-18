#ifndef CRYPTICK_CREDENTIAL_STORE_H
#define CRYPTICK_CREDENTIAL_STORE_H

/**
 * Lock around the global TOTP `credentials` vector (defined in main.cpp).
 *
 * Two cores touch it:
 *   - FIDO task (core 0): CTAPHID OATH PUT / DELETE / PUT_OTPAUTH insert,
 *     erase and re-save entries, which can reallocate the vector.
 *   - Arduino loop (core 1): the serial CLI mutates it, and the OLED render
 *     path walks it to draw the current code.
 *
 * Without this lock a reallocation on core 0 frees the storage that core 1 is
 * mid-iteration over, so the renderer reads dangling `String` bodies.
 *
 * The mutex is recursive: OATH handlers hold it across helpers in `oath_ops`
 * that lock again.
 */

#ifdef __cplusplus
extern "C" {
#endif

void credential_store_init(void);
void credential_store_lock(void);
void credential_store_unlock(void);

#ifdef __cplusplus
}

/** Scoped guard so early returns cannot leak the lock. */
class CredentialLock {
public:
    CredentialLock() { credential_store_lock(); }
    ~CredentialLock() { credential_store_unlock(); }
    CredentialLock(const CredentialLock &) = delete;
    CredentialLock &operator=(const CredentialLock &) = delete;
};
#endif

#endif /* CRYPTICK_CREDENTIAL_STORE_H */
