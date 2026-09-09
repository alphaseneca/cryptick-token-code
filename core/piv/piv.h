#ifndef CORE_PIV_H
#define CORE_PIV_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * PIV card application (NIST SP 800-73-4).
 *
 * This is what macOS CryptoTokenKit and Linux pam_pkcs11 actually talk to for
 * login and screen unlock. It is deliberately transport-independent: APDUs in,
 * APDUs out, no idea whether they arrived over USB CCID or a BLE-backed
 * virtual reader. That is the same seam ctap_request() gives the FIDO stack,
 * and for the same reason — see docs/MAC_LOGIN.md.
 *
 * Crypto, storage and user presence live behind piv_hal_t so the host test
 * suite can drive the whole applet without an ESP32.
 */

/** NIST SP 800-73 PIV AID: RID(5) + PIX(4) + version(2) */
#define PIV_AID_LEN 11

/**
 * Shortest AID a SELECT may carry: RID + PIX, without the trailing version
 * bytes. SP 800-73 provides for selecting the PIV Card Application by a
 * right-truncated AID, and ISO 7816-4 SELECT with P1=0x04 is a DF-name prefix
 * match, so clients are entitled to send only these 9 bytes.
 */
#define PIV_AID_MIN_LEN 9

/* --- Instructions -------------------------------------------------------- */

#define PIV_INS_VERIFY               0x20
#define PIV_INS_CHANGE_REFERENCE     0x24
#define PIV_INS_GENERATE_KEYPAIR     0x47
#define PIV_INS_GENERAL_AUTHENTICATE 0x87
#define PIV_INS_SELECT               0xA4
#define PIV_INS_GET_RESPONSE         0xC0
#define PIV_INS_GET_DATA             0xCB
#define PIV_INS_PUT_DATA             0xDB

/* --- Key slots (SP 800-73-4 part 1, table 3) ----------------------------- */

#define PIV_SLOT_AUTHENTICATION 0x9A /* PIV Authentication — login  */
#define PIV_SLOT_SIGNATURE      0x9C /* Digital Signature           */
#define PIV_SLOT_KEY_MANAGEMENT 0x9D /* Key Management — decryption */
#define PIV_SLOT_CARD_AUTH      0x9E /* Card Authentication         */

/* --- Data object tags (the 3-byte BER tags under 0x5C) ------------------- */

#define PIV_OBJ_CCC       0x5FC107 /* Card Capability Container    */
#define PIV_OBJ_CHUID     0x5FC102 /* Card Holder Unique ID        */
#define PIV_OBJ_CERT_9A   0x5FC105
#define PIV_OBJ_CERT_9C   0x5FC10A
#define PIV_OBJ_CERT_9D   0x5FC10B
#define PIV_OBJ_CERT_9E   0x5FC101

/* --- Status words -------------------------------------------------------- */

#define PIV_SW_OK                    0x9000
#define PIV_SW_WRONG_LENGTH          0x6700
#define PIV_SW_SECURITY_NOT_SATISFIED 0x6982
#define PIV_SW_AUTH_BLOCKED          0x6983
#define PIV_SW_WRONG_DATA            0x6A80
#define PIV_SW_NOT_FOUND             0x6A82
#define PIV_SW_WRONG_P1P2            0x6A86
#define PIV_SW_INS_UNSUPPORTED       0x6D00
#define PIV_SW_CLA_UNSUPPORTED       0x6E00
/* 0x63C0 | retries — VERIFY failed, this many attempts remain. */
#define PIV_SW_VERIFY_FAILED(retries) (0x63C0 | ((retries) & 0x0F))

/* --- Limits -------------------------------------------------------------- */

/** PIN block is always 8 bytes, ASCII digits, 0xFF padded (SP 800-73-4). */
#define PIV_PIN_BLOCK_LEN 8
#define PIV_PIN_MIN_LEN   6
#define PIV_PIN_MAX_LEN   8
#define PIV_PIN_MAX_RETRIES 3

/**
 * Largest generated response. The biggest is the GENERATE reply: a 65-byte
 * uncompressed point inside 0x86 inside 0x7F49.
 */
#define PIV_SCRATCH_LEN 128

/** Uncompressed P-256 point: 0x04 ‖ X(32) ‖ Y(32). */
#define PIV_PUBKEY_LEN 65

/** PIV GUID, as carried in the CHUID's 0x34 field. */
#define PIV_GUID_LEN 16

/* --- Platform hooks ------------------------------------------------------ */

typedef struct {
    /**
     * Look up a stored data object. Returns 1 and points *out at storage the
     * applet may read until the next APDU; 0 if the object is absent.
     * Certificates are large, so this hands back a pointer rather than a copy
     * and the applet chains from it directly.
     */
    int (*get_object)(uint32_t tag, const uint8_t **out, size_t *out_len);

    /** Persist a data object. Returns 1 on success. */
    int (*set_object)(uint32_t tag, const uint8_t *data, size_t len);

    /**
     * Sign a 32-byte hash with the slot's private key, writing a DER
     * ECDSA-Sig-Value. Returns 1 on success.
     */
    int (*sign_p256)(uint8_t slot, const uint8_t *hash32,
                     uint8_t *der_out, size_t *der_len);

    /** Check a PIN. Returns 1 if correct. Retry accounting is the applet's. */
    int (*pin_check)(const uint8_t *pin, size_t len);

    /** Replace the PIN. Returns 1 on success. */
    int (*pin_set)(const uint8_t *pin, size_t len);

    /**
     * Write the slot's public key as a 65-byte uncompressed point (0x04 ‖ X ‖ Y).
     * Without this there is no way to issue a certificate against the key, and
     * a PIV card with no certificate cannot log anyone in.
     */
    int (*public_key)(uint8_t slot, uint8_t *out65);

    /**
     * Write the device's 16-byte PIV GUID.
     *
     * Must be stable for the life of the device and distinct between devices:
     * hosts key their record of the card on it, so a shared GUID would make
     * two tokens look like the same card. Returns 1 on success; without it the
     * synthesised CHUID cannot be built and GET DATA reports the object absent.
     */
    int (*device_guid)(uint8_t *out16);

    /**
     * Roll the slot's key. Returns 1 on success.
     *
     * Keys are derived, not stored, so this bumps a per-slot generation
     * counter that feeds the derivation — a genuinely new key with nothing
     * new to persist. Any certificate already issued for the slot stops
     * matching, which is the correct meaning of generating a key pair.
     */
    int (*key_generate)(uint8_t slot);

    /** Persisted retry counter — it must survive a power cycle. */
    int  (*pin_retries_get)(void);
    void (*pin_retries_set)(int retries);

    /**
     * User presence (fingerprint) for a private-key operation. Returns 1 when
     * confirmed. Must route through the same gate as FIDO — see
     * docs/ARCHITECTURE.md#threading-model — never a second presence flag.
     * May be NULL, in which case the PIN alone authorises signing.
     */
    int (*user_presence)(uint8_t slot);
} piv_hal_t;

/** Install the platform hooks and reset applet state. */
void piv_init(const piv_hal_t *hal);

/** Forget PIN verification and any chained response (card reset / deselect). */
void piv_reset(void);

/** Non-zero once the application PIN has been verified this session. */
int piv_pin_is_verified(void);

/**
 * Handle a single ISO 7816 APDU.
 *
 * Returns the response length written to `out` (including the two status
 * bytes), or -1 if the arguments are unusable. Responses longer than the
 * requested Le are truncated and reported with 61xx; the client collects the
 * rest with GET RESPONSE.
 */
int piv_handle_apdu(const uint8_t *cmd, size_t cmd_len, uint8_t *out, size_t out_max);

/**
 * Install the ESP32 platform hooks (piv_hal_esp32.cpp) and log the applet
 * state. Call once at boot, after LittleFS and the crypto stack are up.
 */
void piv_hal_init(void);

#ifdef __cplusplus
}
#endif

#endif
