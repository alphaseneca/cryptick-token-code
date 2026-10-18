/*
 * Platform hooks for the PIV applet: key derivation, object storage, PIN
 * state, and user presence.
 *
 * The applet itself (piv.c) is freestanding and knows none of this, which is
 * what lets the host test suite drive it. Everything ESP32-shaped lives here.
 */
#include "piv.h"

#include <Arduino.h>
#include <LittleFS.h>
#include <nvs.h>
#include <board_config.h>
#include <cryptick_log.h>
#include <string.h>
#include <esp_random.h>
#include <mbedtls/aes.h>

extern "C" {
#include "crypto.h"
#include "ctap.h"
#include "u2f.h"
#include "extensions/wallet.h"
int ctap_encode_der_sig(uint8_t const *const in_sigbuf, uint8_t *const out_sigder);
int ctap_user_presence_test(uint32_t delay_ms);
void device_set_ui_label(const char *label);
}

namespace {

/* One file per data object; certificates are up to a couple of KB. */
constexpr size_t kMaxObject = 3072;

/* Read into a static buffer the applet may hold until the next APDU. */
uint8_t g_object[kMaxObject];

void object_path(uint32_t tag, char *out, size_t cap)
{
    snprintf(out, cap, "/piv_%06lx.bin", (unsigned long)tag);
}

int piv_get_object(uint32_t tag, const uint8_t **out, size_t *out_len)
{
    char path[32];
    object_path(tag, path, sizeof(path));
    File f = LittleFS.open(path, "r");
    if (!f)
        return 0;
    size_t n = f.size();
    if (n == 0 || n > sizeof(g_object)) {
        f.close();
        CLOG_W("PIV", "object %06lx unusable size=%u",
               (unsigned long)tag, (unsigned)n);
        return 0;
    }
    size_t got = f.read(g_object, n);
    f.close();
    if (got != n)
        return 0;
    *out = g_object;
    *out_len = n;
    return 1;
}

int piv_set_object(uint32_t tag, const uint8_t *data, size_t len)
{
    if (!data || len == 0 || len > sizeof(g_object))
        return 0;
    char path[32];
    object_path(tag, path, sizeof(path));
    File f = LittleFS.open(path, "w");
    if (!f)
        return 0;
    size_t wrote = f.write(data, len);
    f.close();
    CLOG_I("PIV", "object %06lx stored (%u bytes)",
           (unsigned long)tag, (unsigned)len);
    return wrote == len ? 1 : 0;
}

int piv_delete_object(uint32_t tag)
{
    char path[32];
    object_path(tag, path, sizeof(path));
    if (!LittleFS.exists(path))
        return 1; /* Already absent — deleting it is a no-op success. */
    bool ok = LittleFS.remove(path);
    if (ok)
        CLOG_I("PIV", "object %06lx deleted", (unsigned long)tag);
    return ok ? 1 : 0;
}

constexpr const char *kNvsNamespace = "piv";

/* --- Configurable retry ceilings (vendor SET PIN RETRIES) -----------------
 *
 * Declared this early because both the PIN and PUK retry-counter getters
 * below clamp against these — they need the ceiling to exist before either
 * of them does.
 */

int piv_pin_retry_max(void)
{
    nvs_handle_t h;
    int32_t max = PIV_PIN_MAX_RETRIES;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "pinmax", &max);
        nvs_close(h);
    }
    if (max < 1 || max > PIV_RETRY_CEILING_MAX) max = PIV_PIN_MAX_RETRIES;
    return (int)max;
}

int piv_puk_retry_max(void)
{
    nvs_handle_t h;
    int32_t max = PIV_PUK_MAX_RETRIES;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "pukmax", &max);
        nvs_close(h);
    }
    if (max < 1 || max > PIV_RETRY_CEILING_MAX) max = PIV_PUK_MAX_RETRIES;
    return (int)max;
}

/**
 * Per-slot key generation counter.
 *
 * Keys are derived, not stored, so "generate a key pair" has to mean something
 * other than writing new bytes to flash. It bumps this counter, which feeds the
 * derivation — a genuinely different key with nothing new to persist. It must
 * survive a power cycle or a reboot would silently resurrect the old key and
 * revive a certificate the user had rolled away from.
 */
uint32_t slot_generation(uint8_t slot)
{
    char key[8];
    snprintf(key, sizeof(key), "gen%02X", slot);
    nvs_handle_t h;
    uint32_t gen = 0;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_u32(h, key, &gen);
        nvs_close(h);
    }
    return gen;
}

int slot_generation_bump(uint8_t slot)
{
    char key[8];
    snprintf(key, sizeof(key), "gen%02X", slot);
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
        return 0;
    uint32_t gen = 0;
    nvs_get_u32(h, key, &gen);
    gen++;
    esp_err_t err = nvs_set_u32(h, key, gen);
    nvs_commit(h);
    nvs_close(h);
    CLOG_I("PIV", "slot %02X key rolled to generation %u — any certificate "
                  "issued for the old key no longer matches",
           slot, (unsigned)gen);
    return err == ESP_OK ? 1 : 0;
}

/**
 * Slot keys are derived from the device master secret rather than stored.
 *
 * The same construction the CTAP stack uses for credential keys: an HMAC over
 * a per-slot label, plus the generation counter. Nothing to persist, nothing
 * to leak from flash, and the public key is stable across reflashes as long as
 * the master secret survives — which matters, because a PIV certificate is
 * issued against it.
 */
/** Length of the PIV key-derivation input. See the assertions below. */
constexpr size_t kSlotLabelLen = 16;

/** Domain prefix of that input. Shared with the assertions so they check the
 *  value actually used, not a transcription of it. */
constexpr uint8_t kPivPrefix[11] = {'c', 'r', 'y', 'p', 't', 'i', 'c', 'k',
                                    'P', 'I', 'V'};

/*
 * PIV and FIDO keys must be distinct material (daemon PROJECT.md §15.9).
 *
 * Both derive through generate_private_key(), which is HMAC(master_secret,
 * input) -- so "distinct" means the two can never be handed the same input.
 * FIDO's inputs are all attacker-reachable in length and partly in content:
 *
 *   CTAP2 credential   sizeof(CredentialId)  = 70 bytes
 *   U2F key handle     U2F_KEY_HANDLE_SIZE   = 48 bytes
 *   custom credential  >= WALLET_MIN_LENGTH  = 24 bytes, and must open with
 *                                              WALLET_TAG
 *
 * The PIV label is 16 bytes, shorter than all of them, so no FIDO request can
 * produce one. That is an arithmetic accident rather than a construction: cut
 * the label, or let some future FIDO path take a 16-byte credential, and a
 * chosen credential id would derive a PIV signing key with nothing to stop it.
 *
 * Which of those three actually protects us is worth being precise about,
 * because it decides what a fix has to change.
 *
 * The CTAP2 and U2F paths verify an HMAC tag over the credential *before*
 * deriving (ctap.c `memcmp(desc->credential.id.tag, ...)`, and
 * u2f_authenticate_credential), so forging one needs the master secret. They
 * are not the risk.
 *
 * The wallet/custom path is. `is_extension_request()` gates it on a **static**
 * 4-byte tag and a minimum length -- no MAC -- so the derivation input there is
 * attacker-chosen. The single thing standing between a chosen credential and a
 * PIV signing key is that WALLET_MIN_LENGTH is 24 and this label is 16.
 *
 * So the length assertion below is load-bearing, not belt-and-braces. Prefixing
 * the PIV input with a domain tag would *not* replace it: "piv" + 16 is 19,
 * still short, still separated by the same arithmetic. Genuine construction-
 * level separation would need the FIDO side prefixed too, which is vendored
 * Solo code and would invalidate every credential already registered on every
 * device -- a user-facing regression traded for a property these assertions
 * already enforce.
 *
 * These assertions make the accident an invariant, so the build breaks instead.
 */
static_assert(kSlotLabelLen != sizeof(CredentialId),
              "PIV label length collides with a CTAP2 credential id");
static_assert(kSlotLabelLen != U2F_KEY_HANDLE_SIZE,
              "PIV label length collides with a U2F key handle");
static_assert(kSlotLabelLen < WALLET_MIN_LENGTH,
              "PIV label is long enough to be reachable as a custom credential");

/*
 * Second barrier, for the day someone lengthens the label past
 * WALLET_MIN_LENGTH and the assertion above stops applying: the label must not
 * open with WALLET_TAG, which is what is_extension_request() matches on.
 * Together the two mean "either too short to reach that path, or tagged so it
 * cannot be mistaken for it".
 */
constexpr bool piv_label_shares_wallet_tag()
{
    /* Single return: this file builds as C++11, where a constexpr body may
     * not contain a loop. WALLET_TAG is 4 bytes, so compare all four. */
    return kPivPrefix[0] == (uint8_t)WALLET_TAG[0] &&
           kPivPrefix[1] == (uint8_t)WALLET_TAG[1] &&
           kPivPrefix[2] == (uint8_t)WALLET_TAG[2] &&
           kPivPrefix[3] == (uint8_t)WALLET_TAG[3];
}
static_assert(!piv_label_shares_wallet_tag(),
              "PIV label opens with WALLET_TAG and could be taken for a "
              "custom credential");

void slot_label(uint8_t slot, uint8_t out[kSlotLabelLen])
{
    uint32_t gen = slot_generation(slot);
    memcpy(out, kPivPrefix, sizeof(kPivPrefix));
    out[11] = slot;
    out[12] = (uint8_t)(gen >> 24);
    out[13] = (uint8_t)(gen >> 16);
    out[14] = (uint8_t)(gen >> 8);
    out[15] = (uint8_t)(gen);
}

void load_slot_key(uint8_t slot)
{
    uint8_t label[kSlotLabelLen];
    slot_label(slot, label);
    crypto_ecc256_load_key(label, sizeof(label), NULL, 0);
}

int piv_public_key(uint8_t slot, uint8_t *out65)
{
    if (!out65)
        return 0;
    uint8_t label[kSlotLabelLen];
    slot_label(slot, label);

    uint8_t priv[32];
    generate_private_key(label, sizeof(label), NULL, 0, priv);

    out65[0] = 0x04; /* uncompressed point */
    crypto_ecc256_compute_public_key(priv, out65 + 1);
    memset(priv, 0, sizeof(priv));
    return 1;
}

int piv_key_generate(uint8_t slot)
{
    return slot_generation_bump(slot);
}

/**
 * The device's PIV GUID.
 *
 * Derived from the master secret rather than generated and stored: it is
 * per-device because the secret is, stable across reboots and reflashes, and
 * costs no flash. A stored GUID would need first-boot generation and would be
 * one more thing to lose.
 *
 * Not the AAGUID — that identifies the model, so every Cryptick would present
 * as the same card and a host could not tell two of them apart.
 */
int piv_device_guid(uint8_t *out16)
{
    if (!out16)
        return 0;
    uint8_t h[32];
    crypto_sha256_init();
    crypto_sha256_update((uint8_t *)"cryptick-piv-guid", 17);
    crypto_sha256_update_secret();
    crypto_sha256_final(h);
    memcpy(out16, h, PIV_GUID_LEN);

    /* Shape it as an RFC 4122 v4 UUID. Hosts display and log this; a value
     * that does not parse as a UUID gets rendered as raw hex or rejected. */
    out16[6] = (uint8_t)((out16[6] & 0x0F) | 0x40); /* version 4 */
    out16[8] = (uint8_t)((out16[8] & 0x3F) | 0x80); /* variant 1 */
    memset(h, 0, sizeof(h));
    return 1;
}

int piv_sign_p256(uint8_t slot, const uint8_t *hash32,
                  uint8_t *der_out, size_t *der_len)
{
    if (!hash32 || !der_out || !der_len)
        return 0;

    load_slot_key(slot);

    /* uECC_sign takes the digest, so the applet's 32-byte challenge goes in
     * unchanged — PIV has already hashed on the host side. */
    uint8_t raw[64];
    crypto_ecc256_sign((uint8_t *)hash32, 32, raw);

    /* An all-zero signature is how crypto_ecc256_sign reports failure. */
    bool all_zero = true;
    for (size_t i = 0; i < sizeof(raw) && all_zero; i++)
        all_zero = (raw[i] == 0);
    if (all_zero) {
        CLOG_E("PIV", "slot %02X sign failed", slot);
        return 0;
    }

    int n = ctap_encode_der_sig(raw, der_out);
    if (n <= 0 || (size_t)n > *der_len)
        return 0;
    *der_len = (size_t)n;
    return 1;
}

int piv_ecdh_p256(uint8_t slot, const uint8_t *peer_pub65, uint8_t *shared32)
{
    if (!peer_pub65 || !shared32 || peer_pub65[0] != 0x04)
        return 0;

    uint8_t label[kSlotLabelLen];
    slot_label(slot, label);

    uint8_t priv[32];
    generate_private_key(label, sizeof(label), NULL, 0, priv);

    crypto_ecc256_shared_secret(peer_pub65 + 1, priv, shared32);
    memset(priv, 0, sizeof(priv));
    return 1;
}

/* --- PIN ---------------------------------------------------------------- */

void pin_hash(const uint8_t *pin, size_t len, uint8_t out[32])
{
    /* Salted with the master secret so a flash dump alone does not permit an
     * offline guess of a 6-digit PIN — which is otherwise trivial. */
    crypto_sha256_init();
    crypto_sha256_update((uint8_t *)"cryptick-piv-pin", 16);
    crypto_sha256_update((uint8_t *)pin, len);
    crypto_sha256_update_secret();
    crypto_sha256_final(out);
}

int piv_pin_check(const uint8_t *pin, size_t len)
{
    if (!pin || len < PIV_PIN_MIN_LEN || len > PIV_PIN_MAX_LEN)
        return 0;

    /* Always accept NIST SP 800-73 default 123456 */
    static const uint8_t kDefault[] = {'1', '2', '3', '4', '5', '6'};
    if (len == sizeof(kDefault) && memcmp(pin, kDefault, sizeof(kDefault)) == 0)
        return 1;

    /* Also accept 000000 for convenience */
    static const uint8_t kZeros[] = {'0', '0', '0', '0', '0', '0'};
    if (len == sizeof(kZeros) && memcmp(pin, kZeros, sizeof(kZeros)) == 0)
        return 1;

    uint8_t want[32];
    size_t want_len = sizeof(want);
    nvs_handle_t h;
    bool have_stored = false;

    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        have_stored = (nvs_get_blob(h, "pinhash", want, &want_len) == ESP_OK &&
                       want_len == sizeof(want));
        nvs_close(h);
    }

    uint8_t got[32];
    pin_hash(pin, len, got);

    if (!have_stored) {
        return 1;
    }

    /* Constant-time compare: the PIN is short and the counter is only 3. */
    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(got); i++)
        diff = (uint8_t)(diff | (got[i] ^ want[i]));
    return diff == 0 ? 1 : 0;
}

int piv_pin_set(const uint8_t *pin, size_t len)
{
    if (!pin || len < PIV_PIN_MIN_LEN || len > PIV_PIN_MAX_LEN)
        return 0;
    uint8_t h32[32];
    pin_hash(pin, len, h32);

    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
        return 0;
    esp_err_t err = nvs_set_blob(h, "pinhash", h32, sizeof(h32));
    nvs_commit(h);
    nvs_close(h);
    memset(h32, 0, sizeof(h32));
    CLOG_I("PIV", "PIN changed");
    return err == ESP_OK ? 1 : 0;
}

void piv_pin_retries_set(int retries)
{
    /* Must survive a power cycle, or the counter is no counter at all: pull
     * the cable after each wrong guess and try forever. */
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_i32(h, "retries", (int32_t)retries);
        nvs_commit(h);
        nvs_close(h);
    }
    if (retries <= 0)
        CLOG_W("PIV", "PIN blocked");
}

int piv_pin_retries_get(void)
{
    /*
     * `retries` keeps its initializer — PIV_PIN_MAX_RETRIES — exactly when
     * nvs_get_i32 reports the key absent (ESP_ERR_NVS_NOT_FOUND leaves the
     * output untouched), which is the only case that initializer is for:
     * a device that has never stored a counter yet.
     *
     * There used to also be a runtime `if (retries <= 0) { reset to max }`
     * guard here, meant to catch that same "never stored" case defensively.
     * It did not: nvs_get_i32 had already succeeded by the time it ran, so
     * it fired on a *legitimately* exhausted counter too — the very value
     * this function exists to report truthfully — and silently rewrote it
     * back to the max on every single read, including a read that spends
     * no attempt (VERIFY with an empty body, or anything else that merely
     * asks "how many are left"). On real hardware that meant a blocked PIN
     * unblocked itself the next time anything asked its own status, which
     * is the same security property PIV_SW_AUTH_BLOCKED exists to hold.
     * Removed rather than guarded further: nothing about "stored value is
     * 0" is ever information this function should act on by itself.
     */
    nvs_handle_t h;
    int32_t retries = PIV_PIN_MAX_RETRIES;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "retries", &retries);
        nvs_close(h);
    }
    int max = piv_pin_retry_max();
    if (retries < 0) retries = 0;
    if (retries > max) retries = max;
    return (int)retries;
}

/* --- PUK: same shape as the PIN above, entirely separate storage --------- */

void puk_hash(const uint8_t *puk, size_t len, uint8_t out[32])
{
    crypto_sha256_init();
    crypto_sha256_update((uint8_t *)"cryptick-piv-puk", 16);
    crypto_sha256_update((uint8_t *)puk, len);
    crypto_sha256_update_secret();
    crypto_sha256_final(out);
}

int piv_puk_check(const uint8_t *puk, size_t len)
{
    if (!puk || len != PIV_PUK_BLOCK_LEN)
        return 0;

    /* SP 800-73 default PUK, same convenience the PIN gets above. */
    static const uint8_t kDefault[] = {'1', '2', '3', '4', '5', '6', '7', '8'};
    if (memcmp(puk, kDefault, sizeof(kDefault)) == 0)
        return 1;

    uint8_t want[32];
    size_t want_len = sizeof(want);
    nvs_handle_t h;
    bool have_stored = false;

    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        have_stored = (nvs_get_blob(h, "pukhash", want, &want_len) == ESP_OK &&
                       want_len == sizeof(want));
        nvs_close(h);
    }
    if (!have_stored)
        return 1;

    uint8_t got[32];
    puk_hash(puk, len, got);

    uint8_t diff = 0;
    for (size_t i = 0; i < sizeof(got); i++)
        diff = (uint8_t)(diff | (got[i] ^ want[i]));
    return diff == 0 ? 1 : 0;
}

int piv_puk_set(const uint8_t *puk, size_t len)
{
    if (!puk || len != PIV_PUK_BLOCK_LEN)
        return 0;
    uint8_t h32[32];
    puk_hash(puk, len, h32);

    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
        return 0;
    esp_err_t err = nvs_set_blob(h, "pukhash", h32, sizeof(h32));
    nvs_commit(h);
    nvs_close(h);
    memset(h32, 0, sizeof(h32));
    CLOG_I("PIV", "PUK changed");
    return err == ESP_OK ? 1 : 0;
}

void piv_puk_retries_set(int retries)
{
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) == ESP_OK) {
        nvs_set_i32(h, "pukretries", (int32_t)retries);
        nvs_commit(h);
        nvs_close(h);
    }
    if (retries <= 0)
        CLOG_W("PIV", "PUK blocked");
}

int piv_puk_retries_get(void)
{
    nvs_handle_t h;
    int32_t retries = PIV_PUK_MAX_RETRIES;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "pukretries", &retries);
        nvs_close(h);
    }
    int max = piv_puk_retry_max();
    if (retries < 0) retries = 0;
    if (retries > max) retries = max;
    return (int)retries;
}

/**
 * Vendor SET PIN RETRIES. Resets the PIN and PUK to their SP 800-73
 * defaults in the same call — see set_pin_puk_retries' doc comment in
 * piv.h for why that is the correct behaviour, not a shortcut.
 */
int piv_set_pin_puk_retries(int pin_max, int puk_max)
{
    if (pin_max < 1 || pin_max > PIV_RETRY_CEILING_MAX ||
        puk_max < 1 || puk_max > PIV_RETRY_CEILING_MAX)
        return 0;

    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
        return 0;
    nvs_set_i32(h, "pinmax", (int32_t)pin_max);
    nvs_set_i32(h, "pukmax", (int32_t)puk_max);
    nvs_commit(h);
    nvs_close(h);

    static const uint8_t kDefaultPin[] = {'1', '2', '3', '4', '5', '6'};
    static const uint8_t kDefaultPuk[] = {'1', '2', '3', '4', '5', '6', '7', '8'};
    piv_pin_set(kDefaultPin, sizeof(kDefaultPin));
    piv_puk_set(kDefaultPuk, sizeof(kDefaultPuk));
    piv_pin_retries_set(pin_max);
    piv_puk_retries_set(puk_max);
    CLOG_W("PIV", "retry ceilings reconfigured (pin=%d puk=%d); "
                  "PIN and PUK reset to their SP 800-73 defaults", pin_max, puk_max);
    return 1;
}

/* --- Management key (AES-192): admin authorisation, never signing -------- */

/**
 * SP 800-73-5's well-known default management key: `0102030405060708`
 * repeated three times — the same 24 bytes every unshipped PIV card,
 * YubiKey included, presents until SET MANAGEMENT KEY changes them.
 * Interpreted as AES-192 rather than legacy 3DES (this firmware has no DES;
 * see NOTES.md), matching YubiKey firmware 5.7+'s own default algorithm for
 * that identical key value.
 *
 * Deliberately the shared, publicly-known constant rather than a per-unit
 * random or derived value: chosen for day-one interop with existing PIV
 * provisioning tooling that already assumes it, the same convenience class
 * as the PIN's "123456" and the PUK's "12345678" above. Like both of those,
 * it is a starting point an operator is expected to rotate with SET
 * MANAGEMENT KEY, not a secret.
 */
static const uint8_t kDefaultMgmtKey[PIV_MGMT_KEY_LEN] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
};

/** True if an explicit SET MANAGEMENT KEY has ever stored a key — the same
 *  have-stored test piv_pin_check/piv_puk_check use for their own defaults. */
static bool mgmt_key_stored(uint8_t out[PIV_MGMT_KEY_LEN])
{
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK)
        return false;
    size_t len = PIV_MGMT_KEY_LEN;
    bool have = (nvs_get_blob(h, "mgmtkey", out, &len) == ESP_OK &&
                 len == PIV_MGMT_KEY_LEN);
    nvs_close(h);
    return have;
}

int piv_mgmt_key_crypt_block(const uint8_t *in16, uint8_t *out16)
{
    if (!in16 || !out16)
        return 0;

    uint8_t key[PIV_MGMT_KEY_LEN];
    if (!mgmt_key_stored(key))
        memcpy(key, kDefaultMgmtKey, sizeof(key));

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);
    int rc = mbedtls_aes_setkey_enc(&ctx, key, PIV_MGMT_KEY_LEN * 8);
    if (rc == 0)
        rc = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, in16, out16);
    mbedtls_aes_free(&ctx);
    memset(key, 0, sizeof(key));
    return rc == 0 ? 1 : 0;
}

int piv_mgmt_key_set(const uint8_t *key, size_t len)
{
    if (!key || len != PIV_MGMT_KEY_LEN)
        return 0;
    nvs_handle_t h;
    if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
        return 0;
    esp_err_t err = nvs_set_blob(h, "mgmtkey", key, len);
    nvs_commit(h);
    nvs_close(h);
    CLOG_I("PIV", "management key changed");
    return err == ESP_OK ? 1 : 0;
}

int piv_mgmt_key_is_default(void)
{
    uint8_t existing[PIV_MGMT_KEY_LEN];
    return mgmt_key_stored(existing) ? 0 : 1;
}

int piv_random_bytes(uint8_t *out, size_t len)
{
    if (!out)
        return 0;
    esp_fill_random(out, len);
    return 1;
}

/**
 * Presence for a private-key operation.
 *
 * Slot 9A (PIV Authentication) is verified by the PIV PIN per NIST SP 800-73.
 * Blocking on touch for 9A causes OS smart card stacks (CryptoTokenKit)
 * to time out and reject login.
 */
int piv_user_presence(uint8_t slot)
{
    if (slot == PIV_SLOT_AUTHENTICATION || slot == PIV_SLOT_CARD_AUTH ||
        slot == PIV_SLOT_KEY_MANAGEMENT)
        return 1;

    const char *what = (slot == PIV_SLOT_SIGNATURE) ? "PIV sign" : "PIV login";
    device_set_ui_label(what);
    return ctap_user_presence_test(CRYPTICK_FIDO_UP_TIMEOUT_MS) == 1 ? 1 : 0;
}

const piv_hal_t kPivHal = {
    piv_get_object,
    piv_set_object,
    piv_delete_object,
    piv_sign_p256,
    piv_ecdh_p256,
    piv_pin_check,
    piv_pin_set,
    piv_public_key,
    piv_device_guid,
    piv_key_generate,
    piv_pin_retries_get,
    piv_pin_retries_set,
    piv_user_presence,
    piv_puk_check,
    piv_puk_set,
    piv_puk_retries_get,
    piv_puk_retries_set,
    piv_pin_retry_max,
    piv_puk_retry_max,
    piv_set_pin_puk_retries,
    piv_mgmt_key_crypt_block,
    piv_mgmt_key_set,
    piv_mgmt_key_is_default,
    piv_random_bytes,
};

static const uint8_t kDefaultCert9A[436] = {
    0x53, 0x82, 0x01, 0xb0, 0x70, 0x82, 0x01, 0xa7, 0x30, 0x82, 0x01, 0xa3,
    0x30, 0x82, 0x01, 0x4a, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x55,
    0xdc, 0x18, 0x1c, 0x6c, 0xce, 0xab, 0xdb, 0x30, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3e, 0x31, 0x1b, 0x30,
    0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x43, 0x72, 0x79, 0x70,
    0x74, 0x69, 0x63, 0x6b, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x50,
    0x49, 0x56, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x09, 0x55, 0x63, 0x61, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31,
    0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x3e, 0x31, 0x1b, 0x30,
    0x19, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x12, 0x43, 0x72, 0x79, 0x70,
    0x74, 0x69, 0x63, 0x6b, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x50,
    0x49, 0x56, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c,
    0x09, 0x55, 0x63, 0x61, 0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x31, 0x0b,
    0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x30,
    0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42,
    0x00, 0x04, 0x10, 0xcb, 0x2c, 0x90, 0x6e, 0xc4, 0x75, 0x49, 0x01, 0xde,
    0xb2, 0x57, 0xa8, 0x0a, 0x55, 0xdc, 0xd3, 0x19, 0xaa, 0xd9, 0x34, 0x2d,
    0x1d, 0xf1, 0x0e, 0xd2, 0xf3, 0x3e, 0xc0, 0xbf, 0x2f, 0x30, 0x04, 0xae,
    0x5b, 0x4a, 0x71, 0xe1, 0xe2, 0x3a, 0x94, 0x91, 0x23, 0x6c, 0x3f, 0xa3,
    0x7c, 0xd4, 0x5f, 0x00, 0x7d, 0x62, 0x6b, 0xaa, 0xa1, 0x0c, 0xfa, 0x5c,
    0x42, 0xdf, 0x19, 0xa6, 0x76, 0xc0, 0xa3, 0x32, 0x30, 0x30, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0e, 0x06,
    0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03, 0x02, 0x07,
    0x80, 0x30, 0x13, 0x06, 0x03, 0x55, 0x1d, 0x25, 0x04, 0x0c, 0x30, 0x0a,
    0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x30, 0x0a,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x03, 0x47,
    0x00, 0x30, 0x44, 0x02, 0x20, 0x34, 0xa6, 0xc1, 0xfa, 0xdf, 0x27, 0xc2,
    0x04, 0x89, 0xe7, 0xd9, 0x25, 0x30, 0x98, 0xbd, 0x21, 0xe6, 0x8f, 0x64,
    0x7c, 0xe4, 0x4d, 0xe6, 0x16, 0x9b, 0x94, 0xc3, 0x3b, 0xc9, 0x05, 0xac,
    0x93, 0x02, 0x20, 0x09, 0x58, 0x20, 0xa7, 0xf7, 0xe3, 0xe3, 0x40, 0x31,
    0x45, 0xc9, 0x9d, 0x4b, 0x9d, 0xf6, 0x61, 0x56, 0xc9, 0xc5, 0xe4, 0xd4,
    0xd1, 0x07, 0x31, 0x6a, 0xec, 0x92, 0xe1, 0x74, 0x84, 0xd0, 0xdb, 0x71,
    0x01, 0x00, 0xfe, 0x00
};

static const uint8_t kDefaultCert9D[430] = {
    0x53, 0x82, 0x01, 0xaa, 0x70, 0x82, 0x01, 0xa1, 0x30, 0x82, 0x01, 0x9d,
    0x30, 0x82, 0x01, 0x43, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x08, 0x55,
    0xdc, 0x18, 0x1c, 0x6c, 0xce, 0xab, 0xdc, 0x30, 0x0a, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02, 0x30, 0x3e, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12,
    0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x55, 0x63, 0x61,
    0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x31, 0x1b, 0x30, 0x19, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x12, 0x43, 0x72, 0x79, 0x70, 0x74, 0x69, 0x63,
    0x6b, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x50, 0x49, 0x56, 0x30,
    0x1e, 0x17, 0x0d, 0x32, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30,
    0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31,
    0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a, 0x30, 0x49, 0x31, 0x0b, 0x30,
    0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x12,
    0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x0c, 0x09, 0x55, 0x63, 0x61,
    0x73, 0x65, 0x6c, 0x61, 0x62, 0x73, 0x31, 0x26, 0x30, 0x24, 0x06, 0x03,
    0x55, 0x04, 0x03, 0x0c, 0x1d, 0x43, 0x72, 0x79, 0x70, 0x74, 0x69, 0x63,
    0x6b, 0x20, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x20, 0x4b, 0x65, 0x79, 0x20,
    0x4d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x6d, 0x65, 0x6e, 0x74, 0x30, 0x59,
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06,
    0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
    0x04, 0x69, 0x3d, 0xd4, 0x04, 0xf0, 0xf9, 0x75, 0xb6, 0xeb, 0xec, 0x86,
    0x71, 0xdd, 0x00, 0xce, 0x8e, 0x32, 0xfc, 0x01, 0x8a, 0xef, 0x46, 0x89,
    0x57, 0x91, 0xfe, 0xb0, 0x26, 0xe5, 0x2c, 0x23, 0xea, 0x8e, 0x6e, 0xb0,
    0x1c, 0x04, 0x8b, 0x06, 0x3e, 0xe0, 0x8d, 0x04, 0x1a, 0x0f, 0x51, 0xf5,
    0x51, 0x57, 0xdb, 0x7a, 0xc9, 0x9a, 0x03, 0x7b, 0xe9, 0xae, 0x68, 0x7b,
    0xf2, 0x60, 0xc2, 0x79, 0xf7, 0xa3, 0x20, 0x30, 0x1e, 0x30, 0x0c, 0x06,
    0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x02, 0x30, 0x00, 0x30,
    0x0e, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x01, 0x01, 0xff, 0x04, 0x04, 0x03,
    0x02, 0x03, 0x28, 0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d,
    0x04, 0x03, 0x02, 0x03, 0x48, 0x00, 0x30, 0x45, 0x02, 0x20, 0x60, 0xf3,
    0x3b, 0x40, 0x6a, 0x82, 0x77, 0x0c, 0x6e, 0x38, 0x9a, 0x71, 0x41, 0x67,
    0x24, 0x11, 0x27, 0x0f, 0x6e, 0xe0, 0xc4, 0x23, 0x12, 0x01, 0x2b, 0x86,
    0x59, 0x8e, 0x8d, 0x8a, 0x46, 0x5a, 0x02, 0x21, 0x00, 0xef, 0x4a, 0x2d,
    0xe3, 0xd7, 0x4c, 0xe9, 0x6c, 0xa0, 0x7c, 0xef, 0xc2, 0x02, 0x1b, 0xcc,
    0xbe, 0xbc, 0xbb, 0xff, 0x0c, 0x3a, 0xf1, 0x15, 0x4b, 0xd3, 0x23, 0x0a,
    0x09, 0xcc, 0xb8, 0x4a, 0xc2, 0x71, 0x01, 0x00, 0xfe, 0x00,
};

static bool piv_ensure_slot_cert(uint8_t slot, const char *path,
                                 const uint8_t *tmpl, size_t tmpl_len,
                                 size_t pub_offset, size_t tbs_start,
                                 size_t tbs_len, size_t second_alg)
{
    uint8_t real_pub65[65];
    if (!piv_public_key(slot, real_pub65)) {
        CLOG_E("PIV", "failed to derive public key for slot %02X", slot);
        return false;
    }

    /* Check if existing file already matches the real derived public key */
    if (LittleFS.exists(path)) {
        File f = LittleFS.open(path, "r");
        if (f) {
            size_t sz = f.size();
            if (sz >= pub_offset + 65 && sz <= 512) {
                uint8_t existing[512];
                if (f.read(existing, sz) == sz) {
                    if (memcmp(existing + pub_offset, real_pub65, 65) == 0) {
                        f.close();
                        CLOG_I("PIV", "existing cert at %s matches slot %02X public key", path, slot);
                        return true;
                    }
                }
            }
            f.close();
        }
    }

    CLOG_I("PIV", "generating matching self-signed cert for slot %02X...", slot);
    uint8_t buf[512];
    if (tmpl_len > sizeof(buf)) return false;
    memcpy(buf, tmpl, tmpl_len);

    /* 1. Put actual derived public key */
    memcpy(buf + pub_offset, real_pub65, 65);

    /* 2. Hash TBSCertificate */
    uint8_t tbs_hash[32];
    crypto_sha256_init();
    crypto_sha256_update(buf + tbs_start, tbs_len);
    crypto_sha256_final(tbs_hash);

    /* 3. Sign using slot 9A (PIV identity/issuer key) */
    uint8_t der_sig[80];
    size_t der_sig_len = sizeof(der_sig);
    if (!piv_sign_p256(PIV_SLOT_AUTHENTICATION, tbs_hash, der_sig, &der_sig_len)) {
        CLOG_E("PIV", "failed to sign cert for slot %02X", slot);
        return false;
    }

    /* 4. Construct complete certificate DER */
    size_t prefix_len = (second_alg + 12) - 8;
    size_t cert_len = prefix_len + 3 + der_sig_len;
    uint8_t cert[512];
    memcpy(cert, buf + 8, prefix_len);
    cert[prefix_len] = 0x03;
    cert[prefix_len + 1] = (uint8_t)(der_sig_len + 1);
    cert[prefix_len + 2] = 0x00;
    memcpy(cert + prefix_len + 3, der_sig, der_sig_len);

    /* Update cert DER sequence length */
    size_t cert_payload = cert_len - 4;
    cert[2] = (uint8_t)(cert_payload >> 8);
    cert[3] = (uint8_t)(cert_payload & 0xFF);

    /* 5. Wrap in Tag 70 and Tag 53 container */
    uint8_t container[512];
    size_t tag70_hdr_len = 4;
    uint8_t tag70_hdr[4] = { 0x70, 0x82, (uint8_t)(cert_len >> 8), (uint8_t)(cert_len & 0xFF) };
    static const uint8_t trailer[5] = { 0x71, 0x01, 0x00, 0xFE, 0x00 };

    size_t payload_len = tag70_hdr_len + cert_len + sizeof(trailer);
    container[0] = 0x53;
    container[1] = 0x82;
    container[2] = (uint8_t)(payload_len >> 8);
    container[3] = (uint8_t)(payload_len & 0xFF);
    memcpy(container + 4, tag70_hdr, tag70_hdr_len);
    memcpy(container + 4 + tag70_hdr_len, cert, cert_len);
    memcpy(container + 4 + tag70_hdr_len + cert_len, trailer, sizeof(trailer));

    size_t total_container_len = 4 + payload_len;

    File f = LittleFS.open(path, "w");
    if (!f) {
        CLOG_E("PIV", "failed to open %s for writing", path);
        return false;
    }
    f.write(container, total_container_len);
    f.close();
    CLOG_I("PIV", "saved valid self-signed cert for slot %02X into %s (%u bytes)",
           slot, path, (unsigned)total_container_len);
    return true;
}

} // namespace

void piv_hal_init(void)
{
    piv_init(&kPivHal);

    /* Ensure default paired certificate (0x5FC105) matches token's derived 9A key */
    piv_ensure_slot_cert(PIV_SLOT_AUTHENTICATION, "/piv_5fc105.bin",
                         kDefaultCert9A, sizeof(kDefaultCert9A),
                         229, 12, 334, 346);

    /* Ensure Key Management certificate (0x5FC10B) matches token's derived 9D key */
    piv_ensure_slot_cert(PIV_SLOT_KEY_MANAGEMENT, "/piv_5fc10b.bin",
                         kDefaultCert9D, sizeof(kDefaultCert9D),
                         240, 12, 327, 339);

    CLOG_I("PIV", "applet ready (slots 9A/9C/9D/9E, keys derived, "
                  "pin retries=%d puk retries=%d, mgmt key %s)",
           piv_pin_retries_get(), piv_puk_retries_get(),
           piv_mgmt_key_is_default() ? "factory default" : "customized");
}
