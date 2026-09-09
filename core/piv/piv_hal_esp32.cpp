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

extern "C" {
#include "crypto.h"
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

constexpr const char *kNvsNamespace = "piv";

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
void slot_label(uint8_t slot, uint8_t out[16])
{
    uint32_t gen = slot_generation(slot);
    const uint8_t prefix[] = {'c', 'r', 'y', 'p', 't', 'i', 'c', 'k',
                              'P', 'I', 'V'};
    memcpy(out, prefix, sizeof(prefix));
    out[11] = slot;
    out[12] = (uint8_t)(gen >> 24);
    out[13] = (uint8_t)(gen >> 16);
    out[14] = (uint8_t)(gen >> 8);
    out[15] = (uint8_t)(gen);
}

void load_slot_key(uint8_t slot)
{
    uint8_t label[16];
    slot_label(slot, label);
    crypto_ecc256_load_key(label, sizeof(label), NULL, 0);
}

int piv_public_key(uint8_t slot, uint8_t *out65)
{
    if (!out65)
        return 0;
    uint8_t label[16];
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
        /*
         * No PIN set yet: fall back to the SP 800-73 default so a fresh device
         * is usable, and say so loudly. Shipping without changing this is a
         * real weakness, not a convenience.
         */
        static const uint8_t kDefault[] = {'1', '2', '3', '4', '5', '6'};
        uint8_t def[32];
        pin_hash(kDefault, sizeof(kDefault), def);
        CLOG_W("PIV", "no PIN set — default 123456 in use, change it");
        return memcmp(got, def, sizeof(got)) == 0 ? 1 : 0;
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

int piv_pin_retries_get(void)
{
    nvs_handle_t h;
    int32_t retries = PIV_PIN_MAX_RETRIES;
    if (nvs_open(kNvsNamespace, NVS_READONLY, &h) == ESP_OK) {
        nvs_get_i32(h, "retries", &retries);
        nvs_close(h);
    }
    if (retries < 0) retries = 0;
    if (retries > PIV_PIN_MAX_RETRIES) retries = PIV_PIN_MAX_RETRIES;
    return (int)retries;
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

/**
 * Presence for a private-key operation.
 *
 * Routed through ctap_user_presence_test() deliberately: that is the one
 * serialized presence gate on the device. A second flag here would reintroduce
 * exactly the confusion bug documented in docs/ARCHITECTURE.md#threading-model
 * — one fingerprint satisfying two different operations.
 */
int piv_user_presence(uint8_t slot)
{
    const char *what = (slot == PIV_SLOT_SIGNATURE) ? "PIV sign" : "PIV login";
    device_set_ui_label(what);
    return ctap_user_presence_test(CRYPTICK_FIDO_UP_TIMEOUT_MS) == 1 ? 1 : 0;
}

const piv_hal_t kPivHal = {
    piv_get_object,
    piv_set_object,
    piv_sign_p256,
    piv_pin_check,
    piv_pin_set,
    piv_public_key,
    piv_key_generate,
    piv_pin_retries_get,
    piv_pin_retries_set,
    piv_user_presence,
};

} // namespace

void piv_hal_init(void)
{
    piv_init(&kPivHal);
    CLOG_I("PIV", "applet ready (slots 9A/9C/9D/9E, keys derived, retries=%d)",
           piv_pin_retries_get());
}
